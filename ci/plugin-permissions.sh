#!/bin/sh
# Mechanizes WI-M5-006: a command missing from the plugin's own IPC ACL is
# refused at runtime however correctly it is registered in the handler and
# COMMANDS. See ci/README.md.
set -u

CHECK_NAME=plugin-permissions
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
LIB_RS="$ROOT_DIR/crates/tauri-plugin-tradr/src/lib.rs"
BUILD_RS="$ROOT_DIR/crates/tauri-plugin-tradr/build.rs"
CAP_DIR="$ROOT_DIR/apps/tradr/src-tauri/capabilities"
cd "$ROOT_DIR" || exit 1

status=0

# --- Validate the allowlist file itself: an empty reason fails every check ---
if [ -f "$ALLOWLIST" ]; then
	while IFS='|' read -r a_check a_path a_reason; do
		trimmed_check=$(printf '%s' "$a_check" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$trimmed_check" in
			'' | '#'*) continue ;;
		esac
		trimmed_reason=$(printf '%s' "$a_reason" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		if [ -z "$trimmed_reason" ]; then
			echo "ci/allowlist.txt: entry for '$trimmed_check' has an empty reason" >&2
			status=1
		fi
	done < "$ALLOWLIST"
fi

# $1 = the token a violation is filed under: a bare command name for rules 1
# and 2, "<plugin>:<symbol>" for rule 3 -- never a file path, since a rule 2
# or 3 violation names a set of capability files, not one of them.
is_allowed() {
	token="$1"
	[ -f "$ALLOWLIST" ] || return 1
	while IFS='|' read -r a_check a_path a_reason; do
		a_check=$(printf '%s' "$a_check" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$a_check" in
			'' | '#'*) continue ;;
		esac
		a_path=$(printf '%s' "$a_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		if [ "$a_check" = "$CHECK_NAME" ] && [ "$a_path" = "$token" ]; then
			return 0
		fi
	done < "$ALLOWLIST"
	return 1
}

# Reads "token@@message" lines from stdin and prints the message for every
# line whose token the allowlist does not cover. "@@" cannot occur inside a
# token (an identifier or "<plugin>:<symbol>"), so splitting on its first
# occurrence is unambiguous.
filter_hits() {
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		hit_token=${line%%@@*}
		hit_msg=${line#*@@}
		if ! is_allowed "$hit_token"; then
			echo "$hit_msg"
		fi
	done
}

if [ ! -f "$LIB_RS" ]; then
	echo "$LIB_RS: missing, cannot check generate_handler![] against COMMANDS"
	exit 1
fi
if [ ! -f "$BUILD_RS" ]; then
	echo "$BUILD_RS: missing, cannot check COMMANDS against generate_handler![]"
	exit 1
fi

# --- Collect command names registered in generate_handler![...] ---
# Entries are paths (identity::device_identity); only the final segment is
# the command name IPC dispatches on.
handler_block=$(awk '
	BEGIN { in_list = 0 }
	{
		line = $0
		if (!in_list && line ~ /generate_handler!\[/) {
			in_list = 1
			sub(/^.*generate_handler!\[/, "", line)
		}
		if (in_list) {
			if (match(line, /\]/)) {
				print substr(line, 1, RSTART - 1)
				in_list = 0
			} else {
				print line
			}
		}
	}
' "$LIB_RS")

handler_names=$(printf '%s\n' "$handler_block" | tr ',' '\n' \
	| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
	| sed -e 's/.*:://' \
	| grep -v '^$')

# --- Collect command names from COMMANDS in build.rs ---
commands=$(awk '
	BEGIN { in_list = 0 }
	{
		line = $0
		if (!in_list && line ~ /COMMANDS[ \t]*:.*=/) {
			in_list = 1
			# Scan only what follows the assignment operator: the type
			# annotation to its left (e.g. "&[&str]") carries its own "]",
			# which is not the list literals closing bracket and must
			# never be read as one on a rustfmt-wrapped declaration.
			sub(/^[^=]*=/, "", line)
		}
		if (in_list) {
			rest = line
			while (match(rest, /"[^"]*"/)) {
				print substr(rest, RSTART + 1, RLENGTH - 2)
				rest = substr(rest, RSTART + RLENGTH)
			}
			if (line ~ /\]/) in_list = 0
		}
	}
' "$BUILD_RS")

# --- Rule 1: the two Rust lists name the same set, checked both ways ---
only_in_handler=$(printf '%s\n' "$handler_names" | awk -v other="$commands" '
	BEGIN {
		n = split(other, arr, "\n")
		for (i = 1; i <= n; i++) if (arr[i] != "") known[arr[i]] = 1
	}
	{ if ($0 != "" && !($0 in known)) print }
' | sort -u)

only_in_commands=$(printf '%s\n' "$commands" | awk -v other="$handler_names" '
	BEGIN {
		n = split(other, arr, "\n")
		for (i = 1; i <= n; i++) if (arr[i] != "") known[arr[i]] = 1
	}
	{ if ($0 != "" && !($0 in known)) print }
' | sort -u)

rule1_raw=$(
	printf '%s\n' "$only_in_handler" | while IFS= read -r name; do
		[ -n "$name" ] || continue
		echo "$name@@crates/tauri-plugin-tradr/src/lib.rs: generate_handler![] registers command \"$name\", absent from COMMANDS in crates/tauri-plugin-tradr/build.rs"
	done
	printf '%s\n' "$only_in_commands" | while IFS= read -r name; do
		[ -n "$name" ] || continue
		echo "$name@@crates/tauri-plugin-tradr/build.rs: COMMANDS lists command \"$name\", absent from generate_handler![] in crates/tauri-plugin-tradr/src/lib.rs"
	done
)

rule1_unsuppressed=$(printf '%s\n' "$rule1_raw" | filter_hits)
if [ -n "$rule1_unsuppressed" ]; then
	printf '%s\n' "$rule1_unsuppressed"
	status=1
fi

# --- Collect the union of granted permissions across every capability file ---
# Scoped to the "permissions" array itself, not the whole file, the same way
# build.rs's COMMANDS is scoped to its own assignment above.
cap_files=$(find "$CAP_DIR" -maxdepth 1 -type f -name '*.json' 2> /dev/null)

cap_perms=$(printf '%s\n' "$cap_files" | while IFS= read -r cf; do
	[ -n "$cf" ] || continue
	awk '
	BEGIN { in_list = 0 }
	{
		line = $0
		if (!in_list && line ~ /"permissions"[ \t]*:/) {
			in_list = 1
			sub(/^[^:]*:/, "", line)
		}
		if (in_list) {
			rest = line
			while (match(rest, /"[^"]*"/)) {
				print substr(rest, RSTART + 1, RLENGTH - 2)
				rest = substr(rest, RSTART + RLENGTH)
			}
			if (line ~ /\]/) in_list = 0
		}
	}
	' "$cf"
done)

# --- Rule 2: every registered command is granted by at least one capability file ---
rule2_raw=$(
	printf '%s\n' "$commands" | while IFS= read -r name; do
		[ -n "$name" ] || continue
		kebab=$(printf '%s' "$name" | tr '_' '-')
		allow_perm="tradr:allow-$kebab"
		if printf '%s\n' "$cap_perms" | grep -qx "$allow_perm"; then
			continue
		fi
		if printf '%s\n' "$cap_perms" | grep -qx 'tradr:default'; then
			continue
		fi
		echo "$name@@apps/tradr/src-tauri/capabilities/*.json: command \"$name\" is registered in COMMANDS but granted by none of them; expected \"$allow_perm\" or \"tradr:default\" in a permissions array"
	done
)

rule2_unsuppressed=$(printf '%s\n' "$rule2_raw" | filter_hits)
if [ -n "$rule2_unsuppressed" ]; then
	printf '%s\n' "$rule2_unsuppressed"
	status=1
fi

# --- Rule 3: every plugin API the frontend imports is granted ---
frontend_files=$(find apps/tradr/src -type f \( -name '*.ts' -o -name '*.tsx' \) \
	-not -path '*/node_modules/*' \
	-not -path '*/.git/*' 2> /dev/null)

rule3_raw=$(
	printf '%s\n' "$frontend_files" | while IFS= read -r f; do
		[ -n "$f" ] || continue
		awk -v fname="$f" -v perms="$cap_perms" '
		BEGIN {
			in_import = 0
			buf = ""
			start_line = 0
			nperm = split(perms, permarr, "\n")
			for (i = 1; i <= nperm; i++) if (permarr[i] != "") known[permarr[i]] = 1
		}
		{
			line = $0
			# A dynamic import(...) destructures at runtime rather than in a
			# statement this parser can read; rather than guess which symbols
			# it pulls in, refuse it outright when its argument names a Tauri
			# plugin module -- the one shape this check exists to catch.
			if (line ~ /import[ \t]*\(/ && line ~ /["'\'']@tauri-apps\/plugin-[A-Za-z0-9_-]+["'\'']/) {
				print "REFUSAL@@" fname ":" FNR ": plugin-permissions.sh cannot determine which symbols a dynamic import(\"@tauri-apps/plugin-...\") pulls in; write the import statically so its permissions can be checked"
			}
			if (!in_import) {
				if (line ~ /^[ \t]*import[ \t]/) {
					in_import = 1
					buf = line
					start_line = FNR
				} else {
					next
				}
			} else {
				buf = buf " " line
			}
			# The quoted module specifier after "from" always exists and
			# always comes last in an import, so it bounds the statement
			# without depending on a trailing ";": no lint rule in this
			# repository requires a trailing semicolon on an import.
			if (in_import && match(buf, /from[ \t]+["'\''][^"'\'']*["'\'']/)) {
				stmt = substr(buf, 1, RSTART + RLENGTH - 1)
				remainder = substr(buf, RSTART + RLENGTH)
				process(stmt, start_line)
				if (remainder ~ /(^|[^A-Za-z0-9_])import([^A-Za-z0-9_]|$)/) {
					print "REFUSAL@@" fname ":" start_line ": plugin-permissions.sh cannot parse two import statements sharing one region; format apps/tradr/src with one import per line"
				}
				in_import = 0
				buf = ""
			}
		}
		END {
			if (in_import) {
				print "REFUSAL@@" fname ":" start_line ": plugin-permissions.sh reached end of file while an import statement starting here had not reached a module specifier"
			}
		}
		# A statement not naming @tauri-apps/plugin-<x> or written as
		# "import type { ... }" carries no runtime-checked plugin API and
		# is skipped entirely; a "type X" specifier is skipped per entry.
		function process(stmt, lineno,    plugin, specpart, specs, n, i, spec, name, kebab, j, ch, permname, defaultname) {
			if (!match(stmt, /@tauri-apps\/plugin-[A-Za-z0-9_-]+/)) return
			plugin = substr(stmt, RSTART, RLENGTH)
			sub(/^@tauri-apps\/plugin-/, "", plugin)

			if (stmt ~ /^import[ \t]+type[ \t]/) return
			if (!match(stmt, /\{[^}]*\}/)) return
			specpart = substr(stmt, RSTART + 1, RLENGTH - 2)

			n = split(specpart, specs, ",")
			for (i = 1; i <= n; i++) {
				spec = specs[i]
				gsub(/^[ \t]+/, "", spec)
				gsub(/[ \t]+$/, "", spec)
				if (spec == "") continue
				if (spec ~ /^type[ \t]/) continue

				if (match(spec, /[ \t]+as[ \t]+/)) {
					name = substr(spec, 1, RSTART - 1)
				} else {
					name = spec
				}
				gsub(/^[ \t]+/, "", name)
				gsub(/[ \t]+$/, "", name)
				if (name == "") continue

				kebab = ""
				for (j = 1; j <= length(name); j++) {
					ch = substr(name, j, 1)
					if (ch ~ /[A-Z]/) kebab = kebab "-" tolower(ch)
					else kebab = kebab ch
				}

				permname = plugin ":allow-" kebab
				defaultname = plugin ":default"
				if (!(permname in known) && !(defaultname in known)) {
					print plugin ":" name "@@" fname ":" lineno ": imports \"" name "\" from @tauri-apps/plugin-" plugin ", not granted as \"" permname "\" or \"" defaultname "\" in any apps/tradr/src-tauri/capabilities/*.json"
				}
			}
		}
		' "$f"
	done
)

# A parse refusal is never routed through filter_hits: letting the allowlist
# silence one would recreate the exact silent-pass defect rule 3 exists to
# remove, so it is printed and counted unconditionally.
rule3_refusals=$(printf '%s\n' "$rule3_raw" | grep '^REFUSAL@@' | sed 's/^REFUSAL@@//')
if [ -n "$rule3_refusals" ]; then
	printf '%s\n' "$rule3_refusals"
	status=1
fi

rule3_hits=$(printf '%s\n' "$rule3_raw" | grep -v '^REFUSAL@@')
rule3_unsuppressed=$(printf '%s\n' "$rule3_hits" | filter_hits)
if [ -n "$rule3_unsuppressed" ]; then
	printf '%s\n' "$rule3_unsuppressed"
	status=1
fi

exit $status

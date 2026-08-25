#!/bin/sh
# Mechanizes WI-M0-014c: a frontend invoke() call names the plugin command
# by string alone, so a typo compiles perfectly and only fails at runtime.
# Reads every invoke("...") and invoke<...>("...") string literal under
# apps/tradr/src/ and requires each to be of the form
# plugin:<plugin>|<command>, where <command> appears in the COMMANDS list
# in crates/tauri-plugin-tradr/build.rs. Runs one way only: a command in
# COMMANDS that the frontend never calls is not a violation.
set -u

CHECK_NAME=invoke-commands
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
BUILD_RS="$ROOT_DIR/crates/tauri-plugin-tradr/build.rs"
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

is_allowed() {
	# $1 = file path relative to repo root
	file="$1"
	[ -f "$ALLOWLIST" ] || return 1
	while IFS='|' read -r a_check a_path a_reason; do
		a_check=$(printf '%s' "$a_check" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$a_check" in
			'' | '#'*) continue ;;
		esac
		a_path=$(printf '%s' "$a_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		if [ "$a_check" = "$CHECK_NAME" ] && [ "$a_path" = "$file" ]; then
			return 0
		fi
	done < "$ALLOWLIST"
	return 1
}

if [ ! -f "$BUILD_RS" ]; then
	echo "$BUILD_RS: missing, cannot check invoke() calls against the plugin's COMMANDS list"
	exit 1
fi

# --- Collect the registered command names from build.rs's COMMANDS list ---
commands=$(awk '
	BEGIN { in_list = 0 }
	{
		line = $0
		if (!in_list && line ~ /COMMANDS[ \t]*:.*=/) in_list = 1
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

files=$(find apps/tradr/src -type f \( -name '*.ts' -o -name '*.tsx' \) \
	-not -path '*/node_modules/*' \
	-not -path '*/.git/*' 2> /dev/null)

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk -v fname="$f" -v cmdlist="$commands" '
	BEGIN {
		known_n = split(cmdlist, known_arr, "\n")
		for (idx = 1; idx <= known_n; idx++) known[known_arr[idx]] = 1
	}
	{
		line = $0
		pos = 1
		while (1) {
			rest = substr(line, pos)
			if (!match(rest, /invoke(<[^>]*>)?\(/)) break
			call_end = pos + RSTART + RLENGTH - 1
			after = substr(line, call_end)
			if (match(after, /^[ \t]*"[^"]*"/)) {
				s = substr(after, RSTART, RLENGTH)
				sub(/^[ \t]*"/, "", s)
				sub(/"$/, "", s)

				ok = 0
				cmd = ""
				if (s ~ /^plugin:[^|:]+\|[^|]+$/) {
					split(s, parts, "|")
					cmd = parts[2]
					if (cmd in known) ok = 1
				}
				if (!ok) {
					if (cmd != "") {
						print fname ":" FNR ": invoke() names command \"" cmd "\", absent from COMMANDS in crates/tauri-plugin-tradr/build.rs (WI-M0-014c)"
					} else {
						print fname ":" FNR ": invoke() literal \"" s "\" is not of the form plugin:<plugin>|<command> (WI-M0-014c)"
					}
				}
			}
			pos = call_end
			if (pos > length(line)) break
		}
	}
	' "$f"
done)

unsuppressed=$(printf '%s\n' "$hits" | while IFS= read -r hit; do
	[ -n "$hit" ] || continue
	hit_file=${hit%%:*}
	if ! is_allowed "$hit_file"; then
		echo "$hit"
	fi
done)

if [ -n "$unsuppressed" ]; then
	printf '%s\n' "$unsuppressed"
	status=1
fi

exit $status

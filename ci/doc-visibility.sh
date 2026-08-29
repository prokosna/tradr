#!/bin/sh
# Mechanizes rule A5: fails on a doc comment (///) immediately above a
# private free function in *.rs files under crates/ and apps/.
set -u

CHECK_NAME=doc-visibility
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
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

files=$(find crates apps -type f -name '*.rs' \
	-not -path '*/target/*' \
	-not -path '*/node_modules/*' \
	-not -path '*/gen/*' \
	-not -path '*/.git/*' 2> /dev/null)

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk -v fname="$f" '
	# Delta of "[" minus "]" occurrences in s, used to track attribute
	# brackets across possibly multi-line #[...] attributes.
	function bracket_delta(s,    copy1, copy2, opens, closes) {
		copy1 = s
		opens = gsub(/\[/, "[", copy1)
		copy2 = s
		closes = gsub(/\]/, "]", copy2)
		return opens - closes
	}

	# Returns 1 if "pub" appears before the "fn " keyword on t, 0 if a
	# "fn " keyword is found without a preceding "pub", -1 if t has no
	# "fn " keyword at all (so it is not a function declaration line).
	function is_pub_before_fn(t,    padded, idx, prefix) {
		padded = " " t
		idx = index(padded, " fn ")
		if (idx == 0) return -1
		prefix = substr(padded, 1, idx)
		if (prefix ~ /(^|[^A-Za-z0-9_])pub([^A-Za-z0-9_]|$)/) return 1
		return 0
	}

	{ lines[FNR] = $0 }
	END {
		n = FNR
		i = 1
		while (i <= n) {
			t = lines[i]
			sub(/^[ \t]*/, "", t)
			if (t !~ /^\/\/\//) {
				i++
				continue
			}

			start = i
			j = i
			while (j <= n) {
				tj = lines[j]
				sub(/^[ \t]*/, "", tj)
				if (tj ~ /^\/\/\//) j++
				else break
			}

			# Skip attribute lines (possibly multi-line) between the doc
			# run and its target.
			k = j
			in_attr = 0
			depth = 0
			while (k <= n) {
				tk = lines[k]
				sub(/^[ \t]*/, "", tk)
				if (!in_attr) {
					if (tk ~ /^#\[/) {
						in_attr = 1
						depth = bracket_delta(tk)
						k++
						if (depth <= 0) in_attr = 0
						continue
					}
					break
				}
				depth += bracket_delta(tk)
				k++
				if (depth <= 0) in_attr = 0
			}

			if (k <= n) {
				tk = lines[k]
				sub(/^[ \t]*/, "", tk)
				pub_status = is_pub_before_fn(tk)
				if (pub_status == 0) {
					# Scan forward from the declaration line to whichever
					# of ";" or "{" ends a line first: ";" is a trait
					# method requirement (public, skip); "{" is a body.
					m = k
					found = ""
					while (m <= n) {
						rt = lines[m]
						sub(/[ \t]+$/, "", rt)
						lastc = substr(rt, length(rt), 1)
						if (lastc == ";") { found = "semi"; break }
						if (lastc == "{") { found = "brace"; break }
						m++
					}
					if (found == "brace") {
						print fname ":" start ": rule A5: doc comment (///) on private function declared at line " k
					}
				}
			}

			i = j
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

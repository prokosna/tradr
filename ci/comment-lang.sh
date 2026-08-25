#!/bin/sh
# Mechanizes CLAUDE.md rule A1: fails on a non-ASCII character inside a
# comment in crates/**/*.rs or packages/**/*.ts.
set -u

CHECK_NAME=comment-lang
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
ALLOWLIST="$ROOT_DIR/ci/allowlist.txt"
cd "$ROOT_DIR" || exit 1

status=0

# Records which files' awk invocation itself failed, so a tool crash is
# never mistaken for a clean scan (see the check below the awk call).
AWK_FAIL_FILE=$(mktemp) || exit 1
trap 'rm -f "$AWK_FAIL_FILE"' EXIT

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

files=$(find crates packages -type f \( -name '*.rs' -o -name '*.ts' \) \
	-not -path '*/target/*' \
	-not -path '*/node_modules/*' \
	-not -path 'packages/protocol/src/gen/*' \
	-not -path '*/.git/*' 2> /dev/null)

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	# LC_ALL=C: GNU awk in a UTF-8 locale rejects [\200-\377] as an invalid
	# collating range; under C, every awk compares it as raw bytes.
	LC_ALL=C awk -v fname="$f" '
	function extract(line,    i, n, two, rest, p, seg, out) {
		n = length(line)
		i = 1
		out = ""
		while (i <= n) {
			if (in_block) {
				rest = substr(line, i)
				p = index(rest, "*/")
				if (p > 0) {
					out = out substr(rest, 1, p + 1)
					i += p + 1
					in_block = 0
				} else {
					out = out rest
					i = n + 1
				}
			} else {
				two = substr(line, i, 2)
				if (two == "//") {
					out = out substr(line, i)
					i = n + 1
				} else if (two == "/*") {
					rest = substr(line, i)
					p = index(rest, "*/")
					if (p > 0) {
						out = out substr(rest, 1, p + 1)
						i += p + 1
					} else {
						out = out rest
						in_block = 1
						i = n + 1
					}
				} else {
					i++
				}
			}
		}
		return out
	}
	FNR == 1 { in_block = 0 }
	{
		c = extract($0)
		if (c != "" && match(c, /[\200-\377]/)) {
			print fname ":" FNR
		}
	}
	' "$f" || echo "$f" >> "$AWK_FAIL_FILE"
done)

if [ -s "$AWK_FAIL_FILE" ]; then
	while IFS= read -r failed_file; do
		echo "comment-lang: awk failed to scan '$failed_file'" >&2
	done < "$AWK_FAIL_FILE"
	status=1
fi

# Command substitution runs in a subshell but its stdout is captured back
# into the parent, so this is where "status" must be decided.
unsuppressed=$(printf '%s\n' "$hits" | while IFS= read -r hit; do
	[ -n "$hit" ] || continue
	hit_file=${hit%%:*}
	if ! is_allowed "$hit_file"; then
		echo "$hit: non-ASCII character in comment"
	fi
done)

if [ -n "$unsuppressed" ]; then
	printf '%s\n' "$unsuppressed"
	status=1
fi

exit $status

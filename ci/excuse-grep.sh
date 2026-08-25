#!/bin/sh
# Mechanizes CLAUDE.md rule A4: fails on any phrase from the A4 table
# (CLAUDE.md section 4) appearing in a comment, case-insensitive, in
# crates/**/*.rs or packages/**/*.ts.
set -u

CHECK_NAME=excuse-grep
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

files=$(find crates packages -type f \( -name '*.rs' -o -name '*.ts' \) \
	-not -path '*/target/*' \
	-not -path '*/node_modules/*' \
	-not -path 'packages/protocol/src/gen/*' \
	-not -path '*/.git/*' 2> /dev/null)

# The A4 table from CLAUDE.md section 4, one phrase per line.
phrases='for now
temporarily
for the time being
unfortunately
sadly
ideally
a bit hacky
workaround
kludge
this is tricky
somewhat
kind of
we have to
we need to
TODO: refactor
FIXME: clean
note that this
be careful
don'"'"'t change this
it seems
apparently
I think'

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk -v fname="$f" '
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
		if (c != "") {
			print FNR "\t" tolower(c)
		}
	}
	' "$f" | while IFS='	' read -r lineno comment_lc; do
		[ -n "$lineno" ] || continue
		printf '%s\n' "$phrases" | while IFS= read -r phrase; do
			[ -n "$phrase" ] || continue
			phrase_lc=$(printf '%s' "$phrase" | tr '[:upper:]' '[:lower:]')
			case "$comment_lc" in
				*"$phrase_lc"*)
					echo "$f:$lineno: contains excuse phrase '$phrase'"
					;;
			esac
		done
	done
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

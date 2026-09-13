#!/bin/sh
# Mechanizes CLAUDE.md rule F6: refuses console calls in frontend
# sources under apps/*/src/ and packages/*/src/.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR" || exit 1

status=0

files=$(find apps packages -type f \
	\( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' \) \
	\( -path 'apps/*/src/*' -o -path 'packages/*/src/*' \) \
	-not -path '*/node_modules/*' \
	-not -path '*/dist/*' \
	-not -path '*/gen/*' \
	-not -path '*/build/*' \
	-not -path '*/target/*' 2>/dev/null | sort)

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk '
	BEGIN {
		in_comment = 0
		in_str = 0
		str_char = ""
	}
	function strip_comments(line,    res, len, pos, ch, next_ch, c_idx) {
		res = ""
		len = length(line)
		pos = 1
		while (pos <= len) {
			if (in_comment) {
				c_idx = index(substr(line, pos), "*/")
				if (c_idx > 0) {
					pos = pos + c_idx + 1
					in_comment = 0
				} else {
					break
				}
			} else {
				ch = substr(line, pos, 1)
				next_ch = (pos < len) ? substr(line, pos + 1, 1) : ""
				if (in_str) {
					if (ch == "\\") {
						if (pos < len) {
							pos++
						}
					} else if (ch == str_char) {
						in_str = 0
						res = res ch
					}
					pos++
				} else if (ch == "\"" || ch == "\047" || ch == "\x60") {
					in_str = 1
					str_char = ch
					res = res ch
					pos++
				} else if (ch == "/" && next_ch == "/") {
					break
				} else if (ch == "/" && next_ch == "*") {
					in_comment = 1
					pos += 2
				} else {
					res = res ch
					pos++
				}
			}
		}
		if (in_str && str_char != "\x60") {
			in_str = 0
			str_char = ""
		}
		return res
	}
	{
		sub(/\r$/, "", $0)
		code = strip_comments($0)
		if (index(code, "console.") > 0) {
			print FILENAME ":" FNR ": console call in a frontend source"
		}
	}
	' "$f"
done)

if [ -n "$hits" ]; then
	printf '%s\n' "$hits"
	status=1
fi

exit $status

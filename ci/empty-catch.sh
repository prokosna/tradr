#!/bin/sh
# Mechanizes CLAUDE.md rule F6: refuses empty catch blocks in Kotlin
# sources under crates/ and apps/.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR" || exit 1

status=0

files=$(find crates apps -type f -name '*.kt' \
	-not -path '*/.tauri/*' \
	-not -path '*/gen/*' \
	-not -path '*/build/*' \
	-not -path '*/target/*' \
	-not -path '*/node_modules/*' 2>/dev/null | sort)

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk '
	# Shares residue reduction so comment syntax behaves identically on catch line and body.
	function reduce(text,    c_idx) {
		while (1) {
			sub(/^[ \t]+/, "", text)
			if (substr(text, 1, 2) == "//") {
				text = ""
				break
			}
			if (substr(text, 1, 2) == "/*") {
				c_idx = index(substr(text, 3), "*/")
				if (c_idx > 0) {
					text = substr(substr(text, 3), c_idx + 2)
				} else {
					in_comment = 1
					text = ""
					break
				}
			} else {
				break
			}
		}
		sub(/^[ \t]+/, "", text)
		sub(/[ \t]+$/, "", text)
		return text
	}
	{
		sub(/\r$/, "", $0)
		lines[FNR] = $0
	}
	END {
		total = FNR
		for (i = 1; i <= total; i++) {
			line = lines[i]
			s = line
			sub(/^[ \t]+/, "", s)
			if (s ~ /^\/\// || s ~ /^\/\*/ || s ~ /^\*/) {
				continue
			}
			if (line !~ /(^|[^a-zA-Z0-9_])catch[^(]*\(.*\).*\{/) {
				continue
			}
			idx = 0
			for (j = length(line); j >= 1; j--) {
				if (substr(line, j, 1) == "{") {
					idx = j
					break
				}
			}
			in_comment = 0
			after = reduce(substr(line, idx + 1))
			if (after != "") {
				if (after == "}") {
					print FILENAME ":" i ": empty catch block"
				}
				continue
			}
			for (k = i + 1; k <= total; k++) {
				nxt = lines[k]
				if (in_comment) {
					c_idx = index(nxt, "*/")
					if (c_idx > 0) {
						residue = substr(nxt, c_idx + 2)
						in_comment = 0
					} else {
						residue = ""
					}
				} else {
					residue = nxt
				}
				residue = reduce(residue)
				if (residue == "") {
					continue
				}
				if (substr(residue, 1, 1) == "}") {
					print FILENAME ":" i ": empty catch block"
				}
				break
			}
		}
	}
	' "$f"
done)

if [ -n "$hits" ]; then
	printf '%s\n' "$hits"
	status=1
fi

exit $status

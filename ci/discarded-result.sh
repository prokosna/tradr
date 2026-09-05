#!/bin/sh
# Mechanizes CLAUDE.md rule F6: refuses discarded results in production
# Rust sources under crates/*/src and apps/*/src-tauri/src.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR" || exit 1

status=0

files=$(find crates apps -type f -name '*.rs' \
	\( -path 'crates/*/src/*' -o -path 'apps/*/src-tauri/src/*' \) \
	-not -path '*/target/*' \
	-not -path '*/tests/*' \
	-not -name 'build.rs' 2>/dev/null)

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk '
	function check_line(line, lineno, fname) {
		sub(/\r$/, "", line)
		s = line
		sub(/^[ \t]+/, "", s)
		if (s ~ /^\/\// || s ~ /^\/\*/ || s ~ /^\*/) return

		if (line ~ /(^|[^a-zA-Z0-9_])let[ \t]+_[ \t]*=([^=]|$)/) {
			print fname ":" lineno ": discarded result via '\''let _ ='\''"
			return
		}

		if (line ~ /(^|[^a-zA-Z0-9_])let[ \t]+_[ \t]*:[^=]+=([^=]|$)/) {
			print fname ":" lineno ": discarded result via '\''let _: T ='\''"
			return
		}

		if (line !~ /(^|[^a-zA-Z0-9_])let[ \t]/) {
			if (line ~ /(^|[;{])[ \t]*_[ \t]*=([^=>]|$)/) {
				print fname ":" lineno ": discarded result via '\''_ ='\''"
				return
			}
		}

		if (s !~ /^\./ && line !~ /(^|[^a-zA-Z0-9_])let[ \t]/) {
			t = line
			sub(/[ \t]*\/\/.*$/, "", t)
			sub(/[ \t]+$/, "", t)
			if (t ~ /\.ok\(\);$/) {
				print fname ":" lineno ": discarded result via statement-position '\''.ok();'\''"
				return
			}
		}
	}
	{ check_line($0, FNR, FILENAME) }
	' "$f"
done)

if [ -n "$hits" ]; then
	printf '%s\n' "$hits"
	status=1
fi

exit $status

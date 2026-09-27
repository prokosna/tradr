#!/bin/sh
# ADR-0023 confines unsafe code to a single Android descriptor adapter.
# Crate roots must keep a lint against unsafe code.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR" || exit 1

status=0

EXEMPT_FILE="crates/tauri-plugin-tradr/src/android_fd.rs"
PLUGIN_LIB="crates/tauri-plugin-tradr/src/lib.rs"

files=$(find crates apps -type f -name '*.rs' \
	-not -path '*/target/*' \
	-not -path '*/gen/*' \
	-not -path '*/node_modules/*' \
	-not -path '*/.tauri/*' 2>/dev/null | sort)

unsafe_hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	[ "$f" != "$EXEMPT_FILE" ] || continue
	awk '
	function check_line(line, lineno, fname) {
		sub(/\r$/, "", line)
		gsub(/#[ \t]*!?[ \t]*\[[ \t]*(forbid|deny|allow)[ \t]*\([ \t]*unsafe_code[ \t]*\)[ \t]*\]/, "", line)
		if (line ~ /(^|[^a-zA-Z0-9_])unsafe([^a-zA-Z0-9_]|$)/) {
			print fname ":" lineno ": unconfined unsafe"
		}
	}
	{ check_line($0, FNR, FILENAME) }
	' "$f"
done)

root_hits=$(for lib in crates/*/src/lib.rs; do
	[ -f "$lib" ] || continue
	if [ "$lib" = "$PLUGIN_LIB" ]; then
		if ! grep -qE '^[[:space:]]*#[[:space:]]*![[:space:]]*\[[[:space:]]*(forbid|deny)[[:space:]]*\([[:space:]]*unsafe_code[[:space:]]*\)[[:space:]]*\]' "$lib"; then
			echo "$lib:1: crate root must contain #![forbid(unsafe_code)] or #![deny(unsafe_code)]"
		fi
	else
		if ! grep -qE '^[[:space:]]*#[[:space:]]*![[:space:]]*\[[[:space:]]*forbid[[:space:]]*\([[:space:]]*unsafe_code[[:space:]]*\)[[:space:]]*\]' "$lib"; then
			echo "$lib:1: crate root must contain #![forbid(unsafe_code)]"
		fi
	fi
done)

hits=""
if [ -n "$unsafe_hits" ]; then
	hits="$unsafe_hits"
fi
if [ -n "$root_hits" ]; then
	if [ -n "$hits" ]; then
		hits=$(printf '%s\n%s' "$hits" "$root_hits")
	else
		hits="$root_hits"
	fi
fi

if [ -n "$hits" ]; then
	printf '%s\n' "$hits"
	status=1
fi

exit $status

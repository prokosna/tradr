#!/bin/sh
# Mechanizes DCR-137: compiles crates with Windows cfg gates for MSVC.
# Scans crates/ only; apps/ is out of scope by ruling.
# See ci/README.md and docs/10-implementation-process.md.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
EXEMPT_FILE="$ROOT_DIR/ci/windows-target-exempt.txt"
cd "$ROOT_DIR" || exit 1

if [ "$#" -ne 0 ]; then
	echo "usage: windows-target.sh" >&2
	exit 2
fi

if ! rustup target list --installed 2>/dev/null | grep -Fxq "x86_64-pc-windows-msvc"; then
	echo "windows-target: target x86_64-pc-windows-msvc is not installed; run 'rustup show' to sync with rust-toolchain.toml" >&2
	exit 1
fi

if [ ! -f "$EXEMPT_FILE" ]; then
	echo "windows-target: $EXEMPT_FILE does not exist" >&2
	exit 1
fi

gated_pairs=$(find crates -type f -name '*.rs' -not -path '*/target/*' -exec grep -l -E \
	'cfg\([[:space:]]*windows[[:space:]]*\)|cfg!\([[:space:]]*windows[[:space:]]*\)|not\([[:space:]]*windows[[:space:]]*\)|target_os[[:space:]]*=[[:space:]]*"windows"|target_family[[:space:]]*=[[:space:]]*"windows"' \
	{} + 2>/dev/null | while IFS= read -r f; do
		[ -n "$f" ] || continue
		rel=${f#crates/}
		crate=${rel%%/*}
		[ -n "$crate" ] || continue
		printf '%s|%s\n' "$crate" "$f"
	done || true)

gated_crates=""
if [ -n "$gated_pairs" ]; then
	gated_crates=$(printf '%s\n' "$gated_pairs" | cut -d'|' -f1 | sort -u)
fi

is_gated_crate() {
	check_c="$1"
	for gc in $gated_crates; do
		if [ "$gc" = "$check_c" ]; then
			return 0
		fi
	done
	return 1
}

exempt_crates=""
exempt_count=0

while IFS='|' read -r raw_crate raw_reason || [ -n "${raw_crate:-}" ]; do
	crate=$(printf '%s' "${raw_crate:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	case "$crate" in
		'' | '#'*) continue ;;
	esac
	reason=$(printf '%s' "${raw_reason:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

	if [ -z "$reason" ]; then
		echo "windows-target: $EXEMPT_FILE: entry '$crate' has an empty reason" >&2
		exit 1
	fi

	if [ ! -d "crates/$crate" ]; then
		echo "windows-target: $EXEMPT_FILE: entry '$crate' does not exist under crates/" >&2
		exit 1
	fi

	if ! is_gated_crate "$crate"; then
		echo "windows-target: $EXEMPT_FILE: entry '$crate' holds no Windows cfg gate (stale exemption)" >&2
		exit 1
	fi

	exempt_crates="$exempt_crates $crate"
	exempt_count=$((exempt_count + 1))
done < "$EXEMPT_FILE"

is_exempt_crate() {
	check_e="$1"
	for ec in $exempt_crates; do
		if [ "$ec" = "$check_e" ]; then
			return 0
		fi
	done
	return 1
}

compiled_count=0
failure=0

for crate in $gated_crates; do
	if is_exempt_crate "$crate"; then
		continue
	fi

	if ! cargo clippy -p "$crate" --target x86_64-pc-windows-msvc --all-targets -- -D warnings; then
		echo "windows-target: crate '$crate' failed to compile for x86_64-pc-windows-msvc; fix the code or add the crate to ci/windows-target-exempt.txt with a reason" >&2
		failure=1
	else
		compiled_count=$((compiled_count + 1))
	fi
done

if [ "$failure" -ne 0 ]; then
	exit 1
fi

echo "windows-target: $compiled_count crate(s) compiled, $exempt_count exempt"
exit 0

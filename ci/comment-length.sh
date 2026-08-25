#!/bin/sh
# Mechanizes CLAUDE.md rule A2: fails on a run of six or more consecutive
# comment lines, covering both /* */ blocks and consecutive // lines, in
# crates/**/*.rs or packages/**/*.ts.
set -u

CHECK_NAME=comment-length
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

hits=$(printf '%s\n' "$files" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	awk -v fname="$f" '
	function flush_run(target) {
		if (run_len >= 6)
			print target ":" run_start ": run of " run_len " consecutive // comment lines through line " (run_start + run_len - 1)
		run_len = 0
	}
	function flush_block(target) {
		if (block_len >= 6)
			print target ":" block_start ": block comment spans " block_len " lines through line " (block_start + block_len - 1)
		block_len = 0
		in_block = 0
	}
	{
		line = $0
		trimmed = line
		sub(/^[ \t]+/, "", trimmed)

		if (in_block) {
			block_len++
			if (index(line, "*/") > 0) flush_block(fname)
			next
		}

		if (trimmed ~ /^\/\//) {
			if (run_len == 0) run_start = FNR
			run_len++
			next
		}
		flush_run(fname)

		if (trimmed ~ /^\/\*/) {
			if (index(trimmed, "*/") == 0) {
				block_start = FNR
				block_len = 1
				in_block = 1
			}
			next
		}
	}
	END {
		flush_run(fname)
		flush_block(fname)
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

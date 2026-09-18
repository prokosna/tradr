#!/bin/sh
# Mechanizes Invariant I1 (ADR-0005) inventory validation.
# See ci/README.md and docs/10-implementation-process.md.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
INVENTORY="$ROOT_DIR/ci/tier01-tests.txt"
cd "$ROOT_DIR" || exit 1

mode="validate"
if [ "$#" -eq 1 ]; then
	if [ "$1" = "--pairs" ]; then
		mode="pairs"
	else
		echo "usage: tier01-inventory.sh [--pairs]" >&2
		exit 2
	fi
elif [ "$#" -gt 1 ]; then
	echo "usage: tier01-inventory.sh [--pairs]" >&2
	exit 2
fi

if [ ! -f "$INVENTORY" ]; then
	echo "tier01-inventory: $INVENTORY does not exist; Invariant I1 has nothing to verify" >&2
	exit 1
fi

entry_count=0
pairs_output=""

while IFS='|' read -r raw_crate raw_target raw_reason || [ -n "${raw_crate:-}" ]; do
	crate=$(printf '%s' "${raw_crate:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	case "$crate" in
		'' | '#'*) continue ;;
	esac
	target=$(printf '%s' "${raw_target:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	reason=$(printf '%s' "${raw_reason:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

	if [ -z "$target" ]; then
		echo "tier01-inventory: $INVENTORY: entry '$crate' has no test target" >&2
		exit 1
	fi
	if [ -z "$reason" ]; then
		echo "tier01-inventory: $INVENTORY: entry '$crate|$target' has an empty reason" >&2
		exit 1
	fi

	test_file="crates/$crate/tests/$target.rs"
	if [ ! -f "$test_file" ]; then
		echo "tier01-inventory: $INVENTORY: $test_file does not exist" >&2
		exit 1
	fi

	entry_count=$((entry_count + 1))
	if [ -z "$pairs_output" ]; then
		pairs_output="$crate|$target"
	else
		pairs_output="$pairs_output
$crate|$target"
	fi
done < "$INVENTORY"

if [ "$entry_count" -eq 0 ]; then
	echo "tier01-inventory: $INVENTORY names no test; Invariant I1 has nothing to verify" >&2
	exit 1
fi

if [ "$mode" = "pairs" ]; then
	printf '%s\n' "$pairs_output"
	echo "tier01-inventory: $entry_count Tier 0/1 test target(s) named in the inventory" >&2
else
	echo "tier01-inventory: $entry_count Tier 0/1 test target(s) named in the inventory"
fi

exit 0

#!/bin/sh
# DCR-036: verifies .githooks/pre-commit is executable.
# See ci/README.md for details.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
HOOK="$ROOT_DIR/.githooks/pre-commit"
cd "$ROOT_DIR" || exit 1

if [ ! -f "$HOOK" ]; then
	echo "$HOOK: missing"
	exit 1
fi

if [ ! -x "$HOOK" ]; then
	echo "$HOOK: exists but is not executable (git file modes are not always preserved by every checkout path)"
	exit 1
fi

exit 0

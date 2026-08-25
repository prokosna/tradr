#!/bin/sh
# DCR-036: .githooks/pre-commit is version-controlled so it arrives with a
# clone, but git file modes are not always preserved by every checkout path
# (a zip download, some CI checkout actions), and a non-executable hook is
# silently never run by git -- no error, no warning, just skipped. This is
# the part a repository can mechanically verify. Whether a given clone has
# actually pointed core.hooksPath at .githooks is a per-clone git config
# setting; nothing under version control can observe that, and this check
# does not claim to.
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

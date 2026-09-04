#!/bin/sh
# The frontend gate: runs `pnpm lint`, `pnpm typecheck` and
# `pnpm format:check` in that order, all three regardless of an earlier
# failure, so one failure never hides another. See ci/README.md.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR" || exit 1

if ! command -v pnpm > /dev/null 2>&1; then
	echo "frontend-gate: pnpm is not on PATH" >&2
	exit 1
fi

if [ ! -d "$ROOT_DIR/node_modules" ]; then
	echo "frontend-gate: $ROOT_DIR/node_modules is missing; run pnpm install" >&2
	exit 1
fi

status=0

if ! pnpm lint; then
	status=1
fi

if ! pnpm typecheck; then
	status=1
fi

if ! pnpm format:check; then
	status=1
fi

exit $status

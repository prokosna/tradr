#!/bin/sh
# Runs every check in ci/, all of them, before reporting failure. Exits
# non-zero if any check failed, but never stops at the first one.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

overall=0

for check in comment-lang comment-length doc-visibility excuse-grep layer-deps state-sync; do
	echo "== $check =="
	if ! "$SCRIPT_DIR/$check.sh"; then
		overall=1
		echo "== $check: FAILED =="
	else
		echo "== $check: passed =="
	fi
done

exit $overall

#!/bin/sh
# Not a check: ci/run-all.sh names its checks explicitly and does not run
# this. It is the only sanctioned way to dispatch a Work Order to the agy
# Implementer, and it exists so that three disciplines STATE.md records as
# things to remember cannot be forgotten one at a time.
# See ci/README.md.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")

# agy's own --print-timeout defaults to 5m0s, which is shorter than
# `cargo test --workspace` plus `sh ci/run-all.sh` in this workspace, so a
# Work Order carrying the gates cannot finish inside it.
PRINT_TIMEOUT=${TRADR_PRINT_TIMEOUT:-30m}
MODEL=${TRADR_IMPLEMENTER_MODEL:-gemini-3.8-flash-high}

if [ $# -lt 1 ]; then
	echo "usage: ci/dispatch-implementer.sh <work-order-file> [log-file]" >&2
	echo "  env: TRADR_IMPLEMENTER_MODEL (default $MODEL)" >&2
	echo "       TRADR_PRINT_TIMEOUT     (default $PRINT_TIMEOUT)" >&2
	exit 2
fi

ORDER="$1"
LOG=${2:-"$ROOT_DIR/.dispatch-$(basename "$ORDER" .md).log"}

if [ ! -f "$ORDER" ]; then
	echo "$ORDER: work order not found" >&2
	exit 1
fi

if ! command -v agy > /dev/null 2>&1; then
	echo "agy is not on PATH" >&2
	exit 1
fi

cd "$ROOT_DIR" || exit 1

# An agy run is a plain subprocess rather than a subagent, so nothing in the
# session can observe its tool use and CLAUDE.md section 3's "the Implementer
# never commits" is held up by the prompt alone. Comparing HEAD across the
# call detects a violation; it does not prevent one.
head_before=$(git rev-parse HEAD)

echo "dispatching $ORDER"
echo "  model         $MODEL"
echo "  print-timeout $PRINT_TIMEOUT"
echo "  log           $LOG"
echo "  HEAD before   $head_before"

agy --model "$MODEL" \
	--print-timeout="$PRINT_TIMEOUT" \
	--add-dir "$ROOT_DIR" \
	--print="$(cat "$ORDER")" > "$LOG" 2>&1
status=$?

head_after=$(git rev-parse HEAD)

echo "  HEAD after    $head_after"
echo "  exit          $status"

if [ "$head_before" != "$head_after" ]; then
	echo "IMPLEMENTER COMMITTED: HEAD moved $head_before -> $head_after (CLAUDE.md section 3)" >&2
	exit 1
fi

# agy reports its own cut-off inside the log and still exits 0, so the exit
# status alone does not say whether the gate results in the report are real.
if grep -q "timeout waiting for response" "$LOG" 2>/dev/null; then
	echo "RUN WAS CUT OFF by agy's own print timeout ($PRINT_TIMEOUT): the report is incomplete" >&2
	echo "raise TRADR_PRINT_TIMEOUT and dispatch again, or review the tree directly" >&2
	exit 1
fi

exit $status

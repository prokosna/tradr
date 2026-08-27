#!/bin/sh
# Enforces Invariant I1 (ADR-0005, docs/10-implementation-process.md):
# Every Tier 0 and Tier 1 feature must work completely standalone with
# no Brokr running or configured.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR"

echo "== no-brokr: Verifying Invariant I1 (Brokr-free operation) =="

# 1. Ensure no hardcoded Brokr URLs or mandatory server endpoints exist in client crates
# docs/05 and ADR-0005: Brokr is strictly optional; default configuration has no Brokr URL.
echo "Checking client crates for hardcoded Brokr dependencies..."
if grep -rnE "https?://.*brokr" crates/ | grep -v "docs/" | grep -v "tests/" | grep -v "README"; then
    echo "Error: Hardcoded Brokr URL found in client crates."
    exit 1
fi

# 2. Run Tier 0 and Tier 1 integration tests under a sealed, Brokr-disabled environment
# TRADR_BROKR_URL points to a non-existent port to guarantee any network dial to a Brokr immediately fails.
export TRADR_BROKR_URL="http://127.0.0.1:0"
export TRADR_NO_BROKR="1"

echo "Running workspace test suites under sealed Brokr-free environment..."
cargo test --workspace

echo "== no-brokr: Invariant I1 verified successfully =="
exit 0

# Git Hooks

## pre-commit
DCR-036's local gate: every commit passes ci/run-all.sh, cargo fmt, cargo clippy and cargo test, in that order, stopping at the first failure. Enabled per clone via `git config core.hooksPath .githooks` (see README.md) -- git does not turn this on by itself, so a clone that never ran that command gets no protection from this file at all.

Runs the full suite rather than only what touches staged files: this fires once per Work Item, after a review has already passed, so completeness is worth more here than speed. The only fast path is skipping entirely when nothing is staged, since there is then nothing for any of the four stages to judge either way.

## pre-push
Direct pushes to main bypass code review and pull request gates. This hook enforces the rule that no branch is pushed directly to `main`.

# Git hooks

Enable per clone: `git config core.hooksPath .githooks`.

- **pre-commit**: refuses commits on `main`; runs `ci/run-all.sh` and `cargo fmt --check`. Fast enough to run on every commit.
- **pre-push**: refuses pushes to `main`; runs clippy, `ci/windows-target.sh` and `cargo test --workspace`. CI runs the same and more.

Never bypass with `--no-verify`.

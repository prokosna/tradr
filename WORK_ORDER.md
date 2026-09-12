# Work Order WI-M7-007m — REVISE round 2

## Role

You are the **Implementer**. `CLAUDE.md` §3 and §4 bind you exactly. **Never edit** `docs/`, `STATE.md`, `RECORD.md`, `CLAUDE.md`, `AGENTS.md`, or this file. **Never commit, push, branch, stash, checkout or reset.** Leave the work in the working tree.

**Round 1 passed review and its commit has landed on this branch. Nothing in it is being discarded.** What follows is a defect CI found that no gate in the Definition of Done could have found, and the second half of this order is about that gap rather than about you.

## Finding — the Android half does not compile, and every gate you were given passes anyway

`.github/workflows/ci.yml`'s `android-debug-smoke` job fails on the branch:

```
error[E0432]: unresolved import `tradr_identity::ClockKeyBindingVerifier`
  --> crates/tauri-plugin-tradr/src/lifecycle.rs:39:5
   |
39 | use tradr_identity::ClockKeyBindingVerifier;
   |     ^^^^^^^^^^^^^^^^-----------------------
   |                     |
   |                     no `ClockKeyBindingVerifier` in the root
```

`crates/tradr-identity/src/lib.rs` declares `pub mod key_binding;` and re-exports nothing from it, so the type's path is `tradr_identity::key_binding::ClockKeyBindingVerifier`. Every other import in that `#[cfg(target_os = "android")]` block is correct.

**This is not a gate you skipped.** `cargo clippy --workspace --all-targets`, `cargo test --workspace` and `sh ci/run-all.sh` all compile for the host, and `spawn_ble_gatt_listener` is behind `#[cfg(target_os = "android")]`, so none of them ever type-checks a line of it. The Work Order named those four gates and they were all genuinely green.

## Definition of Done

### 1. Correct the import

`crates/tauri-plugin-tradr/src/lifecycle.rs` line 39: `use tradr_identity::key_binding::ClockKeyBindingVerifier;`.

**Do not re-export the type from `crates/tradr-identity/src/lib.rs`.** That crate is out of scope and the path that already exists is correct.

### 2. Fix whatever else the Android target reports, and nothing else

The error above is the first the compiler reached; there may be more behind it in the same `cfg` block. Fix only errors the Android target actually reports, in `crates/tauri-plugin-tradr` only. **If an Android error can only be fixed by changing something under `crates/tradr-*` or by changing behaviour rather than a path or a type, stop and report it** rather than working around it.

### 3. Gates — five, and the first one is new

```
cargo check --target aarch64-linux-android -p tauri-plugin-tradr
cargo fmt --all -- --check
sh ci/run-all.sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

**The first is the one that matters here and it needs no NDK** — `cargo check` does not link, so the cross-target check runs on this machine with nothing installed beyond the `aarch64-linux-android` rustup target, which is already present. It reproduces the CI failure exactly; run it before and after your change and report both.

Format files you edited with `rustfmt --edition 2024 <path>` per file.

**Report the commands' actual output, never an assertion about it.** A gate you did not run is reported as NOT RUN.

## Change nothing else

No test changes, no new test. The behaviour of `spawn_ble_gatt_listener` does not change: this is a path, not a decision.

## Report back

The files you changed; the verbatim output of `cargo check --target aarch64-linux-android -p tauri-plugin-tradr` **before** your change and **after** it; the verbatim tail of the other four gates; and any Design Change Request you are raising.

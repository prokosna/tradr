# ADR-0015: Tauri 2 is retained after M0's decision point

**Status**: Accepted
**Date**: 2026-08-25
**Supersedes**: nothing. [ADR-0001](0001-tauri-2-as-app-shell.md) stands, and this records the evaluation it scheduled.

## Context

[ADR-0001](0001-tauri-2-as-app-shell.md) chose Tauri 2 as the app shell and named three conditions whose failure would mean moving to Electron with Kotlin. It scheduled the evaluation for the end of M0 rather than leaving it to judgement, because a shell is expensive to leave late and each condition is cheap to check early.

## Decision

**All three conditions are met, and Tauri 2 is retained.**

| Condition | Evidence |
|---|---|
| Bidirectional Kotlin and Rust calls | WI-M0-005, on a real emulator. Rust into Kotlin through `PluginHandle::run_mobile_plugin`, Kotlin into Rust through `tauri::ipc::Channel`, pushed 1.5 s after the call returned. A negative control moved Rust's printed value when Kotlin's formula changed, and `ro.product.model` came back as a value Rust could not otherwise know |
| `ACTION_SEND` arrives through the plugin | WI-M0-005b, cold start and `onNewIntent` both, corroborated by `ActivityTaskManager`'s own launch codes and an identical pid across the two deliveries |
| The Android build passes reliably in CI | WI-M0-015. The workflow builds an unsigned APK and an AAB across four ABIs, with no OAuth configuration present, and the first real run was green |

Change Drill D9 was also walked (DCR-035). No `Cargo.toml` under `crates/` but the binding crate's names `tauri`; a move to Electron reaches `tauri-plugin-tradr`, the app's `src-tauri`, and the UI, and no library crate at all.

## Consequences

- The withdrawal conditions do not expire. **ADR-0001's third condition is about reliability, which a single green run does not establish**, so it stays worth watching rather than settled forever.
- The composition root remains the only crate naming the shell, and `ci/layer-deps.sh` keeps it that way on every run.
- **The Android job costs 41 minutes**, which does not fit a free tier at every-push frequency. Reducing it must not reduce what the condition above rests on: the four-ABI release build is what proves the toolchain, and a routine build proving less has to say so.

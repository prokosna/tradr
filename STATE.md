# STATE

Short, current, and edited in the same PR as the change it describes. History lives in `git log` and PRs. The pre-2026-11-26 long-form record is at `git show ad37cc7:STATE.md` and `git show ad37cc7:RECORD.md`.

```yaml
last_updated: 2026-11-26
current_milestone: M8 (self-beta in use) / M9 built
latest_release: v0.1.4 (draft, 2026-10-17)
```

## In flight

Nothing is in progress in code. The last landed work: dial deadline 3 s (#369), mDNS recheck + Refresh (v0.1.3), and the release pipeline (v0.1.1+).

## Device checks

None are tracked. The user runs the builds daily and reports problems as they appear (decided 2026-11-27). Only one setup step remains: the release APK cannot sign in until its keystore SHA-1 is registered for `com.tradr.app` in the Google console.

## Open decisions (the user's)

- Same-account and linked auto-accept: does it need a size or extension threshold?

## Backlog

Product:
- Forget a known device (Windows still lists the replaced debug APK as offline).
- A file written into this device's folder by another device adds no Received row.
- A download into its own folder writes straight to its final name instead of going through `.tradr-partial`.
- QR scanning inside the app (`WI-M6-009`). Drag-out and shell integration. Sharing Shortcuts.
- 24 h silent Attestation renewal (desktop refresh token; Android unmeasured).
- Hardware-backed keys (Keystore, Secure Enclave, TPM). Blocked on `backing()` being one value for two keys.

Tech debt:
- `packages/` holds empty stubs, and the ts-proto output (`packages/protocol`, `buf.gen.yaml`) is imported by nothing. Delete both, or use them.
- `keep_alive_preserves_idle_connection_past_timeout` once hung CI for an hour; it needs a bound.
- `tauri-plugin-opener` is pinned to `=2.5.5` until a deliberate Tauri 2.12 upgrade.
- The atomic-write registry helper is copied in several places (tradr-identity, tradr-app). Unify it.
- `is_virtual_interface` misses one tailnet interface prefix, so tailnet addresses get published as mDNS candidates.
- Listener failure lines: the cause of the stray "channel already closed" is still unconfirmed.
- Secret Service prompt wait is unbounded. `SharedSecret` is not zeroized. `KeyStore` is synchronous (it would block on Android Keystore).
- Android Rust code (`cfg(target_os="android")`) is not on the commit path: run `cargo check --target aarch64-linux-android -p tauri-plugin-tradr`. Full Android clippy does not pass yet.
- CI runners are unpinned `-latest`.
- Several tests survive mutation of the line they guard: the rung choice in `open_identity`, the platform arm in `provider_profile`, the link-reply pin expectation, and others. See `git show ad37cc7:STATE.md`, Deferred table.

## Notes for the next session

- UI preview and screenshot instructions: [docs/12](docs/12-user-interface.md#checking-ui-work).
- Build env: Ubuntu 24.04 with Rust, pnpm and the Android SDK/NDK. `cargo check --target aarch64-linux-android` needs only the rustup target.
- The release flow: push tag `vX.Y.Z` to get a draft Release ([docs/09](docs/09-roadmap-and-risks.md#releases)).

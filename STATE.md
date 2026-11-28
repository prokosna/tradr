# STATE

Short, current, and edited in the same PR as the change it describes. History lives in `git log` and PRs. The pre-2026-11-26 long-form record is at `git show ad37cc7:STATE.md` and `git show ad37cc7:RECORD.md`.

```yaml
last_updated: 2026-11-28
current_milestone: M8 (self-beta in use) / M9 built
latest_release: v0.1.7 (draft, 2026-11-28)
```

## In flight

Nothing is in progress in code. The last landed work: Settings shows the version, the signed-in email and the receive service state (#382), in v0.1.7.

## Device checks

None are tracked. The user runs the builds daily and reports problems as they appear (decided 2026-11-27). Only one setup step remains: the release APK cannot sign in until its keystore SHA-1 is registered for `com.tradr.app` in the Google console.

## Open decisions (the user's)

- Same-account and linked auto-accept: does it need a size or extension threshold?

## Backlog

Product:
- Android: resume receiving after an app update or reboot without opening the app (`MY_PACKAGE_REPLACED`/`BOOT_COMPLETED`, plus starting the Rust listener without the Activity). Supersedes ADR-0022's "never at boot"; needs an ADR.
- QR scanning inside the app (`WI-M6-009`). Drag-out and shell integration. Sharing Shortcuts.
- Hardware-backed keys (Keystore, Secure Enclave, TPM). Blocked on `backing()` being one value for two keys, and `KeyStore` would need to become async (a Keystore sign is an IPC).

Tech debt:
- Android receive service: once seen not running while the app was open (cause unknown); gone after v0.1.7. It is now restarted on every resume, and Settings → About this device shows any refusal.
- Listener failure lines: the cause of the stray "channel already closed" is unconfirmed. Paste the `transfer from <id> failed during <phase>` line when it next appears.
- Tests that still survive mutation of the line they guard: see `git show ad37cc7:STATE.md` (Deferred). The link-reply pin, OAuth platform choice and key-rung choice are now covered.

## Notes for the next session

- UI preview and screenshot instructions: [docs/12](docs/12-user-interface.md#checking-ui-work).
- Build env: Ubuntu 24.04 with Rust, pnpm and the Android SDK/NDK. `cargo check --target aarch64-linux-android` needs only the rustup target.
- The release flow: push tag `vX.Y.Z` to get a draft Release ([docs/09](docs/09-roadmap-and-risks.md#releases)).

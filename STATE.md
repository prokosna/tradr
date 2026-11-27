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
- QR scanning inside the app (`WI-M6-009`). Drag-out and shell integration. Sharing Shortcuts.
- Automatic Attestation renewal. A refresh token is useless (its ID token has no `nonce`, measured 2026-11-27). The candidate is re-running the authorization with the same nonce before day 21: desktop `prompt=none` in the browser, Android Credential Manager auto-select.
- Hardware-backed keys (Keystore, Secure Enclave, TPM). Blocked on `backing()` being one value for two keys, and `KeyStore` would need to become async (a Keystore sign is an IPC).

Tech debt:
- Listener failure lines: the cause of the stray "channel already closed" is unconfirmed. Paste the `transfer from <id> failed during <phase>` line when it next appears.
- Tests that still survive mutation of the line they guard: see `git show ad37cc7:STATE.md` (Deferred). The link-reply pin, OAuth platform choice and key-rung choice are now covered.

## Notes for the next session

- UI preview and screenshot instructions: [docs/12](docs/12-user-interface.md#checking-ui-work).
- Build env: Ubuntu 24.04 with Rust, pnpm and the Android SDK/NDK. `cargo check --target aarch64-linux-android` needs only the rustup target.
- The release flow: push tag `vX.Y.Z` to get a draft Release ([docs/09](docs/09-roadmap-and-risks.md#releases)).

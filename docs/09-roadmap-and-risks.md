# 09. Roadmap, releases and risks

Deployment: **private**, meaning one person's four devices (Android, Windows, Linux, MacBook). Nothing is distributed to strangers, so store submission, multi-format packaging and purchased signing certificates are out of scope.

## Milestones

| # | Scope | Status |
|---|---|---|
| M0 | Skeleton: monorepo, Tauri on Linux and Android, Google sign-in, keys, Attestation | done 2026-08-25 |
| M1 | LAN transfer: mDNS, QUIC, resume, drag-and-drop | done 2026-08-29 |
| M2 | Android integration: share sheet, fd adoption, permissions | done 2026-08-30 |
| M3 | Folder browsing: VFS, boundary enforcement, Browse plane | done 2026-08-30 |
| M4 | Windows and macOS builds, tray | done 2026-08-30 |
| M5 | Static Peers over Tailscale | done 2026-08-31 |
| M6 | Account linking: invite blob, QR display, Fingerprint | done 2026-09-05 |
| M7 | BLE | built 2026-09-14, never used, **removed 2026-11-27** ([ADR-0028](adr/0028-ble-removed.md)) |
| M8 | Usable UI ([12](12-user-interface.md)) + CLI | in use; feature-complete for a self-beta |
| M9 | Brokr, cut down to Deferred Delivery ([13](13-deferred-delivery.md)) | built; device run owed |
| M10 | Finishing: internal security review, i18n (ja/en), exhaustive resume tests | todo |

Not built and not scheduled: Phase 3 path race, Phase 5 mid-transfer switching, `wifi-direct`, holepunch/relay, Brokr presence, Sharing Shortcuts, `Watch`, drag-out, a QR scanner (`WI-M6-009`), hardware-backed keys, 24 h silent renewal, ephemeral nearby mode.

## Releases

A pushed tag `vX.Y.Z` makes `.github/workflows/release.yml` build a **draft** GitHub Release. Drafts are visible only to people with write access, so they stay private.

| Platform | Artifact | Signing |
|---|---|---|
| Android | release APK, aarch64, `com.tradr.app` | project keystore (repo secrets). Its SHA-1 must be registered for the Android OAuth client |
| Windows | NSIS installer | none (SmartScreen click) |
| macOS | zipped `.app`, Apple Silicon | ad-hoc (`signingIdentity "-"`, verified with `codesign`); use "Open Anyway" once. No DMG |
| Linux | `.deb` | none |

- The tag is the version: `X.Y.Z` goes to every build, and Android's `versionCode` derives from it.
- `TRADR_OAUTH_CLIENT_IDS` and `TRADR_OAUTH_CLIENT_SECRET` come from repo secrets, and the release is refused if either is empty.
- The release APK (`com.tradr.app`) and the debug APK (`com.tradr.app.debug`) are different apps with different Device IDs.
- Auto-update is off. R8 minification of the release APK is untested on a device.
- CI builds macOS and Windows with `--no-bundle`; only the Linux job bundles.

## Risks (still open)

| # | Risk | Response |
|---|---|---|
| R6 | Transfers break on a path switch | 1 MiB reference chunks (I6); resume is a Critical Module |
| R8 | A Brokr dependency creeps into Tier 0/1 | `no-brokr` CI job (I1) |
| — | Android battery cost of the resident service | measure |

## Open questions

- Same-account auto-accept: is a size or extension threshold needed?
- Clipboard send: an explicit action only, if ever.
- Write limits on the served folder.
- Post-quantum: write an ADR once rustls ML-KEM is stable.

Decided: one Google account per device (v1). BLE removed (ADR-0028). The Received list is kept until the user clears it.

## Fragile places → their guard

| Place | Guard |
|---|---|
| Chunk resumption | Critical Module tests (`chunk_resumption.rs`), I6 |
| Folder boundary | Critical Module adversarial suite in `tradr-vfs/tests` (I5) |
| Attestation verification | a negative test per step |
| No-Brokr operation | CI `no-brokr` (I1) |
| Android `content://` lifetime | never pass a URI to Rust; adopt the fd in the Activity |

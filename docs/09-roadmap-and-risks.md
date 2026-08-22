# 09. Roadmap and risks

## Milestones

Estimates assume one person working. M4 onward can be split when work runs in parallel.

### M0 — Skeleton (2 weeks)

- pnpm and Cargo monorepo, code generation from `proto`, CI
- The Tauri 2 app launches on Linux and Android
- Google OAuth works on both, loopback with PKCE on desktop and Custom Tabs on Android
- Key generation and OS key store storage, Linux and Android
- Issuing an Attestation, with the public keys in the nonce, and verifying one

**Done when**: two devices exchange Attestations by hand and each verifies the other.

### M1 — LAN transfer (4 weeks), the most important

- mDNS advertising and discovery
- QUIC via `quinn` with public-key pinning for mutual authentication
- `Hello`, `TransferOffer`, `TransferAccept`
- Chunking, BLAKE3 verified streaming, pull-based transfer
- Resumption after interruption
- Desktop drag-and-drop sending
- Android receiving, with the foreground service

**Done when**: a 1 GB file goes Linux to Android, survives Wi-Fi being cut and restored by resuming automatically, and the hashes match.

M1 completing makes UC-1 work. It is the smallest thing that is a product, so **getting through it fastest is the priority**.

### M2 — Android integration (3 weeks)

- `ACTION_SEND` and `ACTION_SEND_MULTIPLE`
- Sharing Shortcuts, putting destinations in the share sheet
- SAF for choosing where files land
- Staged permission requests
- Accept and decline from a notification

**Done when**: choosing a photo in the Android gallery and tapping Tradr once in the share sheet delivers it to a PC.

### M3 — Share browsing (3 weeks)

- `tradr-vfs` with `PosixVfs` and `SafVfs`, boundary enforcement, TOCTOU handling
- The Browse plane
- The share browser UI: listing, download, upload where `rw`
- Live updates through `Watch`

**Done when**: an adversarial path suite covering `..`, symlinks, and Unicode tricks is entirely rejected. **That suite is written before the feature.**

### M4 — Windows and macOS (3 weeks)

- Builds, packaging, and signing on all three desktop platforms, including Authenticode and notarization
- Auto-update through the Tauri updater
- Tray and menu bar integration
- Per-OS key store implementations

**Done when**: signed installers ship and all four platforms transfer between each other.

### M5 — Static Peers and overlay networks (1 week)

- Static Peer registration UI and trust-on-first-use key pinning
- Reading Tailscale status to offer candidates
- Phase 3 of path selection, the race

**Done when**: a transfer completes over Tailscale with no Brokr.

M5 is cheap and resolves UC-6, so **it comes before M6 and M7**.

### M6 — Account linking (2 weeks)

- In-person linking by QR and by invite blob
- Link Secret derivation and `link_id`
- Fingerprint display and verification UI
- Naming a link in a Share's audience
- Removing a link

**Done when**: two devices on different accounts link by QR, transfer both ways, and removal takes effect immediately.

### M7 — BLE (4-5 weeks), the largest estimation risk

- `BleAdvertiser` and `BleScanner` traits with four platform implementations
- EID derivation and rotation, ABK exchange
- Noise_IK over GATT
- Payloads up to 512 KiB
- Integration into path selection

**Done when**: with all Wi-Fi off, Linux and Android exchange text and a 200 KB image.

### M8 — Brokr (3 weeks)

- Fastify and SQLite, WebSocket presence registry
- Registration by join token and challenge signature
- Rendezvous and NAT hole punching
- Relay, streaming and temporary storage
- FCM wake-up
- Linking through a Brokr
- Revocation list
- Docker image and setup instructions

**Done when**: every Tier 0 and Tier 1 integration test passes with the Brokr stopped. That check goes into CI.

### M9 — Finishing (ongoing)

- External security review
- Play Store submission, which needs permission justifications
- Linux packaging: Flatpak, AppImage, deb, rpm
- Internationalization, Japanese and English
- Exhaustive resumption tests across every path

## Risks

| # | Risk | Impact | Likelihood | Response |
|---|---|---|---|---|
| R1 | **BLE peripheral role means four separate implementations** | M7 doubles | High | Spend M7's first week on nothing but connectivity checks per OS. If three or more prove difficult, fall back to scan-only BLE, where others find you but you do not advertise |
| R2 | **Tauri 2's Android maturity** | The foundation gets rechosen | Medium | M0 prioritizes the Android build and Kotlin plugin calls above everything. If it stalls, decide at the end of M0 whether to switch to Electron plus native Android |
| R3 | **A Google change breaks the Attestation design** | Authentication gets rebuilt | Low | `nonce` is core OIDC and unlikely to move. Silent refresh via `prompt=none` could be restricted, but that only raises re-login frequency without breaking the design |
| R4 | **SAF too slow for Share browsing to be usable** | UC-3 fails on Android | Medium | Measure against a 10,000-file directory early in M3. If caching is insufficient, restrict Android Share Roots to a few frequently used directories |
| R5 | **Play Store rejects the BLE or storage permissions** | Loss of a distribution channel | Medium | The design avoids `MANAGE_EXTERNAL_STORAGE` and declares `neverForLocation` correctly. Worst case, fall back to F-Droid and direct APK distribution |
| R6 | **Transfers break when the path switches** | The core capability's reliability | Medium | Chunk boundaries are fixed at 1 MiB regardless of path. Build a harness that forces path switches during M1 and reuse it in every later milestone |
| R7 | **Low hole-punching success rate** | Tier 2 leans on relay and eats bandwidth | Medium | Measure with `rendezvous_attempts_total{result}`. Below 50%, consider implementing something TURN-shaped |
| R8 | **Brokr-free operation breaks as features are added** | The central premise of the design collapses | High | Make the no-Brokr Tier 0/1 integration test a required CI job. Introduce it at M1, not M8 |
| R9 | **macOS and Windows code signing** | Distribution stops | Medium | Start certificate procurement before M4. Apple Developer Program and an Authenticode certificate can each take weeks |
| R10 | **Dragging out cannot be implemented** | A gap in the experience | Medium | Substitute a download button in v1. Functionally equivalent and not fatal |

R1, R2, and R8 are the heavy ones. R2 gets an explicit decision point at the end of M0.

## Open design questions

Written down, not yet decided.

1. **Whether one device may use several Google accounts.**
   Wanting to switch between work and personal is a real request. Several Attestations are technically fine, but the UI and the Share audience model both get more complicated. Ship v1 single-account and decide from feedback.

2. **Whether same-account transfers auto-accept by default.**
   Convenient, but a compromised account could push files silently. A compromise is auto-accept with a confirmation threshold on size or extension. Decide from how it actually feels.

3. **How much transfer history to retain.**
   A list of received files is useful, and is itself a sensitive record. No default retention period has been chosen.

4. **Whether to do clipboard sharing.**
   It fits inside the 512 KiB BLE limit and suits UC-5. Continuously watching the clipboard carries a real privacy cost, so limiting it to an explicit "send clipboard" action would be safe. Low priority.

5. **What write limits a writable Share should carry.**
   A limit is needed against disk filling, but legitimate large transfers look identical. A daily byte cap is workable; there is no basis yet for a default value.

6. **When to move to post-quantum cryptography.**
   Write an ADR once both `rustls` X25519MLKEM768 and `snow`'s hybrid Noise patterns are stable. Priority is low, since transferred files rarely need secrecy over that horizon.

## The most fragile parts of this design

Named before implementation begins, so testing goes where it is needed.

| Place | Why it is fragile | Response |
|---|---|---|
| Chunk-level resumption | The whole path-selection design rests on it — see [03](03-discovery-and-transport.md#phase-5-is-the-point). Breaking it cascades | Keep `tradr-core` free of I/O and build a harness in M1 that injects disconnections and path switches |
| Share Root boundary enforcement | Getting past it means arbitrary file read. Attacker input becomes a path directly | Write the adversarial path suite before the feature. Concentrate the implementation in one `tradr-vfs` function and let nothing else assemble paths |
| Attestation verification | Skipping one step of the check admits impersonation | Write a negative test for every step, each disabling one check |
| Operation without a Brokr | Implicit dependencies creep in with every feature | Make it a required CI job (R8) |
| The lifetime of Android `content://` URIs | Bound to the Activity lifecycle, so passing one into async work fails later | Keep the discipline of never handing a URI to Rust; convert to an fd or a copy inside the Activity |

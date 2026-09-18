# 09. Roadmap and risks

## Milestones

Estimates assume one person working. M4 onward can be split when work runs in parallel.

**The tail of this list was reshaped on 2026-09-13 against how this software is actually going to be used (DCR-113), and the reshape added a milestone rather than only removing work.** The deployment is private: four devices belonging to one person -- Android, Windows, Linux and a MacBook -- and no distribution to anyone else. **The first consequence is what was missing.** Every milestone here was a capability, and nothing scheduled the interface; the two interface defects still open, `WI-M5-009` and `WI-M5-010`, were both found by *running* the application rather than by any planned work. A roadmap optimised for capability had no place for "usable enough to start using", which is the condition the person running it actually set, so **M8 is now that milestone and the two that followed moved up by one.**

```
old M8  Brokr      -> M9       (kept; see the requirement it gained below)
old M9  Finishing  -> M10      (shrunk; a private deployment deletes most of it)
new M8  Usable interface       (the gap this reshape found)
```

**Text elsewhere that says "M8 — Brokr" or "M9 — Finishing" predates this** and means what is now M9 and M10.

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

**It closed on its code instead, 2026-09-14, by DCR-118's neighbour DCR-117.** Every row a machine can implement is landed and every gate is green; the run above needs an APK built on the user's MacBook and two radios in one room, and it has never been performed. **Closing on the code is a reading of what this milestone was for**: M7 was the largest estimation risk because nobody knew what BLE would cost to write, and that is answered. Whether it works is the other question, and a milestone boundary answers neither way -- so the run carries into M8, which is the milestone whose whole instrument is running the thing.

### M8 — Usable interface (unestimated)

**The condition on using this software at all, and the only milestone here that came from the person running it rather than from the design.** Nothing before this point scheduled the interface, and the application is in a state its own author calls too hard to use.

- The two open interface defects: a refusal the frontend swallows reaching nobody (`WI-M5-009`), and a Static Peer arriving in a list that claims to show the local network (`WI-M5-010`)
- Whatever else running the application on all four devices turns up. **The list is not written here, because the way to find it is to use the thing** -- which is the same instrument that produced the two above
- **Done when**: the person running it sends and receives on all four devices without needing to know what a Static Peer or a Trust Tier is

**No estimate.** An interface is judged by use rather than by completion criteria, and an estimate here would be a number with nothing behind it.

**A command-line interface is wanted as well, and measuring what it costs turned Change Drill D9 from a hypothetical into a reading.** D9 budgets a move away from Tauri at "UI, Adapter and the binding crate swapped, the other five crates untouched", and a CLI is that swap performed for real rather than argued. The measurement, taken 2026-09-13: in `crates/tauri-plugin-tradr/src/commands.rs` **every function above the first `#[tauri::command]` names no Tauri type** -- the whole send path, the browse path, `resolve_peer`, `pick_candidate`, `connect_and_pin` and the peer-source drain -- and ten of the crate's modules mention Tauri not once, `handshake.rs`, `listener.rs`, `peer_trust.rs` and `transfer.rs` among them. Everything below that line is a thin wrapper resolving `State<'_, _>` and delegating.

**So a CLI is a move rather than a rewrite**: lift the Tauri-free half into a crate of its own, leave the command wrappers and the plugin lifecycle where they are, and write a second composition root over it. `ci/layer-deps.sh` already forbids every `Cargo.toml` under `crates/` except the binding crate's from naming Tauri, so the extraction strengthens that gate instead of straining it.

**Where it goes was settled on 2026-09-14 by DCR-118, and settling it found a rule the measurement had not checked.** `ci/layer-deps.sh` lets an implementation crate depend only on `tradr-core` and `tradr-proto`; the Tauri-free half reaches six internal crates, so a crate holding it fails the gate on its first commit. The composition tier therefore has two crates rather than one -- `crates/tradr-app` and `crates/tauri-plugin-tradr` -- and check 4 exempts both. **Check 3 exempts only the second**, which is what turns this paragraph's own reading into a gate: the half that must never name Tauri is now held to that by a manifest scan rather than by a grep somebody ran once. See [docs/02](02-architecture.md).

**Four phases, each leaving a compiling tree and a green gate.** Phase 1 is the five modules that name neither Tauri nor a sibling -- `capabilities`, `handshake`, `link_exchange`, `share`, `transfer` -- plus the rule change. Phase 2 is `peer_trust`, `attestation` and `sign_in`, and it is the phase with real work in it: `sign_in` is a command that binds a listener, opens a browser and waits on a person, so the split is that everything after the code exchange becomes a function taking the `PeerTrust` and asking it to warm itself from the provider's JWKS uri (DCR-119). **Taking a document the caller fetched was the first answer and it opens DF-60's own hole one line further out**: the line choosing which uri to fetch would stay in the `#[tauri::command]`, so `fetch_jwks(&profile.token_uri)` there would survive every test there is. Phase 3 is `listener`, `link_invite`, `broadcast_secrets` and `commands.rs` above its first `#[tauri::command]`. Phase 4 is the second composition root.

**Two things make it cheaper than it looks, and the third was the one open question.** The progress seam exists already -- `execute_send_files_with_progress` takes a callback, and a Tauri build emits an event through it where a CLI would draw a bar, which is the coupling a UI-shaped API would have hidden. And sign-in is a loopback listener plus a browser launch, which is what a command-line OAuth flow does anyway.

**Receiving is settled, 2026-09-15 by DCR-123: `tradr receive` is a foreground command.** It holds the terminal, drives `listen_for_transfers`, prints each arrival, and ends when the person ends it. There is no daemon, no unit file and no control socket, and **what that costs is stated rather than hidden**: nothing arrives while the command is not running. **That is the product this CLI is** -- a session a person opens on one side of a transfer, not a service a machine keeps -- and the GUI remains the thing that is running when a transfer arrives unannounced. **The seam it needs is the one the plugin already drives**: `tradr_app::listener::listen_for_transfers` takes the verifier and the accept callback, so a foreground command supplies a terminal prompt where the shell supplies a dialog. **The clause that used to end this sentence -- that phase 4 adds a composition root rather than anything to the crate -- was wrong, and DCR-126 measured it**: the second front end may name exactly one internal crate, so the composition it would assemble cannot be written there at all. See [docs/02](02-architecture.md#two-front-ends-one-device).

**Whose device the CLI is was settled the same day, by DCR-124: the same one the GUI is.** One installation, one Device Key and one application data directory -- because Change Drill D9 asks what swapping the shell costs, and **a swap that minted a new Device Key would not be a swap**. Two consequences follow and neither is optional. The storage ladder is searched in exactly one place, which today is a file naming `tauri::AppHandle`, so the search and the Device Key open move into `tradr-app` with the ladder passed in rather than built inside; and the CLI goes to `apps/tradr-cli`, where `ci/layer-deps.sh` check 3's blanket exemption for `apps/` narrows to the Tauri app so that the second front end is refused `tauri` by the same manifest scan that holds the shell-free crate to it. **Phase 4 is therefore more than one Work Item before it is any commands**: what both front ends must share, which `WI-M8-011` and `WI-M8-012` landed, then the sign-in flow and the receive composition DCR-126 and DCR-127 move across, and the commands last. See [docs/02](02-architecture.md#two-front-ends-one-device).

**What one device does not mean is one sign-in, decided 2026-09-16 by DCR-127 after the sentence above claimed it did**: nothing shares a sign-in and nothing was written to, `SignInState` is held in memory for the life of a process, and a `tradr receive` composed over the tree as it stood would bind, advertise, accept a channel and then refuse every transfer on it. Each front end signs in for itself and the command does it first, which is [docs/02](02-architecture.md#two-front-ends-one-device) again.

**What the command accepts, and where it gets a client id, were the two questions phase 4 had left, both settled 2026-09-17.** DCR-129 answers the first and it is open decision 9 arriving as an implementation question: an account that is neither this device's own nor linked never reaches an offer, because the handshake refuses it, so `tradr receive` accepts everything the peers that do reach one send -- the GUI's own answer -- and a prompt on stdin is refused rather than postponed, since the listener loop owns the terminal and two transfers can arrive at once. DCR-128 answers the second: a build script bakes a value because a GUI has no environment to read, a command has one, so the CLI reads the deployment's two variables at run time and bakes nothing. See [docs/02](02-architecture.md#two-front-ends-one-device) and [docs/05](05-security.md#oauth-client-configuration).

### M9 — Brokr (3 weeks)

- Fastify and SQLite, WebSocket presence registry
- Registration by join token and challenge signature
- Rendezvous and NAT hole punching
- Relay, streaming and temporary storage
- FCM wake-up
- Linking through a Brokr
- Revocation list
- Docker image and setup instructions

**Done when**: every Tier 0 and Tier 1 integration test passes with the Brokr stopped. That check goes into CI.

**The Brokr is wanted for a reason this list did not contain, stated 2026-09-13: exchange that is not real time.** A sender hands a transfer to the Brokr, and a receiver that is offline collects it when it next comes online, with neither side waiting on the other. **"Relay, streaming and temporary storage" above is not that**: it holds bytes for a live transfer whose other end is already connected, and it is the reason the requirement is easy to mistake for something already designed.

**It is not sync, and the distinction has to hold in the vocabulary as well as in the code.** [docs/01](01-overview.md)'s non-goals refuse synchronisation, and this is a queued delivery of one Transfer in one direction, with no reconciliation, no conflict and no shared state to converge. **Nothing about it is designed yet** -- how long the Brokr holds ciphertext, what bounds the queue, what the sender learns about delivery, and how it interacts with [ADR-0005](adr/0005-brokr-is-optional.md)'s promise that every Tier 0 and Tier 1 feature works with no Brokr, since this feature is definitionally Tier 2. That design happens when this milestone is cut, and the requirement is recorded here so it is not rediscovered as a surprise.

### M10 — Finishing (ongoing)

**A private deployment deletes most of what this milestone used to hold, and the deletions close two open decisions and two risks with them.**

- **An internal security review**, not an external one. It protects one person's own files, which is reason enough to run it and not reason enough to pay a third party
- ~~Play Store submission~~ **Dropped.** Direct APK installation. **R5 goes with it** -- a store cannot reject permissions it is never shown
- **One Linux package, not four.** ~~Flatpak, AppImage, deb, rpm~~. **R11 and open decision 7 resolve here**: dropping AppImage is what removes the five unpinned build-time downloads, and there is nothing left to vendor or hash-pin
- **Internationalization, Japanese and English** -- kept, and the only item on this list the private premise did not shrink, because both languages are wanted
- **Exhaustive resumption tests across every path** -- kept unchanged. This is the correctness of the transfers themselves
**What that leaves CI building, decided 2026-09-18 by DCR-132.** Three jobs run `cargo tauri build` -- `desktop`, `macos` and `windows` -- and what they are for is that the tree compiles, tests and links on their own host. **Bundling is not that, and on two of the three it packages a deliverable this list already dropped**: a DMG and an MSI are installers for strangers, and there are none. So `macos` and `windows` build with `--no-bundle`, and **`desktop` keeps its bundle, which is the ruling rather than an oversight** -- one Linux package is the one desktop artifact this milestone still owes, and that step is the only thing in CI that would notice it breaking.

**The signing branches go with the bundles.** `--no-bundle` produces nothing to sign, so each platform's `if:`-guarded pair collapses to one step and the workflow stops naming six Apple secrets and two Windows ones that the paragraph above settled will never be set. **And "release builds" in the workflow's own trigger comment no longer names a macOS or Windows artifact**, because after this there is none to name; a manual run builds what a push builds, and the Linux bundle is where a desktop release still comes from.

**What this does not decide is whether a macOS build is a deliverable at all.** The paragraph above answers for signing and not for the platform. The job stays because a compile-or-link failure on macOS is worth knowing about on the day it appears, and that is now the whole of what it claims.

- **A signing key that outlives a machine.** ~~Apple Developer Program and Authenticode~~ are for distributing to strangers, so **open decision 8 loses its purchase and its weeks of lead time, and R9 with it**: an unsigned build costs one Gatekeeper override per macOS install and one SmartScreen click per Windows install. **What does not go away is Android.** A debug keystore is per-machine and disposable, and an Android OAuth client is bound to one package name and one certificate, so regenerating it silently breaks sign-in. A project keystore kept somewhere durable, and a client registered against it, is free and is the residue of decision 8 that a private deployment still owes

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
| R11 | **The AppImage bundler downloads unpinned executables at build time** | The Linux release path is neither reproducible nor auditable, and a compromise upstream reaches users through a signed-looking bundle | Medium | Observed at M0: `cargo tauri build` fetched `AppRun`, `linuxdeploy` and its GTK and GStreamer plugins from `github.com/tauri-apps/binary-releases` and `raw.githubusercontent.com`, with no hash in the invocation. **`deb` and `rpm` need no such download.** Either drop AppImage, or vendor and hash-pin those five artifacts before M2. Folded into open decision 7, distribution channels |

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

6. **What `ChunkData.chunk_index` counts when a transport subdivides.** ~~Open~~ **Decided 2026-08-23**: `chunk_index` counts reference chunks, and a new `offset_in_chunk` field carries the position within one. See [docs/04](04-protocol.md#where-a-subdivided-piece-belongs) for why stream order was not used. The text below is kept as the record of the question.
   [docs/04](04-protocol.md#chunk-sizes) fixes 1 MiB as the reference boundary and has `relay` and `ble-gatt` subdivide it, into 256 KiB and 4 KiB. `ChunkData` carries `chunk_index`, `payload_len` and `last`, but **no offset within the reference chunk**, so a 1 MiB chunk arriving as four relay pieces has nothing on the wire distinguishing the second piece from the third.

   Stream order can carry it: the data plane is one unidirectional stream per Item, so the pieces arrive in order and the receiver tracks the offset itself, with `last` closing the reference chunk. That works, and it is unstated, which is the problem — it makes correct resumption depend on an assumption nobody wrote down.

   **Decide before the chunk-resumption Work Item**, which [CLAUDE.md](../CLAUDE.md) §6 names a Critical Module. Either state the stream-order rule in `docs/04` and test it, or add an explicit offset to `ChunkData`. The second costs eight bytes a chunk and removes the assumption entirely.

7. **When to move to post-quantum cryptography.**
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

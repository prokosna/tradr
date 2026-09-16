# 02. Architecture

## The three tiers

Tradr operates at three tiers. Each higher tier **adds to** the one below rather than replacing it.

```
Tier 0 — Standalone           Requires: nothing
  Discovery: mDNS on the LAN, BLE in proximity
  Auth:      mutual exchange of Google Attestations,
             verified against Google's public keys alone
  Transport: direct-quic / ble-gatt / wifi-direct
  > UC-1, 2, 3, 5 work completely

Tier 1 — Pinned               Requires: a reachable address for the peer
  Discovery: the above plus Static Peers the user registered
  Transport: the above, now reaching across Tailscale, WireGuard,
             ZeroTier, or a fixed IP via direct-quic
  > UC-6 works on an overlay network with no added infrastructure

Tier 2 — Brokered             Requires: a deployed and registered Brokr
  Discovery: the above plus the Brokr's presence registry
  Transport: the above plus holepunch-quic and relay
  > Discovery from anywhere; NAT traversal and relay available
```

Tier 1 exists as a separate tier because **anyone already running Tailscale has no use for a Brokr**. An overlay network has already solved reachability. The only thing left for Tradr to solve is learning the peer's address, and the user can supply that once by hand. Collapsing this tier into "deploy a Brokr to cross networks" would impose infrastructure on people whose infrastructure is already sufficient.

## Components

```
+---------------------------- Device A ----------------------------+
|  +------------------------------------------------------------+  |
|  |  UI layer  (TypeScript / React)                             |  |
|  |  Screens, drag and drop, progress, settings.                |  |
|  |  Touches neither the network nor the disk                   |  |
|  +---------------------------+--------------------------------+  |
|            Tauri commands and events, types generated from proto  |
|  +---------------------------+--------------------------------+  |
|  |  Core layer  (Rust)                                         |  |
|  |  +----------+-----------+----------+---------+-----------+  |  |
|  |  |discovery | transport | identity |   vfs   |   core    |  |  |
|  |  |mDNS/BLE/ |QUIC/BLE/  |Attestation|Share   |sessions/  |  |  |
|  |  |static/   |relay/     |/Noise/   |boundary |chunking/  |  |  |
|  |  |Brokr     |selection  |key store |posix|saf|resume     |  |  |
|  |  +----------+-----------+----------+---------+-----------+  |  |
|  +--------------+--------------------------+--------------------+  |
|      OS native (Kotlin / WinRT / CoreBluetooth / BlueZ)           |
+-----------------+--------------------------+---------------------+
                  |                          |
        BLE adv / GATT          QUIC over UDP (LAN / tailnet / punched)
                  |                          |
+-----------------+--------------------------+---------------------+
|                            Device B                              |
+------------------------------------------------------------------+
                             \            /
                              \          /   present only at Tier 2
                        +- - - -+- - - - +- - - - +
                          Brokr (optional)
                        | presence / rendezvous / |
                          relay. Verifies nothing
                        +- - - - - - - - - - - - -+
                                  \
                                   \  JWKS fetch, done by every device itself
                              +-----+------+
                              |   Google   |
                              | OIDC / JWKS|
                              +------------+
```

Note that a Brokr never talks to Google. Attestation verification always happens on a device, fetching Google's JWKS directly. This keeps the Brokr outside the circle of trust, so compromising it grants no ability to impersonate anyone — see [05](05-security.md#threat-model).

## Where the language boundaries fall, and why

TypeScript is the default. Rust and Kotlin take over at these boundaries.

### Rust owns the network, the disk, and the keys

BLE, mDNS, QUIC, file I/O, and cryptography live in Rust for three reasons.

1. **Library maturity.** Node's BLE libraries — the `noble` lineage — have been unstably maintained for years, and their handling of platform differences is incomplete. Rust offers `btleplug`, `bluer`, `quinn`, `snow`, and `blake3`, all of them in production use.
2. **Tauri's shape.** Tauri's native side is Rust to begin with, and its Android and iOS plugins call Kotlin and Swift from Rust. Writing this layer in TypeScript would mean carrying a Node sidecar process, which dissolves the single-codebase premise behind choosing Tauri.
3. **The nature of transfer.** Pushing gigabytes at tens of megabytes per second while hashing every chunk makes GC pauses and buffer copies show up directly in the numbers.

### Kotlin covers Android-specific OS integration only

Limited to Android APIs Rust cannot reach, and placed on the Kotlin side of the Tauri plugin.

- Receiving `ACTION_SEND` and `ACTION_SEND_MULTIPLE` from the share sheet
- Storage Access Framework — acquiring and persisting tree URIs
- The foreground service that keeps transfers running and shows progress
- `BluetoothLeAdvertiser`, since no Rust crate covers Android's peripheral role
- Wi-Fi Direct through `WifiP2pManager`
- OAuth through Chrome Custom Tabs, because Google rejects WebViews

### TypeScript covers the UI and the Brokr

- All UI, in React. It never touches the network or the filesystem, working only through Tauri commands and events.
- The entire Brokr, in Fastify. I/O is light there, and type sharing and iteration speed win outright. **Being an optional component, the choice here cannot affect how clients behave.**

**The test that decides:** anything called tens of thousands of times per second, reaching a low-level OS API, or touching a secret key goes to Rust. Anything reachable only through an Android OS API goes to Kotlin. Everything else is TypeScript.

## Monorepo layout

```
tradr/
+-- proto/                      # Protocol definitions, the single source of truth
|   \-- tradr/v1/*.proto         #   generated into Rust via prost and TS via ts-proto
|
+-- apps/
|   +-- tradr/                  # Tauri 2 app, desktop and Android from one project
|   |   +-- src/                #   UI entry point, React
|   |   \-- src-tauri/          #   Rust entry point, command definitions, capabilities
|   |       \-- gen/android/    #   Android project, Kotlin glue. Tauri generates it here
|   +-- tradr-cli/              # The command-line front end. Desktop only, may not name tauri,
|                               #   and builds a binary named tradr-cli rather than tradr
|   \-- brokr/                  # The optional backend, TypeScript and Fastify
|
+-- packages/                   # TypeScript workspace, pnpm
|   +-- ui/                     #   Screens and components, shared desktop and mobile
|   +-- protocol/               #   Types generated from proto, plus hand-written helpers
|   +-- brokr-client/           #   Typed client for the Brokr's REST and WebSocket API
|   \-- client-state/           #   State machines for transfer and discovery as the UI sees them
|
\-- crates/                     # Rust workspace, Cargo
    +-- tradr-core/             #   Transfer/Item/Chunk, resumption policy, the traits
    +-- tradr-proto/            #   The protobuf codec, and the only crate naming prost
    +-- tradr-identity/         #   Attestation issue and verify, Noise, key policy
    +-- tradr-transport/        #   Five Transport implementations and path selection
    +-- tradr-discovery/        #   mDNS, BLE advertise and scan, static pins, Brokr presence
    +-- tradr-vfs/              #   Share Root boundary enforcement, posix and saf backends
    +-- tradr-integrity/        #   Verified streaming against a content hash. The only crate naming bao
    +-- tradr-oidc/             #   JWKS fetch, OAuth loopback and token exchange. Speaks HTTP
    +-- tradr-secrets/          #   Where a Device Key is actually held. Speaks D-Bus and the keyring
    +-- tradr-app/              #   The shell-free half of the composition root. Names no Tauri type
    \-- tauri-plugin-tradr/     #   Exposes the above as Tauri commands; holds the Kotlin side
```

### Where the shell-free half lives

`crates/tradr-app/` holds everything the application does that does not depend on which shell is showing it. **Which modules that is today is `ls crates/tradr-app/src/`, and it is deliberately not written here.** The sentence that stood in this place enumerated five, and DCR-118's extraction added six more across three Work Items without any of them reaching this paragraph -- so it read as a definition while being an inventory, and it was stale within a day of being written. **What does not go stale is the rule**: a module belongs here when nothing it decides depends on a shell, and `ci/layer-deps.sh` check 3 is what holds the crate to that, not this paragraph. **`apps/tradr/` is the Tauri shell and `crates/tradr-app/` is the application it shows**, which is the whole of the distinction between the two names.

**It exists because a CLI was measured rather than argued about** ([docs/09](09-roadmap-and-risks.md)). Every function in `commands.rs` above the first `#[tauri::command]` names no Tauri type and ten of the plugin crate's modules mention Tauri not once, so the second front end is a move; **what the measurement did not check is whether a crate could hold them**. It could not: `ci/layer-deps.sh` lets an implementation crate depend only on `tradr-core` and `tradr-proto`, and this half reaches six internal crates. So DCR-118 makes the composition tier two crates rather than one, and check 4 exempts both.

**`tradr-app` is not exempt from the `tauri` confinement, and that is the point of the split rather than a detail of it.** Change Drill D9 asks how far a move off Tauri reaches; the answer used to be a grep somebody ran once, which [CLAUDE.md](../CLAUDE.md#c-flexibility-against-external-change--the-change-drill) already records as the wrong instrument, since a doc comment explaining why a file is D9-safe defeats it. **A manifest that may not name `tauri` cannot be defeated that way**: the day someone reaches for a `tauri::State` inside this crate, the build fails before the gate does.

**The split falls where `tradr-oidc`'s and `tradr-secrets`' did, and for the opposite reason.** Those two moved *out* of a crate because a dependency could not be reached through `tradr-core`; this one moves out because a dependency could not be reached at all -- `tauri` -- and confining what may reach it is what a second front end needs. The composition root keeps what a shell decides: the `#[tauri::command]` wrappers, the plugin lifecycle, the Kotlin side, and the state Tauri manages.

### Two front ends, one device

**A CLI beside the GUI is a second front end over one installation rather than a second installation, decided 2026-09-15 by DCR-124.** [CONTEXT.md](../CONTEXT.md) defines a Device as one installation holding one key pair and one Attestation, and Change Drill D9 asks what moving off Tauri costs: **a swap that changed the Device Key would not be a swap at all**, since the machine would arrive at every peer as a stranger and every Link would name a device that no longer answers, with nothing failing while it happened. So both front ends open one Device Key out of one application data directory.

**What that settles first is where the rung is chosen.** [docs/05](05-security.md#one-rung-per-device-and-what-else-goes-on-it) says the storage ladder is searched once and the rung it answers with is kept beside the `KeyStore` it opened; that search has exactly one call site today and it sits in a file naming `tauri::AppHandle`. A second front end building its own ladder would be a second search, and the two answer differently the first time a Secret Service session is present for one process and absent for the other -- **two Device Keys on one machine, and no build, test or handshake failing to say so**. The search, the open, and what `backing()` is then allowed to report move into `tradr-app`, and **the ladder is passed in rather than built inside**: a rung is a D-Bus session on this platform, so a caller that cannot supply its own rungs cannot be tested at all.

**The application data directory is the other half of one device, and it is resolved in one place.** Tauri answers `app_data_dir()` from the identifier in `tauri.conf.json`, which is `com.tradr.app` and resolves on this machine to `~/.local/share/com.tradr.app`. On Android that answer is the platform's and there is no second front end to disagree with it; on desktop both front ends read one function in `tradr-app` rather than two computations that happen to agree.

**What it costs is recorded here rather than discovered later**: two front ends may run at once, and then one device advertises itself twice. The QUIC bind already falls back to an ephemeral port when the default is taken ([docs/03](03-discovery-and-transport.md)), and mDNS then shows one `DeviceId` under two instance names. Nothing arrives while `tradr receive` is not running (DCR-123), so the overlap is something a person chooses rather than the resting state.

**What the second front end may name is one crate, and that is what decides where the receive composition lives, 2026-09-16 by DCR-126.** Check 4 became per-app so the CLI reaches implementation crates through `tradr-app`; **probed rather than read, `tradr-transport` and `tradr-discovery` added to `apps/tradr-cli/Cargo.toml` are refused by name**. The QUIC bind is in `tradr-transport`, the mDNS advertisement in `tradr-discovery`, the downloads root in `tradr-vfs`, and the traits `listen_for_transfers` is handed -- `KeyStore`, `Rng`, `Clock`, `ContentVerifier` -- in `tradr-core`, so a composition root assembling them itself would have to name four crates it may not. [docs/09](09-roadmap-and-risks.md#m8--usable-interface-unestimated) said phase 4 added a composition root and nothing to the crate, and **that is the same sentence DCR-124 already corrected once**: the gate decides where a thing can live, and reading a file list does not.

**So the composition lives in `tradr-app` and the front end supplies what the crate cannot resolve**: the directory to receive into, and a callback per arrival. That callback is `execute_send_files_with_progress`'s progress callback arriving on the receiving side -- a Tauri build emits an event through it where a command prints a line -- and it is why `init_lifecycle` delegates to the same bind and the same advertisement rather than keeping a second copy of either. **A second copy is the failure this is cut to avoid**: the ephemeral-port fallback and the interface filter are decisions about a network rather than about a shell, and two of them drift the first time one is changed.

**One device is not one sign-in, and the sentence saying it was is corrected here, 2026-09-16 by DCR-127.** A Device is one installation holding one key pair and one Attestation, and the key pair is the half that is stored; the Attestation is not. `SignInState` is held in memory for the life of a process, and `handle_incoming_channel` reads the `id_token` out of it fresh on every connection and refuses the channel without one -- so **`tradr receive` composed over the tree as it stood would bind, advertise, accept a channel and then refuse every transfer on it**, naming the one thing a command-line front end had no way to do.

**Sharing one would have to mean a token at rest, which is a larger question than this milestone asked.** An ID token expires in an hour, so a stored one is worth nothing by the time a second front end reads it, and a stored refresh token is a [docs/05](05-security.md#key-storage) design about what the `SecretStore` holds besides a Device Key -- nobody has written it, and the renewal measurement it would rest on has not been taken. **Each front end therefore signs in for itself, and `tradr receive` signs in as the first step of the session it holds**, which is what DCR-123 already decided the command is: a session a person opens, not a service a machine keeps. What it costs is a browser opening each time the command starts, and that is recorded here rather than discovered later.

**The flow moves with the decision.** The desktop half is a loopback listener, an authorization url, a browser launch and a code exchange, and it names no Tauri type but the `spawn_blocking` it hands the blocking `accept` to -- so it goes into `tradr-app` beside `finish_sign_in`, and the shell keeps the Android bridge and the command wrapper. Both front ends then drive one flow rather than two that agree today.

**The binary the CLI package builds is `tradr-cli`, and the name a person types is a packaging question rather than this one, decided 2026-09-16 by DCR-125.** The Tauri app's package is already named `tradr` and already builds a binary of that name, so a second `[[bin]]` called `tradr` shares one output path in the workspace target directory. **Cargo does not refuse that, which is why it is written down here**: it warns `output filename collision`, builds both, and leaves whichever linked last sitting there under the name `tradr` -- measured rather than assumed, and the 431 MB Tauri binary is what answered afterwards. A warning is not a gate, and a front end that is sometimes the other front end is the kind of defect no test names. So the target keeps its package's name, `cargo run -p tradr-cli -- device` is how it is driven from the workspace, and **the `tradr device` and `tradr receive` spellings this document and [docs/09](09-roadmap-and-risks.md) use are what an installed Tradr offers** -- one Linux package is M10's line, and installing this target under the name `tradr` is that package's job.

**`apps/tradr-cli/` is where the second front end goes, and `ci/layer-deps.sh` is what makes that more than a directory name.** Check 3 exempted every manifest under `apps/` from the `tauri` confinement, on the reading that an app is the Tauri app; a CLI under that blanket would be Tauri-free only because nobody had reached for a Tauri type yet, which is the grep [CLAUDE.md](../CLAUDE.md#c-flexibility-against-external-change--the-change-drill) already records as the wrong instrument. The exemption narrows to `apps/tradr/`, so the second front end is refused `tauri` by the same manifest scan that holds `tradr-app` to it. Check 4 becomes per-app for the same reason: the Tauri app reaches implementation crates through `tauri-plugin-tradr` and the CLI reaches them through `tradr-app`, and neither may reach one directly.

**Where the CLI's OAuth client comes from is the environment, decided 2026-09-17 by DCR-128, and it is the one thing phase 4 could not inherit.** The GUI's two values are baked into its artifact by `apps/tradr/src-tauri/build.rs` and read back with `option_env!`, because a launcher hands a GUI no environment to read. A command is invoked from a shell that has one, so `tradr-cli` reads `TRADR_OAUTH_CLIENT_IDS` and `TRADR_OAUTH_CLIENT_SECRET` at run time and carries no client id in its binary. See [docs/05](05-security.md#oauth-client-configuration) for why a second build script would have been worse than the duplication it resembles. **The type follows the decision**: `OAuthConfig` held `Option<&'static str>` because `option_env!` produces one, and a value read from the environment is owned, so both fields become `Option<String>` and the normalisation each front end was doing for itself -- an empty or whitespace-only value is no value -- becomes one constructor both call.

**What `tradr receive` accepts is what the handshake already trusted, decided 2026-09-17 by DCR-129, and that is open decision 9 answered for this front end.** `AttestationPolicy` is built with `ephemeral_receive: false`, so an account that is neither this device's own nor a linked one leaves `classify_with_profile` as `Err(UntrustedAccount)` and the channel is refused before any offer is read -- **measured in the code rather than assumed**, which is what makes the next sentence safe. Only `SameAccount` and `Linked` peers reach a `TransferOffer`, and the command passes no item filter, which is the answer the GUI has always given rather than a new one.

**A prompt on stdin is refused rather than postponed.** The listener loop owns the terminal, two transfers can arrive at once, and a question drawn across another transfer's output is a worse interface than no question. **The control a person has is the session itself** -- DCR-123 made this a command they start and end -- and that, not convenience, is what auto-accept rests on.

**The command opens no invite, so it serves no link exchange.** `handle_incoming_channel` refuses a stream that opens with a `LinkReply` when it holds no link service, saying that no invite is open on this device, and `tradr receive` passes none. Linking is a QR code and a Fingerprint compared on two screens; a terminal adds nothing to it.

**An arrival reaches the person through the loop rather than past it.** `listen_for_transfers` discards the paths each connection placed, and DCR-126 already recorded that a loop keeping them cannot be written outside `tradr-app`. So the loop gains the seam: it takes an arrival callback beside the item filter and the link service it already takes optionally, and calls it once per connection that placed at least one file. **An empty placement is not an arrival** -- a browse stream and a link exchange each return nothing placed, and a command printing a blank line for every directory a peer lists would be reporting the wrong event. The Tauri shell passes no callback today, and the event it would emit through one is an interface change rather than this one.

### Where the talk to an identity provider lives

`crates/tradr-oidc/` is the only crate that speaks HTTP and the only one naming an HTTP client. It holds the JWKS fetch, and from WI-M0-008 the OAuth loopback and token exchange as well.

**Where it lives was forced rather than chosen.** [DCR-022](../STATE.md) put the JWKS cache's policy inside `tradr-identity` and the fetching outside it, and `ci/layer-deps.sh` lets an implementation crate depend only on `tradr-core` and `tradr-proto` -- so an HTTP client reachable from `tradr-identity` would have to live *inside* `tradr-identity`, the crate holding Attestation verification. `tauri-plugin-tradr` was the other candidate and is worse: Change Drill D9 swaps that crate out the day Tauri goes, and fetching a JWKS has nothing to do with a shell.

### Where a Device Key is actually held

`crates/tradr-secrets/` implements `SecretStore` and nothing else: the Secret Service over D-Bus, the kernel keyring, and a `0600` file, the three rungs [docs/05](05-security.md#key-storage) lists for Linux. It is the only crate naming a D-Bus client, checked the way `prost`, `tauri` and `reqwest` are.

**The reason it is not in `tradr-identity` is the reason `tradr-oidc` is not either**, one paragraph above. A Secret Service client brings an executor and roughly ninety-six transitive crates, and `ci/layer-deps.sh` permits an implementation crate only `tradr-core` and `tradr-proto`, so a client reachable from `tradr-identity` would have to live *inside* the crate that verifies Attestations. The split falls where the earlier one did: **`tradr-identity` keeps the policy and `tradr-secrets` keeps the I/O.** `select_rung` and `SoftwareKeyStore` are pure and stay where they are; the composition root builds the ladder and hands it in, exactly as it hands in a fetched JWKS.

**Only Linux has a ladder at all.** On Android, macOS and Windows the key is generated inside a secure element and never exists as bytes to store, so there is nothing for a `SecretStore` to hold. This crate is the answer to the one platform with no such element, which is why a cross-platform credential-store dependency would buy nothing the other three could use.

**No Layer 1 trait wraps it.** Nothing in Layer 1 fetches anything: DCR-022 leaves the single `await` in the composition root, so a `JwksSource` trait would be a dispatch point with one implementation and no caller that needs to swap it. What such a trait would buy -- confinement, so that changing the client touches one place -- the crate boundary already buys, and buys checkably: `grep -rl reqwest crates/` must return `crates/tradr-oidc/` and nothing else. `tradr-oidc` therefore exposes plain `async fn`s, and [ADR-0013](adr/0013-layer-1-async-traits-return-boxed-futures.md)'s `BoxFuture` does not reach it.

**`reqwest`, with `rustls-tls` and no default features.** rustls is already in the driver layer for QUIC, so sharing that stack costs nothing new, while `native-tls` would pull OpenSSL into the Linux and Android builds to perform one GET. A blocking client wrapped in `spawn_blocking` was the alternative and buys nothing here, since every caller is already async.

### Where content verification lives

`crates/tradr-integrity/` implements the `ContentVerifier` trait `tradr-core` declares, and nothing else: [ADR-0006](adr/0006-blake3-for-content-integrity.md)'s `bao` verified streaming, checking a piece against an `Item`'s `content_hash` at the absolute offset [docs/04](04-protocol.md#where-a-subdivided-piece-belongs) computes. It is the only crate that may name `bao`, checked the way `prost`, `tauri`, `reqwest` and the D-Bus client are.

**The crate tree said `tradr-core` held integrity, and that was never reachable.** Verifying a piece needs BLAKE3 and the `bao` tree format; [invariant I4](../CLAUDE.md#8-invariants-that-must-not-break) lets `tradr-core` declare no dependency at all, and ADR-0006's fourth reason forbids the other way out -- **not assembling cryptographic primitives by hand is an important discipline**, and a hand-rolled Merkle path is exactly that. So the annotation described a home the rules had already closed.

**The split falls where it fell twice before.** `tradr-core` keeps the policy: `ItemResumption` records that a piece verified, and the trait says what verifying means. `tradr-integrity` keeps the primitive. This is the `tradr-oidc` and `tradr-secrets` argument a third time, and it arrives the same way -- a dependency an implementation crate may not reach through `tradr-core` has to become a crate of its own.

**A trait wraps it, where `tradr-oidc`'s does not.** The reason is that there is a second implementation and the composition root must not choose between them by editing itself: a receiver verifies incrementally as pieces arrive, and a whole-file check after an interrupted transfer resumes is the same question asked over a file already on disk. What that buys over a plain function is a test double, which is how `tradr-core`'s resumption tests state what a failed verification does without hashing anything.

### Direction of dependency

**Two directions are easy to confuse here, so both are drawn.** Calls travel one way; crate dependencies travel the other, which is what dependency inversion means and what CI enforces.

Call flow, what invokes what at run time:

```
apps/tradr(UI) -> packages/ui -> packages/client-state -> packages/protocol
                                              |
                                       Tauri bridge
                                              v
       tauri-plugin-tradr -> tradr-core -> the Transport / Vfs / KeyStore traits
                                                          |
                          the implementations satisfying them at run time
```

Crate dependencies, what appears in each `Cargo.toml`:

```
                          tradr-core          <- depends on nothing internal
                               ^                  declares the traits
       +-----------+-----------+-----------+-----------+
       |           |           |           |           |
  tradr-transport  |     tradr-identity    |      tradr-proto
              tradr-vfs             tradr-discovery      ^
                                                         |
       tradr-transport, tradr-identity and tradr-discovery
       also depend on tradr-proto for the wire encoding

       tradr-app          -> all six         <- the composition tier. tradr-app
       tauri-plugin-tradr -> all six + tradr-app   holds what no shell decides
                                                and may not name tauri at all;
                                                tauri-plugin-tradr holds the
                                                commands, the lifecycle and the
                                                Kotlin side
```

### Where the protobuf codec lives

`tradr-proto` is Layer 2. It converts between the domain types `tradr-core` owns and the wire messages in `proto/tradr/v1/`, and **it is the only crate that may name `prost` or any other protobuf library**. That is what makes Change Drill D5 — replacing protobuf with another format — an Adapter-layer change rather than a sweep.

The check is mechanical, the same shape as D9's: `grep -rl prost crates/` must return `crates/tradr-proto/` and nothing else.

`tradr-core` does not depend on it. Domain types have no encoding, which is rule B2 holding: the core must not know that protobuf exists.

**Every arrow points at `tradr-core`, and none leaves it.** An implementation crate depends on the core to implement its traits; the core never names an implementation. `tradr-transport` does not depend on `tradr-identity` either — what it needs from keys arrives through `KeyStore`, which is what keeps Change Drill D3 confined to `transport/quic/`.

The wiring happens in the composition tier, and only there. `tauri-plugin-tradr` is the only crate that knows a shell exists, which is why swapping the app shell (D9) reaches no further than it; `tradr-app` is the only other crate that may reach more than `tradr-core` and `tradr-proto`, and it may not name `tauri`.

**Every Layer 1 trait is declared in `tradr-core` and nowhere else.** `Transport`, `SecureChannel`, `Vfs`, `KeyStore`, `Clock` and `Rng` all live there, along with the stream traits `SecureChannel` hands out; `tradr-transport` and `tradr-vfs` hold implementations of them and declare none of their own. Reading a trait's name in an implementation crate's directory listing is not a statement about where it is declared, and putting a declaration beside its implementations would collapse rule B3 quietly, since everything would still compile.

`tradr-core` never calls I/O directly; it declares the `Transport` and `Vfs` traits and depends on nothing else. That makes the core logic — offer and accept, chunking, deciding where to resume, verification — testable with neither a real network nor a real filesystem. This is the most breakable and most test-hungry part of the design, so it is kept pure on purpose.

`tradr-discovery` **does not know a Brokr exists**. It holds four implementations of a `DiscoverySource` trait, one of which happens to be `BrokrSource`. Unconfigured, that implementation simply is not registered. Likewise `tradr-transport` sees `relay` as one of five `Transport` implementations. Keeping the tier distinction confined to which implementations are registered stops it from leaking upward.

## Process model

### Desktop

One resident process. Closing the window leaves it in the tray, still listening and still transferring.

- **Main thread**: the Tauri event loop and the WebView
- **Tokio runtime**: discovery, listening, transfer — independent of whether a window exists
- Arrivals while the window is closed raise an OS notification whose actions accept or decline

### Android

- **App process**: the UI. Liable to be stopped once backgrounded
- **Foreground service** of type `dataSync`: started only during a transfer, holding a progress notification
- **Listening**: continuous listening costs too much battery, so instead
  - Tier 0 and 1: BLE scans and mDNS queries on screen-on and at an interval. Peers nearby get found
  - Tier 2: a Brokr sends an FCM data message to wake the device, which then connects only when needed

That FCM only helps at Tier 2 is an honest difference in experience. An Android device with no Brokr finds peers when you pick it up, and cannot receive fully in the background.

## Where state lives

| State | Location | Rationale |
|---|---|---|
| Device private keys | OS key store | Never on disk in the clear — see [05](05-security.md#key-storage) |
| Google refresh token | OS key store | Used to renew the Attestation |
| Current Attestation | SQLite | Public information, shown to peers |
| Local settings, Share definitions, Static Peers | SQLite in app data | Purely local |
| Known peers and pinned keys | SQLite | How Tier 0 remembers a peer. Trust genuinely lives here |
| In-flight transfer state | SQLite plus partial files | Survives a process restart |
| ABK and Link Secrets | OS key store | Secrets used to recognize peers over BLE |
| File contents | Never duplicated | Written straight to the destination, with no intermediate copy |

**Share definitions deliberately never reach a Brokr.** Which directories someone exposes is itself sensitive, and a Brokr has no need to know. Peers learn about them over the protocol at connection time.

## Where trust actually lives

Working at Tier 0 means **trust lives in each device's local database**.

1. When devices A and B first meet, each verifies the other's Attestation. A matching provider signature, a matching `(iss, sub)` pair, and a `nonce` corresponding to the peer's public keys together establish that this is a device of the same account.
2. Each then pins the other's Device Key locally.
3. Later connections check against the pinned key. The Attestation is re-verified periodically to catch revocation, but everyday connections need no call to Google.

**There is therefore no central roster.** No global truth exists about which devices belong to an account; each device merely holds the set it has met and verified. That simplifies the design and produces two consequences.

- A device never met does not appear, even on the same account. The first meeting must happen on a shared LAN or in proximity. Deploying a Brokr removes this.
- Revoking a device — after a loss — is a local operation. Revoking the app's access in Google settings stops that device renewing its Attestation, and every peer rejects it once the grace period passes, 30 days by default. That is the only global revocation mechanism, and it is slow. A manual per-device revocation UI covers urgent cases.

These consequences are the price of Tier 0, not a defect in it. They are presented as the thing deploying a Brokr buys you.

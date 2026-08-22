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
|   \-- brokr/                  # The optional backend, TypeScript and Fastify
|
+-- packages/                   # TypeScript workspace, pnpm
|   +-- ui/                     #   Screens and components, shared desktop and mobile
|   +-- protocol/               #   Types generated from proto, plus hand-written helpers
|   +-- brokr-client/           #   Typed client for the Brokr's REST and WebSocket API
|   \-- client-state/           #   State machines for transfer and discovery as the UI sees them
|
\-- crates/                     # Rust workspace, Cargo
    +-- tradr-core/             #   Transfer/Item/Chunk, resumption, integrity
    +-- tradr-proto/            #   The protobuf codec, and the only crate naming prost
    +-- tradr-identity/         #   Attestation issue and verify, Noise, key storage
    +-- tradr-transport/        #   Five Transport implementations and path selection
    +-- tradr-discovery/        #   mDNS, BLE advertise and scan, static pins, Brokr presence
    +-- tradr-vfs/              #   Share Root boundary enforcement, posix and saf backends
    \-- tauri-plugin-tradr/     #   Exposes the above as Tauri commands; holds the Kotlin side
```

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

       tauri-plugin-tradr -> all six         <- the composition root, and the
                                                only place implementations are
                                                bound to the traits
```

### Where the protobuf codec lives

`tradr-proto` is Layer 2. It converts between the domain types `tradr-core` owns and the wire messages in `proto/tradr/v1/`, and **it is the only crate that may name `prost` or any other protobuf library**. That is what makes Change Drill D5 — replacing protobuf with another format — an Adapter-layer change rather than a sweep.

The check is mechanical, the same shape as D9's: `grep -rl prost crates/` must return `crates/tradr-proto/` and nothing else.

`tradr-core` does not depend on it. Domain types have no encoding, which is rule B2 holding: the core must not know that protobuf exists.

**Every arrow points at `tradr-core`, and none leaves it.** An implementation crate depends on the core to implement its traits; the core never names an implementation. `tradr-transport` does not depend on `tradr-identity` either — what it needs from keys arrives through `KeyStore`, which is what keeps Change Drill D3 confined to `transport/quic/`.

The wiring happens once, in `tauri-plugin-tradr`. That crate is the only one that knows which implementations exist, which is why swapping the app shell (D9) reaches no further than it.

**Every Layer 1 trait is declared in `tradr-core` and nowhere else.** `Transport`, `Vfs`, `KeyStore`, `Clock` and `Rng` all live there; `tradr-transport` and `tradr-vfs` hold implementations of them and declare none of their own. Reading a trait's name in an implementation crate's directory listing is not a statement about where it is declared, and putting a declaration beside its implementations would collapse rule B3 quietly, since everything would still compile.

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

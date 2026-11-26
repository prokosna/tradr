# 02. Architecture

## Tiers

Each tier adds to the one below; none replaces it.

| Tier | Requires | Discovery | Transport |
|---|---|---|---|
| 0 Standalone | nothing | mDNS (LAN), BLE (proximity) | direct-quic, ble-gatt |
| 1 Pinned | a reachable peer address | + Static Peers | direct-quic over Tailscale / WireGuard / fixed IP |
| 2 Brokered | a self-hosted Brokr | + Brokr | + Deferred Delivery ([13](13-deferred-delivery.md)) |

Tier 1 exists because someone already on Tailscale needs no Brokr: reachability is solved, only the address is missing, and the user types it once.

A Brokr never talks to Google and never verifies anything. Every device fetches Google's JWKS itself, so compromising a Brokr impersonates nobody ([05](05-security.md)).

## Languages

| Language | Owns | Why |
|---|---|---|
| Rust | network, disk, keys, crypto | mature crates (quinn, btleplug, bluer, snow, blake3); Tauri's native side is Rust; GB/s hashing |
| Kotlin | Android-only OS APIs: share sheet, SAF, foreground service, `BluetoothLeAdvertiser`, Custom Tabs OAuth | unreachable from Rust |
| TypeScript | all UI (React), the Brokr (Fastify) | UI never touches network or disk |

Rule: hot paths, low-level OS APIs and secret keys → Rust. Android-only APIs → Kotlin. Everything else → TypeScript.

## Layout

```
proto/tradr/v1/          wire schema (source of truth; prost for Rust, ts-proto for TS)
apps/tradr/              Tauri 2 app (desktop + Android); src-tauri/gen/android holds Kotlin
apps/tradr-cli/          CLI front end; binary `tradr-cli`; may not name tauri
apps/brokr/              optional backend, TypeScript + Fastify
packages/                pnpm workspace: ui, protocol, client-state, ...
crates/
  tradr-core             Layer 0/1: domain types, protocol state machines, all traits. No I/O
  tradr-proto            protobuf codec. Only crate naming prost
  tradr-identity         Attestation verify, Noise, key policy, links, HPKE
  tradr-transport        Transport implementations (QUIC, BLE GATT)
  tradr-discovery        mDNS, BLE advertise/scan, Static Peers
  tradr-vfs              the only place file paths are assembled (posix, SAF)
  tradr-integrity        bao verified streaming. Only crate naming bao
  tradr-oidc             JWKS fetch, OAuth loopback + token exchange. Only crate naming an HTTP client
  tradr-secrets          Linux key storage rungs (Secret Service, keyring, 0600 file). Only crate naming D-Bus
  tradr-app              shell-free composition: send, receive, browse, sign-in, peers. May not name tauri
  tauri-plugin-tradr     Tauri commands, lifecycle, Kotlin bridge. The only crate naming tauri
```

## Dependency rules (enforced by `ci/layer-deps.sh`)

- `tradr-core` depends on nothing internal and declares every trait: `Transport`, `SecureChannel`, `Vfs`, `KeyStore`, `Clock`, `Rng`, `ContentVerifier`, `DiscoverySource`.
- Implementation crates may depend only on `tradr-core` and `tradr-proto`. A third-party dependency they cannot otherwise reach becomes its own crate (that is why `tradr-oidc`, `tradr-secrets` and `tradr-integrity` exist).
- `tradr-app` and `tauri-plugin-tradr` are the composition tier. Only `tauri-plugin-tradr` and `apps/tradr` may name `tauri`.
- `apps/tradr` reaches implementation crates only through `tauri-plugin-tradr`; `apps/tradr-cli` only through `tradr-app`.
- Each volatile library has one owner crate: prost→proto, bao→integrity, reqwest→oidc, D-Bus→secrets, tauri→plugin.
- `tradr-discovery` does not know a Brokr exists. Optional tiers come in as extra registered implementations, never as conditionals.

## Two front ends, one device

The GUI and `tradr-cli` are two front ends over one installation. They share the application data directory (`com.tradr.app`, resolved in one function in `tradr-app`), so they share the Device Key and the kept Attestation. If a second front end opened its own key it would turn up at every peer as a stranger.

- The key-storage ladder is searched once, in `tradr-app`, and is passed in so it can be tested.
- The sign-in flow lives in `tradr-app`: loopback listener on fixed port 21821, falling back to an ephemeral port. If no browser opens, it prints the URL on its own line, prints an `ssh -L 21821:localhost:21821` hint, and accepts the pasted redirect URL on stdin; whichever arrives first wins.
- The kept Attestation (`attestation` file, 0600) is re-verified at start and reused while `iat` ≤ 21 days old ([05](05-security.md)).
- The CLI reads OAuth client config from `TRADR_OAUTH_CLIENT_IDS` / `TRADR_OAUTH_CLIENT_SECRET`. The GUI bakes them in at build time.
- If both front ends run at once, one device advertises twice. That is accepted.

### CLI commands

- `tradr-cli device`: prints this device.
- `tradr-cli receive`: a foreground session, not a daemon. It signs in, binds QUIC (21820, else ephemeral) and advertises. It auto-accepts from `SameAccount` and `Linked` peers only and never prompts on stdin. It serves no link exchange. Failures print as `transfer from <id> failed during <phase>: <err>`.
- `tradr-cli peers`: browses for a 5 s window and prints the peers it finds.
- `tradr-cli send <peer> <file>...`: the peer is a key (exact match) or a name (exact match; ambiguous names are refused). It resolves files first, then discovery, then sign-in. It binds an ephemeral port only. Progress is printed as lines, not a bar.

The Device Authorization Grant is not used: nobody has checked that Google carries `nonce` through it.

## Process model

- **Desktop**: one resident process. Closing the window leaves it in the tray, still listening.
- **Android**: once the app has been opened, a `connectedDevice` foreground service keeps the listener alive and holds a multicast lock. Its notification has a Stop action. It is not started at boot ([ADR-0022](adr/0022-android-stays-resident-to-receive.md)).

## Where state lives

| State | Location |
|---|---|
| Device private keys, ABK, Link Secrets | OS key store (Linux: [05](05-security.md) ladder) |
| Kept Attestation | `attestation` in app data, 0600 |
| Static Peers | `static-peers.json` |
| Link records | `links.json` (secret in key store) |
| ABK record | `account-broadcast-key.json` (key in key store) |
| Known Devices | records each met peer's keys, for Deferred Delivery only. Refuses nothing |
| Received history | app data (`received_history`) |
| In-flight transfers | the partial files themselves; resume reads their size |

There is no SQLite. Share definitions are not stored ([ADR-0024](adr/0024-one-folder-per-device-full-access.md): one folder per device).

## Trust

Trust lives on each device. Every connection runs [05](05-security.md)'s verification in full, against a JWKS cached in memory. There is no key pinning. A Device ID is a hash of the identity key, so a key cannot change under a known ID, and a reinstalled device is a new device.

What follows from this:
- There is no central roster. A device you have never met does not appear.
- Revocation is slow: revoke the app in Google settings, and peers reject the device once its Attestation passes 30 days.

# 03. Discovery and transport

BLE was removed ([ADR-0028](adr/0028-ble-removed.md)). Discovery is mDNS and Static Peers; the only built transport is `direct-quic`.

## Discovery

`DiscoverySource` implementations run concurrently and report **events**, not lists:

| Event | Meaning |
|---|---|
| `Observed(PeerObservation)` | replaces any earlier observation with the same `ObservationId` |
| `Lost(ObservationId)` | this source no longer sees it; says nothing about other sources |

`PeerObservation` = `id` (`SourceId` + source-local key), optional `device_id`, `candidates`, `display_name`, `capabilities`. Observations are keyed by what the source calls them, not by Device ID, because a Static Peer has no Device ID until its first connection. Trust-on-first-use is just a re-report of the same `ObservationId` with `device_id` filled in.

### Peer list (`tradr-core`, pure)

- Observations sharing a Device ID form one peer. An observation without a Device ID is a peer of its own.
- A peer's candidates are the union of its observations' candidates, deduplicated and sorted by transport, then address.
- Names and capabilities are not merged. The caller picks one (`PeerInfo` in the UI DTO also carries `sources`).
- An event whose `ObservationId` names a source other than the one that delivered it is refused, so a Brokr cannot impersonate mDNS.
- **Self is filtered** where sources are drained (`drain_peer_sources`): an observation carrying this device's own Device ID never enters the list.

### 1. mDNS (Tier 0)

- `_tradr._udp.local`, instance name = 8 random hex chars. Library: `mdns-sd`. Android needs a `MulticastLock`.
- TXT: `v` protocol major, `id` Device ID (base64url, no padding, 22 chars), `pk` Agreement Key Tag (first 8 bytes of `BLAKE3(agreement_pub)`, 11 chars), `n` display name (≤ 32 bytes UTF-8), `p` platform (`linux|win|mac|android`), `c` capability bitmask.
- An unknown `v` is **not** dropped; versions are negotiated in `Hello`. A malformed record is skipped and the source keeps running.
- The Device ID is visible on the LAN. That is accepted.
- **Display name**: the first label of the hostname, truncated to 32 bytes on a char boundary. Android uses `Settings.Global.DEVICE_NAME`, falling back to `Build.MODEL`. `localhost` is never used. It is decided once at plugin start. If invalid, `n` is omitted and the advertisement still goes out.
- **Vanished peers**: mDNS forgets a silent device only after the 120 s TTL. A failed send dial, or the UI's **Refresh**, calls `ServiceDaemon::verify` (RFC 6762 §10.4, 10 s timeout) on mDNS observations. It is fire-and-forget, with no periodic timer. The choice of which observations to recheck lives in `tradr-app`; the daemon call lives in `tradr-discovery`.

### 2. Static Peers (Tier 1)

```jsonc
{ "id": "<32 hex>", "label": "Home desktop",
  "endpoints": ["desktop.tail9f3c.ts.net:21820", "192.168.10.5"],
  "expect_device_id": "3f9a..." }   // pinned on first connection
```

- Stored in `static-peers.json`, rewritten whole. A missing file means an empty registry. **A malformed file is an error and is never replaced with an empty one**, because that would drop every pin.
- Keyed by a random `id`, not by label or endpoints. A missing port defaults to `:21820`.
- **Pin (Critical Module)**: an entry with `expect_device_id` dials with `PeerExpectation::Device`; otherwise `Unpinned`. The first successful connection writes the pin, and only into an empty slot. There is no re-pin: the user deletes and re-adds the entry.
- The source never probes. It reports every entry at start and on each change.
- Default port **UDP 21820**: not 51820, which is WireGuard's, and below the ephemeral range. The bind falls back to an ephemeral port; mDNS advertises the actual port.
- The listener binds `[::]` with `IPV6_V6ONLY=false`, set explicitly through `socket2`.

### 3. Brokr presence (Tier 2)

**Not built.** M9 delivered only Deferred Delivery ([13](13-deferred-delivery.md)).

## Transports

| ID | Status | Notes |
|---|---|---|
| `direct-quic` | built | `quinn`, TLS 1.3, 10 s keep-alive, 30 s idle timeout |
| `wifi-direct` | not built | Android↔Android only, if ever |
| `holepunch-quic`, `relay` | not built | would need a Brokr rendezvous (and an encrypted channel for relay) |

### `direct-quic`

- A candidate is parsed as a `SocketAddr` first, and otherwise resolved through `tokio::net::lookup_host` on every dial (no cache). Only one address is dialled; the race belongs to path selection.
- Link-local IPv6 candidates must carry the **numeric** scope (`[fe80::1%2]:p`). `mdns-sd`'s `Display` prints interface names on non-Windows platforms, so sources format the address themselves.
- Every resolution failure is `Unreachable`.

## Path selection

Design (ICE / Happy Eyeballs style):
1. **Gather** candidates from every source.
2. **Race** for up to 3 s (relay starts at 1.5 s).
3. **Adopt** the highest `class_weight - rtt_ms/10`. Weights: direct-quic 1000, wifi-direct 800, holepunch 700, relay 300. An unknown transport weighs 0.
4. **Re-evaluate** mid-transfer: resume on a new path from the last verified chunk.

**Built today**: phase 1 and a single dial of the highest-weight candidate this device can dial (ties keep list order), with a **3 s deadline** in `connect_and_pin`. Candidates for transports this device does not hold are skipped. Error messages distinguish *no candidates* from *none dialable here*. A failed dial triggers the mDNS recheck.

### Transport contract (Layer 1)

- `Transport::connect(candidate, PeerExpectation)` returns a `SecureChannel`, which is already mutually authenticated, ordered and multiplexed. Each transport owns its encryption.
- `PeerExpectation` (`#[non_exhaustive]`):
  - `Unpinned`: authenticate whatever key is presented, and report its DeviceId.
  - `Device(id)`: refuse unless the key derives `id`.
  - `Identity(pub)`: the same, plus the agreement key must match.
  - mDNS → `Device`. A Static Peer → whatever its pin says. Any other unidentified source is refused.
- `TransportId` and candidate addresses are opaque to the core. `Candidate::new`, `DisplayName::new` and `ObservationKey::new` refuse empty strings, control characters, and bidi reordering characters (U+202A-E, U+2066-9, U+2028-9; one shared predicate with `RelPath`).
- `SecureChannel` reports `max_frame_size` and `rtt`. A transport with no continuous RTT reports its handshake RTT.
- `TransportError` (a closed set of 6):
  - Any QUIC CRYPTO_ERROR is `AuthenticationFailed`.
  - `Unreachable` = could not attempt, a local verdict.
  - `Rejected` = the peer refused during the handshake (retryable).
  - `Closed` = an established connection ended.
- **`Incoming::accept` never returns one peer's failure.** It logs the failure with the remote address and waits for the next connection. It returns an error only when the listener itself is closed or broken.
- D10: adding a transport = one implementation + one registration + one weight + one reserved capability bit. No `tradr-core` trait changes.

## Capability flags

A bitmask in the mDNS TXT `c` field and `Hello`.

| Bit | Meaning |
|---|---|
| 0 | direct-quic |
| 1 | wifi-direct |
| 2 | retired (was ble-gatt); never reassigned |
| 3 | relay |
| 4 | accepts browsing |
| 5 | writable folder |
| 6 | metered link |
| 7-15 | reserved, for new transports |

The declared set is one runtime value in the composition root (`LocalCapabilities`), read at each declaration.

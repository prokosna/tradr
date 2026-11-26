# 03. Discovery and transport

## Premise: Bluetooth cannot carry bulk

| Method | Throughput | 1 GB |
|---|---|---|
| BLE GATT, 247-byte MTU, 2M PHY | ~100 KB/s | ~2.8 h |
| Wi-Fi Direct | ~20 MB/s | ~50 s |
| LAN | 50-110 MB/s | 10-20 s |

BLE is for discovery, authentication and payloads of **≤ 512 KiB** ([ADR-0002](adr/0002-ble-for-discovery-and-small-payloads.md)). Anything bigger never uses BLE.

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
- The list is shared between the drain call (mDNS, Static) and the BLE task. Nothing may hold it across non-merge work.

### 1. mDNS (Tier 0)

- `_tradr._udp.local`, instance name = 8 random hex chars. Library: `mdns-sd`. Android needs a `MulticastLock`.
- TXT: `v` protocol major, `id` Device ID (base64url, no padding, 22 chars), `pk` Agreement Key Tag (first 8 bytes of `BLAKE3(agreement_pub)`, 11 chars), `n` display name (≤ 32 bytes UTF-8), `p` platform (`linux|win|mac|android`), `c` capability bitmask.
- An unknown `v` is **not** dropped; versions are negotiated in `Hello`. A malformed record is skipped and the source keeps running.
- The Device ID is visible on the LAN. That is accepted.
- **Display name**: the first label of the hostname, truncated to 32 bytes on a char boundary. Android uses `Settings.Global.DEVICE_NAME`, falling back to `Build.MODEL`. `localhost` is never used. It is decided once at plugin start. If invalid, `n` is omitted and the advertisement still goes out.
- **Vanished peers**: mDNS forgets a silent device only after the 120 s TTL. A failed send dial, or the UI's **Refresh**, calls `ServiceDaemon::verify` (RFC 6762 §10.4, 10 s timeout) on mDNS observations. It is fire-and-forget, with no periodic timer. The choice of which observations to recheck lives in `tradr-app`; the daemon call lives in `tradr-discovery`.

### 2. BLE (Tier 0)

Advertisement ([ADR-0019](adr/0019-a-128-bit-service-uuid-for-the-ble-advertisement.md)), 31 bytes on air:

```
Flags (platform-written)                           3
Service Data, 128-bit UUID (AD 0x21)              28
  len 1 | type 1 | UUID 00000001-6eed-40d6-85d3-3794eaa7b21c (LE) 16
  data 10: version 0x01 (1) | EID (8) | flags (1: platform<<4 | caps bits 0-3)
```

Platform codes: 0 unknown, 1 linux, 2 win, 3 mac, 4 android. Nothing else goes on air (no name, no TX power). A scanner ignores unknown versions.

**EID** ([ADR-0018](adr/0018-blake3-derive-key-for-eids.md)):
```
window = unix_time.div_euclid(900)
EID    = BLAKE3::derive_key("tradr-eid-v1", secret(32) || window as i64 BE)[0..8]
```
`secret` ∈ {ABK, each Link Secret, `derive_key("tradr-bootstrap-v1", account_id)`}. Scanners try windows t-1, t and t+1. The bootstrap secret is weak, because `account_id` is not secret: it allows presence detection but not connection.

- **Matching set** (scanner): ABK, Link Secrets and bootstrap, **always including bootstrap** so the device can meet new same-account devices. It is read per advertisement, so link changes apply at once.
- **Advertised set**: ABK (or bootstrap if there is no ABK) plus Link Secrets. One secret per **4 s slot**, in rotation. `start` is called only when the payload changes, and `start` replaces the current payload. An empty set stops the radio. More than 6 secrets would break the 30 s age-out; that case is reported, not fixed.
- An unreadable secret is left out of the set, and the cause is logged once when it changes.

**Scanner contract** (all platforms):
- Report one event per advertisement received, with duplicate suppression off, and only the 10 Tradr service-data bytes plus a platform **handle**.
- The handle (BT address or platform UUID) is the observation key and the `ble-gatt` candidate. It rotates (RPA). The duplicate entry ages out, and that is accepted: merging by EID would conflate devices that share an ABK.
- An EID matching no held secret produces no observation. BLE observations carry no Device ID and no name.
- `Lost` = 30 s without a report for that handle (monotonic clock). It is evaluated on report arrival, so a fully silent radio leaves stale entries.
- BLE runs in its own task, because `next_report` is not cancel-safe. Every error ends the task.
- `BleError::Unsupported` means only "the platform cannot do this role" and is the D4 scan-only retreat. Busy, permission and adapter-off errors have their own variants. **Tradr never powers on an adapter**: powered-off reads as `AdapterUnavailable`.

| OS | Advertise | Scan |
|---|---|---|
| Linux | `bluer` (this dev machine's controller refuses advertising) | `bluer`. Service-UUID filters cannot see Service Data, so filtering happens in software |
| Windows | `windows` crate | `btleplug` |
| macOS | **none**: CoreBluetooth drops Service Data ([ADR-0021](adr/0021-macos-is-scan-only-on-ble.md)) | `btleplug` |
| Android | Kotlin `BluetoothLeAdvertiser` (legacy API) | Kotlin `BluetoothLeScanner` with a Service Data filter (needed while the screen is off) |

- `BleAdvertiser` and `BleScanner` are declared in `tradr-discovery` (not core), so D4 can drop the peripheral role without a core change.
- Android split: Kotlin calls the radio and returns raw codes and bytes. **All mapping is in Rust**, outside `cfg(android)`, so host tests cover it. The Kotlin→Rust queues are bounded: the scan queue drops the oldest entry, and the GATT inbound queue (8192 bytes) latches a refusal when full. A `selftest` flag on `startBleScan` pushes a synthetic `SELFTEST` report through the real Kotlin builder to check the JSON seam.

### 3. Static Peers (Tier 1)

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

### 4. Brokr presence (Tier 2)

**Not built.** M9 delivered only Deferred Delivery ([13](13-deferred-delivery.md)).

## Transports

| ID | Status | Notes |
|---|---|---|
| `direct-quic` | built | `quinn`, TLS 1.3, 10 s keep-alive, 30 s idle timeout |
| `ble-gatt` | built (Linux central, Android peripheral) | Noise_XX, ≤ 512 KiB |
| `wifi-direct` | not built | Android↔Android only, if ever |
| `holepunch-quic`, `relay` | not built | would need a Brokr rendezvous |

### `direct-quic`

- A candidate is parsed as a `SocketAddr` first, and otherwise resolved through `tokio::net::lookup_host` on every dial (no cache). Only one address is dialled; the race belongs to path selection.
- Link-local IPv6 candidates must carry the **numeric** scope (`[fe80::1%2]:p`). `mdns-sd`'s `Display` prints interface names on non-Windows platforms, so sources format the address themselves.
- Every resolution failure is `Unreachable`.

### `ble-gatt`

```
service 00000002-6eed-40d6-85d3-3794eaa7b21c   (not advertised; discovered after connect)
  00000003-...  central→peripheral, write-without-response
  00000004-...  peripheral→central, notify (+ CCCD 0x2902)
```

- Each direction is a byte stream of `[u16 BE len][record]`, chopped to the current MTU by whichever side owns the radio. The ATT boundary means nothing.
- The reassembler refuses len 0, len > 528, mid-record EOF, and a delivery > 530. **Every refusal latches.** Memory is bounded at about 1059 bytes per link.
- The Link Layer supplies loss recovery and ordering. A rejected send is a link error, never retried.
- A link starts at the CCCD subscription (the central acquires notify before write) and ends on disconnect.
- Peripheral `accept`: handshakes run concurrently, one per link. A failed link is discarded; it does not end the listener.
- Dial is bounded at 10 s, and the link is torn down on any failure. Responder RTT is measured from message 1 to message 3.
- A platform may hold only one half. A missing half answers `Io(Unsupported)`. Capability bit 2 is set from the **peripheral** half only.

## Path selection

Design (ICE / Happy Eyeballs style):
1. **Gather** candidates from every source.
2. **Prefilter**: drop `ble-gatt` if the byte count is > 512 KiB **or unknown** (downloads). Browse and link exchange keep it.
3. **Race** for up to 3 s (relay starts at 1.5 s).
4. **Adopt** the highest `class_weight - rtt_ms/10`. Weights: direct-quic 1000, wifi-direct 800, holepunch 700, relay 300, ble 50. An unknown transport weighs 0.
5. **Re-evaluate** mid-transfer: resume on a new path from the last verified chunk.

**Built today**: phases 1, 2, and a single dial of the highest-weight candidate this device can dial (ties keep list order), with a **3 s deadline** in `connect_and_pin`. Candidates for transports this device does not hold are skipped. Error messages distinguish *no candidates* / *none dialable here* / *dropped by size*. A failed dial triggers the mDNS recheck.

### Transport contract (Layer 1)

- `Transport::connect(candidate, PeerExpectation)` returns a `SecureChannel`, which is already mutually authenticated, ordered and multiplexed. Each transport owns its encryption.
- `PeerExpectation` (`#[non_exhaustive]`):
  - `Unpinned`: authenticate whatever key is presented, and report its DeviceId.
  - `Device(id)`: refuse unless the key derives `id`.
  - `Identity(pub)`: the same, plus the agreement key must match.
  - mDNS → `Device`. A Static Peer → whatever its pin says. BLE → `Unpinned` (there is nothing to pin). Any other unidentified source is refused.
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

A bitmask in the BLE advertisement (bits 0-3), the mDNS TXT `c` field, and `Hello`.

| Bit | Meaning |
|---|---|
| 0 | direct-quic |
| 1 | wifi-direct |
| 2 | ble-gatt payloads (peripheral listening) |
| 3 | relay |
| 4 | accepts browsing |
| 5 | writable folder |
| 6 | metered link |
| 7-15 | reserved, for new transports |

The declared set is one runtime value in the composition root and is read at each declaration. Bit 2 is set when the GATT server has started and withdrawn when it stops.

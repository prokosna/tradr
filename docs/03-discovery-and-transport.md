# 03. Discovery and transport

## Starting premise: Bluetooth cannot carry bulk

This has to be stated first, because the rest of the design follows from it.

| Method | Effective throughput | Time for 1 GB |
|---|---|---|
| BLE GATT, 20-byte MTU | ~5 KB/s | about 55 hours |
| BLE GATT, 247-byte MTU on 2M PHY | ~100 KB/s | about 2.8 hours |
| Bluetooth Classic, RFCOMM | ~1.5 MB/s | about 11 minutes |
| Wi-Fi Direct, 802.11n | ~20 MB/s | about 50 seconds |
| Wired or Wi-Fi 6 LAN | 50-110 MB/s | 10-20 seconds |

Neither Quick Share nor AirDrop puts payload on BLE. **BLE carries discovery and key exchange only**, after which both switch to Wi-Fi Direct or AWDL. Tradr takes the same shape.

The decision, recorded in [ADR-0002](adr/0002-ble-for-discovery-and-small-payloads.md):

- **BLE serves three purposes: discovery, mutual authentication, and small payloads**
- BLE alone may carry **512 KiB at most** — text, URLs, contacts, small images
- Anything larger drops BLE from the candidate list. With no other path available the transfer queues as waiting for a network and starts by itself once Wi-Fi returns

512 KiB comes from roughly 5 seconds at the 100 KB/s that a 247-byte MTU on 2M PHY achieves in practice. The implementation adjusts the ceiling from measured throughput.

## Discovery

Four `DiscoverySource` implementations run concurrently, merging into one peer list. A Device ID arriving from several sources collapses into a single peer holding several candidates.

### 1. mDNS / DNS-SD — the same LAN, Tier 0

- Service type `_tradr._udp.local`, since QUIC rides UDP
- Instance name: eight random hex characters. The Device ID never appears in the name
- TXT record:

  | Key | Value |
  |---|---|
  | `v` | Protocol major version |
  | `id` | Device ID, 16 bytes, base64url |
  | `pk` | Agreement public key fingerprint, first 8 bytes |
  | `n` | Display name, UTF-8, 32 bytes maximum |
  | `p` | Platform: `linux`, `win`, `mac`, `android` |
  | `c` | Capability flags, a bitmask |

- Implemented with `mdns-sd`. On Android, multicast arrives only while a `WifiManager.MulticastLock` is held, acquired on the Kotlin side

Putting the Device ID in the TXT record exposes device identity to anyone on the LAN. That is accepted: a LAN is already a somewhat trusted space, and concealing identity there would badly hurt how quickly discovery works. **Proximity, where anonymity does matter, is handled differently** — see EIDs below.

### 2. BLE — proximity, no network required, Tier 0

Advertise on an interval while scanning at the same time. Both roles run.

**Advertisement payload**, fitted into the 31-byte limit:

```
Service UUID, 16-bit, one allocated value    2 bytes
Service Data:
  +- version                                 1 byte
  +- EID (ephemeral identifier)              8 bytes
  +- platform and capability flags           1 byte
  \- reserved                                2 bytes
```

**Deriving an EID**:

```
EID = HKDF-Expand(secret, "tradr-eid-v1" || floor(unix_time / 900), 8)
```

`secret` is one of the following. A device computes an EID from every secret it holds and **advertises them in rotation**. A scanner computes candidate EIDs from every secret it holds and matches against what it received.

| secret | Purpose |
|---|---|
| ABK (Account Broadcast Key) | Devices of the same account |
| Link Secret | Devices of a linked account |
| `HKDF(account_id, "tradr-bootstrap-v1")` | First discovery, before any ABK exists |

Rotation period is 15 minutes. To absorb clock skew, scanners try the `t-1`, `t`, and `t+1` windows.

Holding N secrets costs 3N HKDF comparisons per advertisement. N stays in the low tens in practice and HKDF takes microseconds, so this does not matter.

**Why no permanent identifier goes on the air**: anyone can receive BLE advertisements. Broadcasting a fixed value would let shop receivers and passing phones track a device's movements. An EID looks like a random string that changes every 15 minutes to anyone without the matching secret.

**On the weakness of the bootstrap secret**: `account_id` is `iss || 0x00 || sub` and is not a secret, merely an opaque provider identifier with the issuer prepended. Anyone who obtains one can detect when that person's device is nearby. This is accepted — a `sub` does not normally leave the app, and **detection grants no ability to connect**, which still requires mutual Attestation. Once two same-account devices meet they exchange an ABK and stop advertising the bootstrap EID.

**Per-platform implementation**: no Rust crate covers the BLE peripheral role across platforms, so this part is written four times. It is the least predictable work in the design — see [09](09-roadmap-and-risks.md).

| OS | Advertising (peripheral) | Scanning (central) |
|---|---|---|
| Linux | `bluer`, BlueZ over D-Bus | `bluer` |
| Windows | `windows` crate, `BluetoothLEAdvertisementPublisher` | `btleplug` |
| macOS | `objc2`, `CBPeripheralManager` | `btleplug` |
| Android | Kotlin, `BluetoothLeAdvertiser` | Kotlin, `BluetoothLeScanner` |

`tradr-discovery` declares `BleAdvertiser` and `BleScanner` traits with those four implementations behind them.

### 3. Static Peer — overlay networks and fixed IPs, Tier 1

A reachable address the user registered by hand.

```jsonc
{
  "label": "Home desktop",
  "endpoints": ["desktop.tail9f3c.ts.net:51820", "192.168.10.5:51820"],
  "expect_device_id": "3f9a..."   // filled in on the first connection
}
```

- Several endpoints are allowed, tried in order — in practice, in parallel
- **This is what Tailscale, WireGuard, and ZeroTier use.** On those networks the peer is simply reachable, so Tradr needs no reachability trickery. It only needs the address, which the user supplies once
- MagicDNS names such as `*.ts.net` work directly; resolution is left to the system resolver
- Recording `expect_device_id` detects DNS hijacking and address reassignment. The first connection pins it, and later mismatches refuse the connection with a warning

**A convenience**: where Tailscale is installed, read `tailscale status --json` and offer tailnet devices as candidates. This only saves typing addresses and creates no dependency — with no such command present, it silently does nothing.

### 4. Brokr presence registry — from anywhere, Tier 2

Active only when a Brokr is registered.

- Devices hold a WebSocket open to the Brokr: always on desktop, only while running on Android
- The Brokr tracks each device's Device ID, last-seen time, and observed reflexive address
- Peer presence and address candidates can be queried
- Offline peers can be woken through FCM or APNs

Details in [07](07-brokr.md).

## Transports

| ID | What it is | Tier | Typical throughput | Where it applies |
|---|---|---|---|---|
| `direct-quic` | QUIC over UDP straight to the peer's address | 0 / 1 | 50-110 MB/s on LAN; network-bound on a tailnet | The default. Peers found via mDNS or a Static Peer |
| `wifi-direct` | A Wi-Fi P2P group carrying QUIC | 0 | 15-25 MB/s | Android to Android with no shared LAN |
| `holepunch-quic` | QUIC through a NAT hole opened via Brokr rendezvous | 2 | Network-bound | Direct connection across networks |
| `relay` | A Brokr forwarding ciphertext | 2 | Bound by the Brokr's uplink | When hole punching fails |
| `ble-gatt` | A BLE GATT write characteristic | 0 | 20-100 KB/s | 512 KiB or less with no Wi-Fi |

### Why QUIC

Chosen over TCP with TLS — see [ADR-0004](adr/0004-quic-as-the-bulk-transport.md):

1. **Multiplexed streams.** Control messages and several file bodies ride independent streams of one connection. On TCP, control queues behind payload — head-of-line blocking.
2. **Connection migration.** Switching from Wi-Fi to cellular, or changing IP, does not end the connection. That matters for the real behaviour of carrying a laptop mid-transfer.
3. **Fits hole punching.** Being UDP, the socket used to punch the hole is the socket used to transfer.
4. **0-RTT resumption.** A previously contacted peer connects one round trip sooner, which shows up in the feel of frequent short transfers.

Implemented with `quinn`.

### Why Wi-Fi Direct is Android-only

Desktop Wi-Fi Direct APIs do not line up — Linux goes through `wpa_supplicant` P2P, Windows through WinRT, and macOS exposes nothing public — and most implementations tear down the existing Wi-Fi connection. What it breaks outweighs what it delivers. Restricted to Android pairs; anything involving a desktop relies on a shared LAN or a Brokr.

## Path selection

The mechanism behind picking the right path automatically. **It does not pick — it races and keeps the winner.** The same idea as ICE and Happy Eyeballs.

```
+- Phase 1: gather candidates (~200 ms) --------------------+
|  Collect every way discovery says the peer is reachable   |
|    mDNS      -> 192.168.1.42:51820        (direct-quic)   |
|    Static    -> desktop.tailnet.ts.net    (direct-quic)   |
|    Brokr     -> 203.0.113.7:44821         (holepunch-quic)|
|    Brokr     -> relay://brokr.example/x   (relay)         |
|    BLE       -> handle:0x0042             (ble-gatt)      |
+-------------------+---------------------------------------+
                    v
+- Phase 2: prefilter --------------------------------------+
|  total bytes > 512 KiB          -> drop ble-gatt          |
|  metered link, not user-approved -> drop relay            |
|  no candidates left              -> queue as              |
|                                     "waiting for network" |
+-------------------+---------------------------------------+
                    v
+- Phase 3: race (3 seconds maximum) -----------------------+
|  t=0 ms     handshake every direct-quic candidate at once |
|  t=0 ms     begin hole punching                           |
|  t=1500 ms  start relay if nothing has established yet    |
|             (a head start for direct paths, so relay      |
|              bandwidth is not spent needlessly)           |
|  t=3000 ms  time out                                      |
+-------------------+---------------------------------------+
                    v
+- Phase 4: adopt ------------------------------------------+
|  Among those established, take the highest score:         |
|    score = class_weight(transport) - rtt_ms / 10          |
|    class_weight: direct-quic 1000 / wifi-direct 800       |
|                  holepunch-quic 700 / relay 300 / ble 50  |
|  Abandon the remaining handshakes immediately             |
+-------------------+---------------------------------------+
                    v
+- Phase 5: re-evaluate mid-transfer -----------------------+
|  Path drops        -> back to Phase 1, resume from the    |
|                       last acknowledged chunk             |
|  Running on relay  -> switch at the next chunk boundary   |
|  and direct opens     to the direct path                  |
+-----------------------------------------------------------+
```

### A transport delivers an already-secure channel

`Transport::connect` returns a `SecureChannel`, never a raw byte stream. [docs/05](05-security.md#two-encryption-layers) gives two families for the five transports — QUIC paths use QUIC's own TLS 1.3, while `relay` and `ble-gatt` use Noise_IK — and says the layer above is never told which.

**That promise is only keepable if each implementation owns its own encryption.** `direct-quic` gets it from the protocol; the `relay` and `ble-gatt` implementations wrap their raw stream in Noise before returning. Putting the Noise handshake in Layer 1 instead would mean the core branching on which transport it is holding, which is the coupling the trait exists to prevent, and it would put a second encryption layer on the QUIC paths or a conditional that skips it.

A `SecureChannel` therefore offers the same thing on every path: mutually authenticated, forward secret, ordered, bidirectional, and multiplexed into the streams [docs/04](04-protocol.md#the-three-planes) describes. Where the underlying transport has no native multiplexing, the implementation provides it in-band, which is what the `stream_id` frame variant in docs/04 is for. **Layer 1 asks for a stream and gets one**; whether that cost a QUIC stream or a frame header is not its concern.

### What the core knows about a transport

**No trait that changes when a transport is added.** Change Drill D10 budgets one implementation, one registration, one weight-table entry and one capability bit for a new transport, and forbids any change to a trait in `tradr-core`. **The bit is in the budget rather than outside it**: the flags below enumerate transports deliberately, and naming a reserved value rewrites nothing. Two things follow, and both are constraints on the `Transport` trait rather than observations about it.

- **A transport's identity is an opaque token, not a closed set.** The core carries a `TransportId` it can compare, order and display, and cannot enumerate. An `enum { DirectQuic, WifiDirect, ... }` in the core would make every new transport a core change, which is the one outcome the drill forbids
- **A candidate address is opaque too.** `192.168.1.42:51820`, `relay://brokr.example/x` and `handle:0x0042` share no structure, and the core has no reason to parse any of them. It collects candidates from discovery and hands each to the transport that produced it
- **Opaque is not unchecked.** A candidate can arrive from a Brokr, which [docs/05](05-security.md#threat-model) does not trust, and it reaches logs and the UI on its way to a transport. So the core rejects an empty address and one carrying control characters: the same two rules, and the same reasoning, as the `item_id` token in [docs/04](04-protocol.md#partial-files). It checks nothing else, because everything else is syntax only a transport knows. **The transport that receives a candidate validates it before use**, and that is a contract on each implementation rather than something the core can do for them
- **The class weights above belong to path selection, not to the transports.** A weight is a comparison between transports, so it is a policy of the component doing the comparing. `tradr-transport` holds the table; a transport does not report its own rank
- **A frame-size limit is the opposite case, and the channel reports it.** [docs/04](04-protocol.md#framing) negotiates `max_frame_size` in `Hello` — 1 MiB by default, 512 bytes over BLE — and that negotiation happens in Layer 1. Either the core carries a per-transport table of limits, which is the table this whole section exists to keep out of it, or the established channel says what it can carry. It says. Unlike a weight, a limit is a property of one path rather than a comparison between several

### What a transport is told about the peer it is dialling

`Transport::connect` takes a second argument beside the candidate: a `PeerExpectation`, which is what the dialling side already knows about the device it is reaching for. Three variants, and they are the three states of identity knowledge this design has rather than a guess at what a transport might want.

| Variant | Where it comes from | What the transport must do with it |
|---|---|---|
| `Unpinned` | A Static Peer's **first** connection, whose `expect_device_id` is empty until that connection fills it | Authenticate the peer to whatever key it presents, and report the `DeviceId` that key derives. Refuse a peer that presents no key at all |
| `Device(DeviceId)` | mDNS, a Brokr, and every Static Peer connection after the first | Refuse unless the key the peer proves possession of derives exactly that `DeviceId` |
| `Identity(PublicIdentity)` | A peer already known in full, both public keys | As `Device`, and additionally the agreement key `Noise_IK` needs before its first message |

**`Unpinned` is not "unauthenticated", and the distinction is the whole reason the variant can exist.** The peer still proves possession of the key its certificate names, so the channel is mutually authenticated and `SecureChannel::peer` still cannot fail; what is absent is only a *prior* expectation to compare that key against. Trust-on-first-use pinning is then the caller's, above the transport, which is exactly where docs/03's Static Peer already puts it — "the first connection pins it". The account-level question is answered later still, by the Attestation exchange in `Hello` ([docs/04](04-protocol.md#the-three-planes)), which does not consult this argument at all.

**It is an argument to `connect` and not a field on `Candidate`, and three separate facts forced that.**

- **A Static Peer's first connection has no `DeviceId` to put there.** A field would have to be optional on a type where every other reader treats it as known
- **`Candidate` derives `PartialEq`, `Eq` and `Hash`, and collapsing one `DeviceId` arriving from several sources into one peer is what those derives are for.** A per-attempt field on it would silently make one address two candidates
- **mDNS carries an 8-byte fingerprint of the agreement key, and `Noise_IK` needs the whole key.** So a candidate could not carry the expectation `ble-gatt` needs even if the first two objections were answered

**The type is `#[non_exhaustive]` and that keeps it inside Change Drill D10.** A fourth state of identity knowledge would be a variant nobody was matching exhaustively on, which rewrites no existing line -- the same reasoning as the reserved capability bit below. **What D10 forbids is changing the trait**, and this argument is added once, before the first transport exists, rather than by a transport paying for itself.

**A transport needing something that is not identity knowledge takes it at construction, not per connect.** A pairing code, a relay token, a Brokr's address: those are configuration of one transport instance, and putting them here would turn a closed domain vocabulary into a bag every transport adds to.

### What a transport can know about a refusal, and what it must not invent

A `Transport` reports `TransportError`, a closed set of six. Mapping a real transport's failures onto it turned out to decide two things the design had not settled, and both were established by running a QUIC handshake rather than by reading a crate's documentation.

**A QUIC peer cannot tell a pin mismatch from a forged signature, and must not pretend it can.** Both arrive as one opaque CRYPTO_ERROR code -- RFC 9000's `0x0100` to `0x01ff` range, carrying a TLS alert number in its low byte -- and the dialling side sees it as a transport error while the listening side sees the same code inside a connection-close frame. **So every code in that range is `AuthenticationFailed`, whichever side reports it.** That is wider than "the peer's key did not match the expected Device ID", and the type says so: the finer distinction is not on the wire, and a transport that invented one would be handing a caller a fact it does not have. What the variant guarantees is the part that matters to a caller — **the peer failed to authenticate, and retrying will not change that**, which is precisely what separates it from `Rejected`.

**`Unreachable` is a local verdict, not the absence of a reply.** Dialling an address where nothing listens does not produce an error: QUIC retries its Initial packets and the future simply stays pending. So `Unreachable` means the dial could not be attempted — an address this transport cannot parse, an endpoint that is shutting down, no common QUIC version — and it is decided before a packet leaves. **The deadline on waiting belongs to Phase 3 above, which already owns a three-second race**, and a transport that invented a second one would compete with it. A dial into nothing does resolve eventually, at the QUIC idle timeout -- `quinn`'s own default of 30 seconds, which this design accepts rather than chooses. **Choosing a value belongs with Phase 5 and not here**: the same timeout governs an established connection, so a number picked to make a failed dial fail sooner is a number that also decides when a paused transfer is abandoned.

**This is also why `Rejected` and `Closed` are separate.** A peer that closes during the handshake with a non-crypto code refused the connection; a peer that closes an established one is `Closed`. A caller retries the first and does not retry the second, and neither is a security event.

### Phase 5 is the point

**Refusing to make path selection a one-time decision is the most important thing in this design.**

Because transfers resume at chunk granularity (see [04](04-protocol.md)), any choice of path is always revocable. That property buys:

- A short Phase 3 timeout, since guessing wrong is correctable
- Safe optimization such as starting on relay and moving to direct
- Transfers that survive carrying a laptop into another room and onto another access point
- No special handling for the "waiting for network" queue — it is simply the state of having zero candidates, inside the same state machine

Read the other way: **if chunk-level resumption breaks, the entire path-selection design stops working.** It gets tested first and hardest.

### Worked example: sending to a home PC over Tailscale

1. A Static Peer already holds `desktop.tail9f3c.ts.net:51820`
2. Phase 1: mDNS returns nothing, being another network. The Static Peer yields one candidate. No Brokr is configured, so there are no others
3. Phase 3: QUIC handshake over the tailnet establishes at 25 ms RTT
4. Phase 4: one candidate, so it is adopted. Transfer runs at full speed as `direct-quic`
5. No Brokr appears anywhere in the sequence

WireGuard and ZeroTier behave identically. The overlay network solved reachability, so Tradr does nothing.

## Android listening and wake-up

| Tier | Mechanism | Experience |
|---|---|---|
| 0 / 1 | BLE scan and mDNS query on screen-on and at an interval, 15 minutes by default. Foreground service only during a transfer | Peers appear when you pick up the device. Fully backgrounded arrival is not possible |
| 2 | The above plus wake-up from a Brokr's FCM data message, sent at `high` priority, connecting within 10 seconds | Arrivals land with the screen off |

Continuous BLE scanning and a permanently held connection are avoided because of Doze and battery drain. The UI presents this gap as the reason to consider Tier 2.

## Capability flags

Carried in advertisements and in `Hello`, so each side knows what the other can do. A bitmask.

| Bit | Meaning |
|---|---|
| 0 | Supports `direct-quic` |
| 1 | Supports `wifi-direct` |
| 2 | Supports `ble-gatt` payloads |
| 3 | Supports `relay`, meaning a Brokr is registered |
| 4 | Accepts Share browsing |
| 5 | Has a writable Share |
| 6 | Currently on a metered link |
| 7-15 | Reserved |

**Bits 7 to 15 are where a new transport's bit comes from, and that is why they are reserved.** Enumerating transports on the wire is deliberate: a peer declares membership of a closed set rather than naming a transport in a string, so a peer cannot claim a transport that does not exist and a receiver never parses an open-ended value. The cost is that adding a transport touches `proto/`, and [Change Drill D10](../CLAUDE.md#c-flexibility-against-external-change--the-change-drill) counts that in its budget instead of pretending it does not happen.

# 04. Wire protocol

`proto/tradr/v1/` is the single source of truth, generated into Rust with `prost` and TypeScript with `ts-proto`. No hand-written type definitions sit at the boundary.

## Layering

```
+-------------------------------------------------------+
|  Application: the Control, Browse, and Data planes     |
+-------------------------------------------------------+
|  Framing: [u32 len][u8 type][payload]                  |
+-------------------------------------------------------+
|  Secure channel:                                       |
|    direct-quic / holepunch-quic -> QUIC's TLS 1.3      |
|    ble-gatt / relay / wifi-direct -> Noise_IK          |
+-------------------------------------------------------+
|  Transport: QUIC stream / GATT characteristic / WS     |
+-------------------------------------------------------+
```

[05](05-security.md#why-there-are-two-encryption-layers) explains why there are two secure-channel families. From above, both present the same thing: a mutually authenticated, forward-secret, ordered, bidirectional byte stream.

## Framing

```
+--------+--------+---------+
| len:u32| type:u8| payload |
+--------+--------+---------+
   BE      msg     protobuf
```

- `len` covers `type` and `payload` together, big-endian, and does not include its own four bytes. It is bounded by the `max_frame_size` negotiated in `Hello` — 1 MiB by default, 512 bytes over BLE. The smallest legal frame is `len == 1`: a type byte with an empty payload
- `type` selects the message; `payload` is its protobuf encoding
- On QUIC the control and data planes take separate streams. BLE and relay offer a single stream, so multiplexing is done in-band with a frame variant carrying a `stream_id`

### Which `max_frame_size` bounds which direction

`max_frame_size` is what a side is willing to **receive**, never what it promises to send. Each side puts its own value in `HelloAck`, so the two are independent and routinely differ — a phone reachable over `ble-gatt` and a laptop over `direct-quic` is the ordinary case, not the exception.

| Direction | Bound |
|---|---|
| Encoding a frame to send | the peer's advertised `max_frame_size` |
| Decoding a frame received | this side's own, the value it advertised |

A side advertises what its own `SecureChannel` reports and enforces exactly that on receive. **Before `HelloAck` arrives both bounds are the channel's own value**, which is what makes `Hello` itself framable: the handshake cannot negotiate the limit that carries the handshake.

### A bad length ends the connection

An announced `len` above the receive bound, or a `len` of zero, is **fatal to the stream and never skipped**. A length-prefixed stream has no second way to find a boundary: the bytes after a bad length are of unknown extent, so there is nothing to resynchronize on and every later frame would be read at a shifted offset. The reader reports the failure and the channel closes.

That is a different thing from the forward compatibility below, and the two sit one layer apart. **Ignoring an unknown message type happens after a well-formed frame has been decoded** — its extent is known, so skipping it costs nothing. A malformed length is not a frame at all.

### The length is never trusted for an allocation

A peer announcing `len = 0xffffffff` must cost the receiver nothing. The bound is therefore checked **the moment the four header bytes are in hand**, before a single byte is reserved, and a reader never sizes a buffer from a value the peer sent. Its memory is the bytes it has actually received and no more.

This is the whole of the framing layer's security surface, and it is where an untrusted stream's first four bytes are read.

### The framing layer does not know what a type byte means

It carries the `u8` verbatim in both directions and holds no registry. Which code names which message is the planes' business, settled where the frame is already in hand — which is also where "unknown message types are ignored" is applied. Framing is byte-level, so [Change Drill D5](../CLAUDE.md#c-flexibility-against-external-change--the-change-drill) does not reach it: replacing protobuf changes what a payload contains, not how it is delimited.

## The three planes

| Plane | Role | Streams |
|---|---|---|
| **Control** | Handshake, capability negotiation, offer and accept, progress and completion | Bidirectional stream 0, always exactly one |
| **Browse** | Listing, stat, and reading or writing Share Roots | A bidirectional stream per request |
| **Data** | Chunk payloads | A unidirectional stream per Item, four concurrent by default |

## The type byte

Every code is listed here and nowhere else, and the ranges are by plane.

| Range | Plane | Assigned |
|---|---|---|
| `0x00` | — | **Never valid.** A zero byte is what padding, a truncated write and an uninitialised buffer all produce, so it is the one code that must never mean a message |
| `0x01`-`0x1f` | Control | `0x01` `Hello`, `0x02` `HelloAck`, `0x03` `TransferOffer`, `0x04` `TransferAccept`, `0x05` `TransferReject`, `0x06` `TransferComplete`, `0x07` `TransferAbort`, `0x08` `PathChanged`, `0x09` `KeepAlive`, `0x0a` `ItemComplete`, `0x0b` `TransferProgress` |
| `0x20`-`0x3f` | Data | `0x20` `ChunkRequest`, `0x21` `ChunkRerequest`, `0x22` `ChunkData`, `0x23` `FlowControl` |
| `0x40`-`0x5f` | Browse | `0x40` `ListDir`, `0x41` `DirListing`, `0x42` `Stat`, `0x43` `StatResult`, `0x44` `ReadFile`, `0x45` `ReadFileBegin`, `0x46` `WriteFile`, `0x47` `Mkdir`, `0x48` `Delete`, `0x49` `Rename`, `0x4a` `Ack`, `0x4b` `Watch`, `0x4c` `FsEvent` |
| `0x60`-`0x7f` | — | Reserved for the in-band multiplexing variant the `stream_id` bullet above describes, which `ble-gatt` and `relay` need and the QUIC paths never send |
| `0x80`-`0xff` | — | Unassigned |

`brokr.proto`'s messages carry no code. They travel on the Brokr's WebSocket, which is not a framed Tradr stream.

### A code is assigned once and never reused

Retiring a message retires its code with it, the way a removed protobuf field becomes `reserved`. A reused code is a peer of an older version decoding new bytes as the message it used to know, and protobuf's own tolerance makes that succeed quietly rather than fail.

### A code names a plane, and the wrong plane is refused rather than ignored

`0x40` `ListDir` arriving on the Control stream is not an unknown message; it is a known one on a stream that does not carry it. **The plane is where authorization lives** — a Browse request is checked against the requester's Trust Tier and the Share's audience before it acts — so accepting one wherever it arrives is how a request reaches the code that serves it without passing the code that guards it. The frame is refused and the stream closes.

**A plane owns its whole range, not merely the codes assigned inside it.** `0x0c` is unassigned and sits in Control's range; on the Browse stream it is refused, not skipped. Reading ownership from the assignments instead would make the answer for a given code change as later versions fill the gaps in, so a device would have to know what a future version assigned in order to decide what to refuse today.

### What "unknown message types are ignored" actually covers

Only an **unassigned** code, and only within the receiving plane's own range. That is the forward compatibility the versioning section promises: a newer peer sending `0x0c` on the Control stream is skipped by an older one, whose extent is known because the frame decoded cleanly.

Three things are outside it and none is skippable: `0x00`, a code belonging to another plane, and a malformed length. The first two are refusals; the third, per the Framing section, is not a frame at all.

## Session flow

```
Sender                                          Receiver
  |                                                  |
  |---- Hello (version, device_id, attestation) ---->|
  |<--- Hello (version, device_id, attestation) -----|
  |                                                  |
  |      Each verifies the other's Attestation       |
  |      and settles a Trust Tier (see 05)           |
  |                                                  |
  |---- HelloAck (capabilities, max_frame_size) ---->|
  |<--- HelloAck ------------------------------------|
  |                                                  |
  |---- TransferOffer (transfer_id, items[]) ------->|
  |                                                  |  +- same account and
  |                                                  |  |  auto-accept on
  |                                                  |  |    -> accept at once
  |                                                  |  +- otherwise
  |                                                  |  |    -> ask the user
  |                                                  |  \- inspect existing partial
  |                                                  |     files to decide resume
  |<--- TransferAccept (accepted[], resume_offsets) -|
  |                                                  |
  |      A data stream opens per item from here      |
  |                                                  |
  |<--- ChunkRequest (item, from, count) ------------|  <- the receiver asks
  |---- ChunkData x N ------------------------------>|
  |<--- ChunkRequest --------------------------------|
  |---- ChunkData x N ------------------------------>|
  |                        :                         |
  |<--- ItemComplete (item_id, verified: true) ------|
  |                        :                         |
  |<--- TransferComplete (transfer_id) --------------|
```

### Why the receiver pulls

Rather than the sender pushing unilaterally, the receiver asks for chunks with `ChunkRequest`.

1. **Flow control follows the receiver's circumstances.** A slow disk, a low battery, competing transfers — the receiver can express all of it directly.
2. **Resumption needs no special case.** Restarting after an interruption means asking from a later chunk index. There is no separate resume protocol.
3. **Deduplication becomes possible.** Before asking, the receiver can check a chunk's hash and skip anything it already holds — from a partially received copy, or from the same content under a different name.
4. **Out-of-order requests work.** Only the corrupted chunk needs re-requesting.

The cost is one extra round trip, but `ChunkRequest` batches with `count` — 64 chunks, meaning 64 MiB, by default — so the round-trip frequency is effectively negligible.

## The Hello exchange

Both sides send `Hello` at once — neither is the client — so each runs the same four steps against the other. **No step performs I/O.** Verifying the peer's Attestation may need a JWKS fetch, so the exchange hands that out and consumes the result, the way [docs/05](05-security.md#who-runs-the-seven-steps)'s `JwksNeeded` already does.

| Step | Given | Produces |
|---|---|---|
| 1 | our own facts, and an `Rng` | our `Hello`, carrying a fresh 16-byte nonce |
| 2 | the peer's `Hello`, the `DeviceId` the channel authenticated, a `Clock` | a refusal, or a request to verify the peer's Attestation |
| 3 | the resulting Trust Tier | our `HelloAck`, signed over the peer's nonce |
| 4 | the peer's `HelloAck` | the settled session: their tier, the negotiated version, our send bound |

### What each side checks, and in what order

Cheapest first, so no signature work is spent on a peer that cannot be talked to at all.

1. **Version overlap.** `negotiated = min(ours.max, theirs.max)`, refused when that is below `max(ours.min, theirs.min)`. An integer comparison, so it goes first.
2. **The key join.** `BLAKE3(theirs.identity_pub)[0..16]` must equal the `DeviceId` the channel already authenticated. One hash, before any signature.
3. **The `KeyBinding`.** A P-256 signature over `tradr-keybind-v1 || agreement_pub` against `identity_pub`, with `not_after` still in the future.
4. **The Attestation**, handed out and never performed here. The Trust Tier that comes back is **ours**.
5. **The peer's nonce signature**, in step 4: P-256 over `tradr-hello-v1 || our nonce` against their `identity_pub`. Over **our** nonce and never theirs — reflecting a peer's own nonce back proves nothing and would let a relay pass carrying no key at all.

### Why the key join earns its place

A channel authenticates a *Device Key*; a `Hello` claims an *account*. Without check 2 the exchange holds two different answers to "who is the peer" — the certificate's and the `Hello`'s — and every later decision has to remember which one it meant.

Check 5 does eventually catch a mismatch, since a relay cannot produce a signature under a key it does not hold. **But it catches it in step 4, after a `HelloAck` granting a Trust Tier has already been sent.** Check 2 moves the refusal to the first cheap operation of the exchange, and makes the tier belong to the device the channel authenticated rather than to whichever device the `Hello` names.

### Three rules that are not checks

- **The tier a side enforces is the one it computed.** `HelloAck.assigned_tier` arriving from the peer is what *they* granted *us*: display material, and never an input to our own grant. A peer claiming `TRUST_TIER_SAME_ACCOUNT` for itself is the whole of the attack this forbids.
- **`Rejected` is an outcome, not an error.** The exchange completes, the `HelloAck` carries `TRUST_TIER_REJECTED`, and every later request is denied. It is not a transport failure and must not be retried as one.
- **The nonce is exactly 16 bytes and fresh per connection**, drawn through the `Rng` trait. Reuse makes the peer's signature replayable against a later session.

### A rejected peer's nonce is still signed

The `HelloAck` sent with `TRUST_TIER_REJECTED` carries a real `nonce_signature`.

Withholding it protects nothing. `tradr-hello-v1` exists precisely so that signing an attacker-chosen sixteen bytes is safe — that is what a domain tag is for — and `assigned_tier` in the same message already tells the peer the verdict, so there is nothing left to conceal. What withholding it would buy is a branch through a Critical Module that only hostile peers ever take, which is the branch least likely to be exercised and most likely to be wrong.

## Chunks and integrity

### Chunk sizes

| Transport | Chunk size |
|---|---|
| `direct-quic`, `holepunch-quic`, `wifi-direct` | 1 MiB |
| `relay` | 256 KiB |
| `ble-gatt` | 4 KiB |

**Chunk boundaries never change when the path does.** 1 MiB is the reference; smaller transports subdivide it. That is what lets a file received partway over `relay` resume over `direct-quic`.

### Where a subdivided piece belongs

`chunk_index` always counts **reference** chunks, never transport-sized pieces, which is [invariant I6](../CLAUDE.md#8-invariants-that-must-not-break). A subdivided piece additionally carries `offset_in_chunk`, its offset within that reference chunk, and the two together give the absolute position:

```
absolute offset = chunk_index * 1 MiB + offset_in_chunk
```

A transport that does not subdivide sends `offset_in_chunk = 0`. Protobuf omits a zero-valued scalar, so **the field costs nothing on the QUIC paths** and a few bytes per frame only where subdivision actually happens.

**Stream order is deliberately not used to carry this.** The pieces do arrive in order on a QUIC stream, and deriving the offset from arrival order would cost no bytes at all. Three things rule it out:

1. **`ble-gatt` cannot promise it.** A GATT write without response is neither ordered nor acknowledged, and that is the mode worth having for throughput on a transport already limited to 20-100 KB/s.
2. **The offset is an input to verification, not only to placement.** Each piece's `verify_path` checks it against `content_hash` at its absolute position, so a wrong offset fails verification rather than corrupting the file — which is the good outcome, reached the bad way: docs/04 then re-requests the chunk, fails again, and after three attempts blames the path. A misordering bug is diagnosed as a bad network.
3. **It would be an unwritten invariant underneath a Critical Module.** Chunk resumption is what [CLAUDE.md](../CLAUDE.md#6-critical-modules-tests-come-first) calls the module whose failure collapses path selection. Three transport implementations would each have to preserve an ordering property nobody stated, and the check for whether they do would be a transfer that thrashes.

Eight bytes at most per subdivided frame, and none on the default path, buys the removal of that assumption.

### Why BLAKE3

BLAKE3 is internally a Merkle tree, which yields two properties — see [ADR-0006](adr/0006-blake3-for-content-integrity.md):

1. **One whole-file hash verifies any chunk.** No separate list of chunk hashes needs sending. Using `bao`-style verified streaming, chunks are checked as they arrive, so nothing gets discovered corrupt only at the end.
2. **Hashing parallelizes.** Hashing a 1 GB file takes seconds under SHA-256 but stays under a second with BLAKE3 across several cores. Pre-send hashing never becomes something the user waits on.

An `Item` carries `content_hash`, the 32-byte BLAKE3 root, and each `ChunkData` carries the tree path needed to verify it — the `bao` outboard.

### Verification failure

- A chunk fails: re-request that chunk alone. After three failures, suspect the path and rerun path selection
- A whole file fails: return `ItemComplete { verified: false }`, discard the partial file, and start over. This happens only through a bug in the hash-tree code, or because the file changed on the sender mid-transfer

## Partial files

Incoming files are written to `<destination>/.tradr-partial/<transfer_id>/<ordinal>`, where **`ordinal` is a number the receiver assigns**, not anything the sender chose.

`item_id` is a string the sender picks. Using it as a path component would put an attacker-controlled value on the filesystem, and every defence against that — rejecting `..`, rejecting separators and control characters, handling Windows reserved names, catching two ids that differ only in case colliding on a case-insensitive filesystem — is a check that has to be right forever. **A receiver-assigned ordinal removes the class instead of defending against it.**

The mapping from ordinal back to `item_id` lives in SQLite alongside the rest of the transfer's progress, which is where the receiver already looks when resuming.

`item_id` is still validated on arrival, because it is a map key and it reaches logs and the UI. It is constrained to an opaque token: **1 to 64 characters of lowercase ASCII letters, digits, `-` and `_`**. That is deliberately narrower than a filename needs to be, since it never has to be one.

- On completion and successful verification, `rename` into place — atomic within one filesystem
- Progress lives in SQLite. To keep the database and the partial file from diverging, the database is updated after the chunk write is `fsync`ed
- Partial files untouched for seven days are swept at startup

## Name collisions and sanitization

The receiver **never trusts an incoming `relative_path`**. It enforces:

| Check | Action |
|---|---|
| Absolute path, starting `/` or `C:\` | Reject |
| Contains `..` | Reject |
| Contains NUL or other control characters | Reject |
| Contains a bidirectional override, embedding or isolate, or a line or paragraph separator | Reject |
| Windows reserved names: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` | Append `_` |
| Trailing dots or spaces, which break on Windows | Strip |
| Path length beyond the OS limit | Reject |
| Collides with an existing file | Number it as `name (2).ext`. Never overwrite |
| Item is a symlink | Reject in v1, since the target may point outside the Share Root |

This is the same attack surface as zip slip. The path is normalized before joining, and the joined result is re-checked to confirm it is prefixed by the destination's realpath.

### Why a filename may not reorder itself

The receiver shows an incoming filename to the user, who accepts or declines on the strength of it. A name carrying `U+202E RIGHT-TO-LEFT OVERRIDE` renders in the opposite order from the bytes it contains:

```
bytes on the wire   report\u{202E}fdp.exe
what the user sees  reportexe.pdf
what gets written   an executable
```

Rejected: `U+202A` to `U+202E`, the overrides and embeddings; `U+2066` to `U+2069`, the isolates; and `U+2028` and `U+2029`, the line and paragraph separators, which also break any single-line rendering of a name and any log line carrying one. None has a use in a filename.

**`U+200E` and `U+200F`, the directional marks, stay permitted.** They influence the direction of neutral characters and cannot reverse a run, so they do not produce the substitution above, and Arabic and Hebrew filenames legitimately carry them. Rejecting them would cost every RTL user something real to defend against nothing.

These are not control characters — `char::is_control` is false for every one of them — so the row above does not cover them and a check written against it alone would let them through.

## The Browse plane

Remote operations on Share Roots. Every request carries a `share_id`, and the receiver checks the requester's Trust Tier against that Share's audience before acting.

| Message | Response | Mode |
|---|---|---|
| `ListDir { share_id, path, cursor, limit }` | `DirListing { entries[], next_cursor }` | ro |
| `Stat { share_id, path }` | `StatResult { entry }` | ro |
| `ReadFile { share_id, path, offset, length }` | Returned on a data stream | ro |
| `WriteFile { share_id, path, content_hash, size }` | Received on a data stream | rw |
| `Mkdir { share_id, path }` | `Ack` | rw |
| `Delete { share_id, path, recursive }` | `Ack` | rw |
| `Rename { share_id, from, to }` | `Ack` | rw |
| `Watch { share_id, path }` | A stream of `FsEvent` | ro |

`ListDir` pages by cursor, since a directory of tens of thousands of entries will not fit one frame. Default page size is 500.

`Watch` uses inotify, FSEvents, `ReadDirectoryChangesW`, or Android's `ContentObserver`, coalescing events with a 250 ms debounce.

## Versioning

- `Hello` carries each side's supported version range; the highest common version wins
- Protobuf fields are only ever added. Removals become `reserved`
- Unknown message types are ignored, giving forward compatibility — but only in the narrow sense [The type byte](#what-unknown-message-types-are-ignored-actually-covers) defines: an unassigned code inside the receiving plane's own range. A code from another plane, `0x00`, and a bad length are each refused
- A breaking change creates `proto/tradr/v2/`, dispatched by the `Hello` negotiation. The old version stays supported for at least a year

## Protobuf definitions

The definitions live in `proto/tradr/v1/`.

| File | Contents |
|---|---|
| `common.proto` | `DeviceInfo`, `Attestation`, `FileEntry`, and other shared types |
| `control.proto` | `Hello`, `HelloAck`, `TransferOffer`, `TransferAccept`, and so on |
| `transfer.proto` | `ChunkRequest`, `ChunkData`, `ItemComplete`, and so on |
| `browse.proto` | `ListDir`, `ReadFile`, `WriteFile`, and so on |
| `brokr.proto` | Messages on the Brokr WebSocket, Tier 2 only |

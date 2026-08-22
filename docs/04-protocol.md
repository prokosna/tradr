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

- `len` covers `type` and `payload` together, bounded by the `max_frame_size` negotiated in `Hello` — 1 MiB by default, 512 bytes over BLE
- `type` selects the message; `payload` is its protobuf encoding
- On QUIC the control and data planes take separate streams. BLE and relay offer a single stream, so multiplexing is done in-band with a frame variant carrying a `stream_id`

## The three planes

| Plane | Role | Streams |
|---|---|---|
| **Control** | Handshake, capability negotiation, offer and accept, progress and completion | Bidirectional stream 0, always exactly one |
| **Browse** | Listing, stat, and reading or writing Share Roots | A bidirectional stream per request |
| **Data** | Chunk payloads | A unidirectional stream per Item, four concurrent by default |

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

## Chunks and integrity

### Chunk sizes

| Transport | Chunk size |
|---|---|
| `direct-quic`, `holepunch-quic`, `wifi-direct` | 1 MiB |
| `relay` | 256 KiB |
| `ble-gatt` | 4 KiB |

**Chunk boundaries never change when the path does.** 1 MiB is the reference; smaller transports subdivide it. That is what lets a file received partway over `relay` resume over `direct-quic`.

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
- Unknown message types are ignored, giving forward compatibility
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

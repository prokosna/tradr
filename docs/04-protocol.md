# 04. Wire protocol

`proto/tradr/v1/` is the source of truth (prost for Rust, ts-proto for TS). Only `tradr-proto` names prost.

```
Planes:   Control / Browse / Data
Framing:  [u32 BE len][u8 type][protobuf payload]
Channel:  QUIC TLS 1.3 (direct-quic; also holepunch and wifi-direct if built)
```

## Framing

- `len` counts `type` + payload. The minimum is 1, and `0` is fatal.
- `max_frame_size` is what a side will **receive**. Each side declares its own in `HelloAck`. Default: 1 MiB; the minimum a peer may declare is 512 bytes. Until `HelloAck` arrives, both directions use the channel's own value.
- The length is checked against the bound **as soon as the 4 header bytes arrive**, before any allocation. An oversize or zero length is fatal to the stream: there is no resync.
- **A reader reads exactly one frame**, never more (fixed-size buffered reads once swallowed the next exchange).
- Framing carries the type byte verbatim. The planes interpret it.

## Planes and type codes

| Plane | Streams |
|---|---|
| Control | bidirectional stream 0, exactly one |
| Browse | one bidirectional stream per request |
| Data | one unidirectional stream per Item, 4 concurrent |

| Range | Codes |
|---|---|
| `0x00` | never valid |
| `0x01-0x1f` Control | 01 Hello, 02 HelloAck, 03 TransferOffer, 04 TransferAccept, 05 TransferReject, 06 TransferComplete, 07 TransferAbort, 08 PathChanged, 09 KeepAlive, 0a ItemComplete, 0b TransferProgress, 0c LinkReply, 0d LinkApprove, 0e LinkDecline. **`0x0f` is permanently unassigned** (it is the test example); **`0x10` is retired** (was BroadcastKeyOffer, ADR-0028) |
| `0x20-0x3f` Data | 20 ChunkRequest, 21 ChunkRerequest, 22 ChunkData, 23 FlowControl |
| `0x40-0x5f` Browse | 40 ListDir, 41 DirListing, 42 Stat, 43 StatResult, 44 ReadFile, 45 ReadFileBegin, 46 WriteFile, 47 Mkdir, 48 Delete, 49 Rename, 4a Ack, 4b Watch, 4c FsEvent, 4d Refused |
| `0x60-0x7f` | retired (was the in-band mux, ADR-0028); refused |
| `0x80-0xff` | unassigned |

Rules:
- A code is never reused once retired.
- A code from another plane's range is **refused**, because authorization lives in the plane.
- An **unassigned** code inside the receiving plane's own range is skipped (forward compatibility). At most **16 consecutive** are skipped per stream.
- **The first frame on a Control stream is never skipped**: it must be `Hello` or `LinkReply`.
- `brokr.proto` messages travel on the Brokr's own channel and carry no codes.

### Link stream

A Control stream opening with `LinkReply` (0x0c) is a linking exchange ([11](11-account-linking.md)). It has no Hello, carries only codes 0c, 0d and 0e, and is accepted only while an invite is open. The receiver reads before it writes on this first frame only.

**Ending streams safely**: whichever side writes last must `finish()` and then wait for the peer to close before dropping the channel, because dropping can lose the frame. `Closed` from that wait counts as success. A CLI that exits after a send closes its endpoint and waits up to 2 s for idle. After a Browse stream, the listener waits up to 2 s for the peer to close.

## Session

```
Sender                                       Receiver
Hello(versions, device_id, keys, attestation, nonce)  <->  Hello
            each verifies the other → Trust Tier
HelloAck(caps, max_frame_size, assigned_tier, sig over peer nonce)  <->  HelloAck
TransferOffer(transfer_id, items[])   →
                                      ←  TransferAccept(items accepted, resume_chunk)
                                      ←  ChunkRequest(item, from, count=64)
ChunkData × N                         →
                                      ←  ItemComplete(item, verified)
                                      ←  TransferComplete
```

- `transfer_id` is a UUIDv7 built from `Clock` (seconds × 1000) and `Rng`.
- The receiver **pulls** ([ADR-0007](adr/0007-receiver-driven-chunk-pull.md)). The same mechanism gives flow control, resume, deduplication and out-of-order re-requests.
- **The listener serves up to 8 connections concurrently.** Each gets **20 s from accept to a finished handshake** (Hello + HelloAck, or a LinkReply). Nothing is timed after that.
- File placement uses `Vfs::rename_no_replace`; on `AlreadyExists` it takes the next collision name. `NativeVfs` holds a process-wide lock across check and rename.

### Hello checks (pure, no I/O), cheapest first

1. Version overlap: `negotiated = min(maxes)` must be ≥ `max(mins)`.
2. Key join: `BLAKE3(identity_pub)[0..16] == channel-authenticated DeviceId`.
3. `KeyBinding`: P-256 signature over `tradr-keybind-v1 || agreement_pub`, and `not_after` is in the future.
4. Attestation: handed out to the caller (it may need a JWKS fetch). The returned Trust Tier is **ours to enforce**.
5. Peer's `HelloAck`: a signature over `tradr-hello-v1 || our nonce` (16 fresh bytes from `Rng`); `negotiated_version` equals ours; `max_frame_size` ≥ 512.

- The peer's `assigned_tier` is display-only. `REJECTED` is an outcome, not an error, and its HelloAck is still signed.
- Decoding tolerance:
  - `capabilities` is narrowed to 16 bits.
  - An over-long `display_name` / `sender_label` is dropped.
  - Unknown `origin` / reject `reason` enums become `None`.
  - Keys, nonces, versions, `item_id`, `relative_path`, `size`, `content_hash` and `transfer_id` are refused if invalid.
  - `chunk_size` must be exactly 1 MiB (0 is refused).
  - `total_bytes` must equal the sum of the item sizes.
  - An empty `items` list or a duplicate `item_id` is refused.
  - `resume_chunk` must be below the item's chunk count.
  - `mime` and `mtime` are not carried.
- Items that the Accept does not name are declined.

## Chunks and integrity

- **1 MiB reference chunks regardless of transport (I6).** Smaller transports subdivide: absolute offset = `chunk_index × 1 MiB + offset_in_chunk`. Offsets are explicit, never inferred from arrival order.
- `content_hash` = BLAKE3 root. The bytes after a `ChunkData` header are a **bao slice** ([ADR-0006](adr/0006-blake3-for-content-integrity.md), [ADR-0016](adr/0016-bao-verified-streaming-costs-6-percent.md)). Overhead is 6.26% per 1 MiB piece. Field 5 (`verify_path`) is reserved.
- **Receiver order**: bound-check `chunk_index`, `offset_in_chunk` and `payload_len`, **then verify, then write**. A failed piece is re-requested; after 3 failures, suspect the path. A whole-file failure sends `ItemComplete{verified:false}` and discards the partial file.
- **Sender streams**: one pass per item builds both the hash and the bao outboard. The outboard spools to an anonymous scratch file from `tradr-vfs` (the temp dir, or the Android cache dir). Pieces are served from a 1 MiB window. A file whose size changed since the Offer fails that item.

## Partial files

- `<dest>/.tradr-partial/<transfer_id>/<item_id>`. Paths come only from the `tradr-vfs` constructors `partial_root_rel_path` and `partial_file_rel_path`.
- `item_id` is 1-64 chars of `[a-z0-9_-]`. Windows reserved names are refused by `ItemId::new` (Critical Module).
- Resume = the partial file's size ÷ 1 MiB (`derive_item_resumption`). There is no database.
- When an item completes and verifies, it is renamed into place. When the transfer ends, the transfer directory is removed with `Vfs::remove`, which refuses a non-empty directory; that refusal is expected.
- **Sweep**: at listener start (`run_listener`), a transfer directory whose own mtime and every entry's mtime are more than 7 days old is removed whole. Only names that parse as `TransferId` / `ItemId` are touched. The partial root is listed through `list_partial_root`, an inherent `NativeVfs` method that is **not on the `Vfs` trait**, so peers cannot reach it. `.tradr-partial` stays refused to `list` from peers.

## Filename sanitization (Critical Module: `RelPath`, `tradr-vfs`)

| Input | Action |
|---|---|
| Absolute, `..`, NUL/control, bidi override/isolate, U+2028/9 | reject |
| Windows reserved stem (`CON`, `COM1`, ...) | append `_` (on every platform) |
| `:` in a component (NTFS ADS) | replace with `_`, before the reserved-name check (on every platform) |
| Trailing dot or space | strip |
| Too long | reject |
| Name collision | `name (2).ext`, never overwrite |
| Symlink | reject |

U+200E and U+200F are allowed. The joined path is re-checked against the destination's realpath. Sanitization is identical on every platform.

## Browse plane

Every request is authorized by the access decision at classification ([ADR-0024](adr/0024-one-folder-per-device-full-access.md): `SameAccount`, or `Linked` with `full_access`).

| Request | Response |
|---|---|
| `ListDir{path, cursor, limit=500}` | `DirListing{entries, next_cursor}` |
| `Stat` | `StatResult` |
| `ReadFile{path, offset, length}` | `ReadFileBegin` + raw bytes |
| `WriteFile{path, size, mode}` | bytes follow, written under `.tradr-partial`, then renamed. Modes: `CREATE_NEW`, `RENAME_IF_EXISTS`, `OVERWRITE` |
| `Mkdir`, `Delete{recursive}`, `Rename{from,to}` | `Ack` |
| `Watch` | `FsEvent` stream (not built) |
| any | `Refused{reason}`: `NO_ACCESS`, `NOT_FOUND`, `ALREADY_EXISTS`, `WRONG_KIND`, `NOT_ALLOWED`, `FAILED`. It never carries a path or an OS message |

## Versioning

- `Hello` carries version ranges, and the highest common version wins. Protobuf fields are only added; removed fields become `reserved`.
- A breaking change creates `proto/tradr/v2/`, and the old version is kept for at least a year.

| File | Contents |
|---|---|
| `common.proto` | shared types |
| `control.proto` | Hello, Offer, Accept, ... |
| `transfer.proto` | chunks |
| `browse.proto` | browse plane |
| `link.proto` | LinkReply / Approve / Decline |
| `brokr.proto` | Brokr API |

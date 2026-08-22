# ADR-0007: The receiver pulls chunks

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

The data flow during a transfer needs a direction.

- **Push**: on `Accept`, the sender streams every chunk unilaterally. Simple
- **Pull**: the receiver requests chunks with `ChunkRequest` and the sender answers

## Decision

**Pull.** The receiver sends `ChunkRequest { item_id, from_chunk, count }` and the sender returns `ChunkData`. Default `count` is 64, meaning 64 MiB.

## Reasoning

1. **Resumption needs no special case.** Restarting after an interruption means requesting from a later chunk index. No dedicated resume protocol, no negotiation. **This is the main reason.** The entire path-selection design rests on transfers always being interruptible and resumable — see [03](../03-discovery-and-transport.md#phase-5-is-the-point) — and pull is the cheapest way to make that true.

2. **Flow control follows the receiver's circumstances.** A slow disk, a low battery, bandwidth shared with another transfer — all expressible directly. Push would need separate flow-control messages.

3. **Deduplication becomes possible.** Before requesting, the receiver can judge from position and `content_hash` whether it already holds that content, and skip the request entirely — for the same file under another name, or a partially received copy.

4. **Out-of-order requests work.** Only a chunk that failed verification needs re-requesting, via `ChunkRerequest`.

5. **Path switching becomes natural.** Resuming a relay-started file over `direct-quic` means the receiver saying "next, from here". The sender holds no state.

## Costs

- **One extra round trip.** But `count` batches — 64 chunks, 64 MiB, by default — so the frequency is effectively negligible. Over a 25 ms RTT tailnet at 100 MB/s, 25 ms per 64 MiB is under 4% overhead. Measure and tune `count`.
- **A heavier receiver implementation.** Tracking which chunks are held, issuing read-ahead requests, and managing in-flight counts all land on the receiver.
- **Round trips cost relatively more over BLE**, where chunks are 4 KiB. Mitigated by raising `count`, to 256 for the equivalent of 1 MiB.

## Implementation notes

- The receiver keeps a fixed number of chunks in flight, pipelining. Requesting only after a full `count` arrives leaves the pipe empty in between; issue the next request once half the previous one has arrived
- `FlowControl` lowers the in-flight ceiling dynamically, for a disk that has backed up
- The sender only reads requested chunks and holds no progress state, which also makes it robust to its own restart

# ADR-0016: `bao` verified streaming costs 6%, not 0.03%

- **Status**: Accepted
- **Date**: 2026-08-27
- **Supersedes**: [ADR-0006](0006-blake3-for-content-integrity.md)

## Context

[ADR-0006](0006-blake3-for-content-integrity.md) chose BLAKE3 with `bao` verified streaming, and put the cost at "a few hundred bytes per chunk, roughly 0.03% against a 1 MiB chunk, so negligible". [DCR-055](../../STATE.md) repeated that figure when it settled what a `ChunkData` carries.

**The figure is wrong by two orders of magnitude, and it was never measured.** It was found by an existing test failing to fit its own frame bound, which is the only reason anyone looked.

Measured against `bao` 0.13.1:

| Piece | Content | Slice | Overhead |
|---|---|---|---|
| 1 MiB of a 3 MiB item | 1,048,576 | 1,114,184 | 65,608 — **6.26%** |
| 1 MiB of a 1 GiB item | 1,048,576 | 1,114,696 | 66,120 — **6.31%** |
| 4 KiB (`ble-gatt`) | 4,096 | 4,936 | 840 — **20.5%** |

The whole outboard for a 1 GiB item is 67,108,808 bytes, **6.4%** of the item.

**One number causes all of it.** ADR-0006 reasoned about the tree as though `bao`'s chunk were the 1 MiB reference chunk docs/04 defines, giving a ten-level tree and a path of ten nodes. **`bao`'s chunk is 1024 bytes, BLAKE3's own**, so a 1 MiB range is a subtree of 1024 leaves and a slice over it carries every one of its ~1023 interior parent nodes rather than a path to its root.

## Decision

**BLAKE3 with `bao` verified streaming is kept, unchanged.** What changes is that its cost is stated correctly and one consequence is left open rather than called negligible.

- A piece costs **6.26%** on the bulk transports, and that is affordable.
- A 4 KiB `ble-gatt` piece costs **20.5%**, on a transport [docs/03](../03-discovery-and-transport.md) already limits to 20–100 KB/s. **That is not obviously affordable and this ADR does not claim it is.** It is the open question for whoever cuts the BLE data path.

## Reasoning

**The cheap alternative is cheap and this project may not have it.** A path to the 1 MiB subtree really would be about ten nodes, a few hundred bytes — the figure ADR-0006 imagined. Using one means recomputing that subtree's hash from its content and comparing it against the path. `bao` exposes no such call. `blake3::guts` does.

**ADR-0006's fourth reason applies to that exactly as written**: not assembling cryptographic primitives by hand is an important discipline. Reaching into `guts` to hash a subtree at an offset is that assembly, one level below where DCR-055 already refused it when it declined to re-interleave `bao`'s slice grammar. **The overhead is what the discipline costs, and paying it is the decision.**

**Neither alternative recovers the bytes anyway.** Sending each item's whole outboard once up front is the same 6.4%, paid before the transfer instead of during it, and it adds a Control-plane message and an outboard to persist for resumption. Splitting the tree path from the payload into separate fields, as the retired `verify_path` did, moves where the parents are written down and removes none of them.

## Consequences

- **Every throughput figure in this design is 6% optimistic where it counts bytes on the wire.** [ADR-0004](0004-quic-as-the-bulk-transport.md)'s 35 MB/s target is a measurement of the transport and is unaffected; a transfer's wall-clock time for a given file is not.
- **`ble-gatt`'s data path is now a decision rather than an assumption.** Options include a larger transport chunk, so the constant per-slice parent count is amortised over more content, or accepting 20.5%, or carrying content unverified on that transport and verifying the item whole at the end — which [ADR-0006](0006-blake3-for-content-integrity.md) rejected for good reasons that still hold.
- **The estimate was wrong for five weeks and nothing noticed**, because nothing in the repository compared it against `bao`. The general form is the one this project keeps rediscovering: a number written in prose is not a measurement, and only a measurement is.

## Costs

- A superseding ADR for a corrected figure is heavier than an edit, and is what [CLAUDE.md](../../CLAUDE.md) section 7 requires: an ADR is never rewritten, so the record shows both what was believed and what was measured.

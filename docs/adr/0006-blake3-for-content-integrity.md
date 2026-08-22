# ADR-0006: BLAKE3 for content integrity

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

Transferred files need integrity verification. Requirements:

- Confirm the whole file arrived correctly
- Verify per chunk, so only a corrupted chunk needs resending
- Keep pre-send hashing off the user's critical path, so a 1 GB file does not cost seconds of waiting
- Skip chunks whose content the receiver already holds

Options: SHA-256 with a chunk hash list, a SHA-256 Merkle tree, or BLAKE3.

## Decision

**BLAKE3.** An `Item` carries only `content_hash`, the 32-byte BLAKE3 root; no chunk hash list is sent. Each `ChunkData` carries a `bao`-format verification path, the outboard.

## Reasoning

1. **BLAKE3 is internally a Merkle tree.** One whole-file hash verifies any chunk, so no chunk hash list needs sending. For 1 GB in 1 MiB chunks that would be 1024 hashes, 32 KB, now unnecessary.

2. **Verified streaming works**, in `bao` format. Chunks are checked as they arrive, so nothing is discovered corrupt only at the end, and a bad chunk is re-requested on the spot.

3. **Hashing parallelizes.** SHA-256 takes seconds for 1 GB at roughly 500 MB/s on one core; BLAKE3 stays under a second across several cores and SIMD, above 3 GB/s. Pre-send hashing never becomes something the user waits on.

4. **No hand-built Merkle tree.** Option 2 offers the same properties, but the tree shape, padding, and domain separation all become decisions to make. BLAKE3 fixes them in its specification and ships `bao` for verified streaming. **Not assembling cryptographic primitives by hand is an important discipline.**

## Costs

- **Less ubiquitous than SHA-256.** Not in standard libraries, and not FIPS certified, which is awkward under a FIPS requirement. Judged inapplicable for personal and small-team file transfer.
- **The `bao` outboard adds per-chunk overhead**, proportional to tree depth. For 1 GB in 1 MiB chunks the tree is about ten levels, a few hundred bytes per chunk — roughly 0.03% against a 1 MiB chunk, so negligible.
- **BLAKE3 is also used to derive Device IDs**, so a weakness would have wide impact. SHA-256 would produce the same shape of dependency.

## Where it is used

| Purpose | Input |
|---|---|
| Device ID | The first 16 bytes over `ed25519_pub` |
| Attestation nonce | `ed25519_pub \|\| x25519_pub` |
| Fingerprint | `"tradr-fp-v1" \|\| ed25519_pub \|\| x25519_pub` |
| Content Hash | File contents |
| `account_tag` | `google_sub \|\| salt` |
| `link_tag` | `link_secret` |

For domain separation, key-derivation-shaped uses always prepend a fixed string. EID derivation is the exception, using HKDF-SHA256 — BLAKE3's KDF mode would serve, but HKDF is the better-worn specification.

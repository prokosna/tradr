# ADR-0018: BLAKE3's `derive_key` for EIDs and the bootstrap secret

- **Status**: Accepted
- **Date**: 2026-09-05
- **Supersedes**: the KDF row of [docs/05](../05-security.md#algorithms)'s Algorithms table, the closing line of [ADR-0006](0006-blake3-for-content-integrity.md), and the `bootstrap_secret` line of [ADR-0010](0010-identity-is-the-issuer-subject-pair.md). Neither ADR is rewritten; both keep the text they were accepted with

## Context

M7 is the first milestone that has to compute an EID. Reading [docs/03](../03-discovery-and-transport.md#2-ble--proximity-no-network-required-tier-0) against the rest of the document set before cutting a Work Item found that **the EID's key derivation is specified two ways, and both specifications are live**.

- [docs/05](../05-security.md#algorithms)'s Algorithms table: `| KDF | HKDF-SHA256 | EID derivation and similar |`
- [docs/11](../11-account-linking.md#deriving-the-link-secret), settling the Link Secret under DCR-066: "Every other derived value in this design is BLAKE3: the Device ID, the Content Hash, the Attestation nonce, the Agreement Key Tag, **the EIDs**."

One of those is false, and **the second one is load-bearing**: DCR-066 chose BLAKE3 for the Link Secret partly *because* the EIDs were already BLAKE3. If they are not, DCR-066's stated reason is wrong about the very list it appeals to.

[ADR-0006](0006-blake3-for-content-integrity.md)'s closing line agrees with docs/05 and names the EID as a deliberate exception: "EID derivation is the exception, using HKDF-SHA256 — BLAKE3's KDF mode would serve, but HKDF is the better-worn specification." **That ADR is Superseded**, by [ADR-0016](0016-bao-verified-streaming-costs-6-percent.md) — which is about `bao`'s per-chunk overhead and says nothing about a KDF at all. So a decision left the live document set as collateral of a supersession that was not about it, and only docs/05's one-row restatement kept it alive.

**Two further things were undecided, and both would have fallen to whoever implemented an EID first.**

**The formula names Expand, and the table under it feeds Expand something that is not a pseudorandom key.** docs/03 reads `EID = HKDF-Expand(secret, "tradr-eid-v1" || floor(unix_time / 900), 8)` over three secrets. An ABK is 32 random bytes and a Link Secret is `derive_key` output, so both are valid PRKs. The third is `HKDF(account_id, "tradr-bootstrap-v1")`, and `account_id` is `iss || 0x00 || sub` — a structured, low-entropy, **public** string, which is precisely the input HKDF-Extract exists to condition. The line skips Extract. So the three-row table is two constructions written as one.

**The bootstrap line carries the defect DCR-066 already named once.** `bootstrap_secret = HKDF(account_id, "tradr-bootstrap-v1")`, in [ADR-0010](0010-identity-is-the-issuer-subject-pair.md) and in docs/05, "named no hash, no salt and no output length" — DCR-066's own words about the Link Secret line, applying unchanged to a second line, found in the milestone that is the first to need it.

## Decision

**Every EID-related derivation is `BLAKE3::derive_key`.**

```
window           = unix_time.div_euclid(900)                    i64
EID              = BLAKE3::derive_key(context = "tradr-eid-v1",
                       key_material = secret || window_be)[0..8]
bootstrap_secret = BLAKE3::derive_key(context = "tradr-bootstrap-v1",
                       key_material = account_id)               32 bytes
```

`window_be` is the window number as **8 bytes, big-endian, two's complement**. `secret` is 32 bytes in all three cases — an ABK, a Link Secret, or the bootstrap secret above.

docs/05's Algorithms table loses its `HKDF-SHA256` row. **No HKDF and no SHA-2 remains anywhere in this design**, so neither `hkdf` nor `sha2` becomes a dependency.

## Reasoning

1. **This is DCR-066's reasoning applied to the line DCR-066 assumed was already settled.** "Adding HMAC-SHA256 for one value would put a second hash family in the trust path to save nothing" was decided three days ago, for a value derived from the same secrets by the same devices. Holding one rule for the Link Secret and its opposite for the EID is the inconsistency; the only question is which way to make them agree.

2. **`blake3` is already a dependency of three crates, and `hkdf` plus `sha2` would be two new ones** — in a security path, to compute eight bytes that go on the air.

3. **`derive_key(context, key_material)` is a KDF with a compile-time context string, which is the role `"tradr-eid-v1"` was already playing as HKDF's `info`.** The construction is unchanged; only the primitive performing it changes.

4. **It dissolves the Extract-versus-Expand question rather than answering it.** `derive_key` accepts arbitrary key material, so an ABK, a Link Secret and `account_id` feed it identically, and docs/03's three-row table becomes one construction over three secrets — which is what it always read as.

5. **docs/11 already asserts that the EIDs are BLAKE3.** Making that true costs one row of a table. Making it false costs DCR-066 its stated reason, in a document that has already shipped.

## The three sub-decisions the old formula left open

**The window goes into the key material, not the context, and that is forced.** `derive_key`'s context must be a compile-time constant — the specification of the function says so, and DCR-066 already leaned on it. So the window cannot be concatenated into the context the way docs/03 concatenated it into HKDF's `info`.

**The order is `secret || window` and the width is fixed.** All three secrets are 32 bytes, so a fixed-width window appended to one makes every input exactly 40 bytes and the boundary unambiguous **by construction rather than by luck**. A decimal rendering would not be: `9` followed by window `1` and `91` followed by nothing are the same bytes, and a variable-width encoding is how that becomes reachable.

**`div_euclid`, not `/`.** Rust's `/` truncates toward zero and `floor` does not, so they disagree for every negative operand: `-1 / 900` is `0` while `floor(-1/900)` is `-1`. `UnixTime` wraps an `i64` and admits times before 1970, so a device with a badly wrong clock is the reachable case. **This is one word, and leaving it out is exactly the class of omission this ADR exists to close** — the implementation would match the written formula on the values anyone tests and diverge on the ones nobody does.

## Costs

- **HKDF-SHA256 is the better-worn specification and that is given up.** ADR-0006's point was real: HKDF has more review, more test vectors and more independent implementations than BLAKE3's KDF mode. What is bought for it is a single hash family across every derived value in the design, which is the trade DCR-066 already made once.
- **Nothing is deployed, so there is no migration.** Had this been found after M7 shipped, changing it would have changed every device's broadcast at once with no way to recompute the old value — the same hazard [ADR-0010](0010-identity-is-the-issuer-subject-pair.md) records for `account_id`, which is why that one was settled before any key existed and why this one is settled before any EID does.

## Conditions for revisiting

- A weakness in BLAKE3 would reach the Device ID, the Content Hash, the Attestation nonce and the Link Secret before it reached an EID, so an EID-specific retreat is not the shape a revisit would take. It would be ADR-0016's and ADR-0012's question, not this one's.

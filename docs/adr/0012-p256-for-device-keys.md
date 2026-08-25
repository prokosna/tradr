# ADR-0012: P-256 for Device Keys

- **Status**: Accepted
- **Date**: 2026-08-22
- Depends on [ADR-0011](0011-keystore-exposes-operations.md), which established that `KeyStore` exposes operations rather than key bytes.

## Context

The design specified Ed25519 for signing and identity and X25519 for Noise key agreement, on the grounds of Noise compatibility and implementation simplicity. That reasoning did not account for what it cost.

**A key those curves use cannot enter a secure element on any platform Tradr targets.**

| | Ed25519 + X25519 | P-256 (ECDSA + ECDH) |
|---|---|---|
| macOS Secure Enclave | No — the Enclave supports P-256 alone | Yes |
| Windows TPM through CNG | Not generally available | Yes |
| Android StrongBox | Recent Keymint only, not dependable | Yes |
| Linux | Software either way | Software either way |

[docs/05](../05-security.md#key-storage) promises hardware backing wherever the platform offers it. Under the original choice that promise was false on three of the four platforms, and the documentation said so in a sentence ending "so it stands for now" — prose standing in for a decision.

The blocking question was whether the Noise implementation could do P-256 at all, and whether a key it never sees could still take part in the handshake.

## Decision

**P-256 throughout: ECDSA for signing and identity, ECDH for key agreement.**

**Wire field names describe the role, not the algorithm**: `identity_pub` and `agreement_pub`, never `ed25519_pub` or `p256_pub`. One curve is in force per protocol version, which `Hello.min_version` and `Hello.max_version` already carry. A future curve change is a version bump, not a negotiation.

The Noise suite becomes `Noise_IK_P256_ChaChaPoly_BLAKE2s`.

## Reasoning

1. **It is the only choice under which the hardware-backing promise is keepable.** Three platforms gain a secure element; none loses anything, since Linux was software-only under either curve.

2. **`snow` supports it, and this was measured rather than assumed.** `snow` 0.10 carries a `p256` feature exposing `DHChoice::P256`. A probe built against it completed a full `Noise_IK_P256_ChaChaPoly_BLAKE2s` handshake between an initiator and a responder.

3. **A key held in hardware can still drive the handshake**, which was the real question behind [ADR-0011](0011-keystore-exposes-operations.md). Reading `snow`'s source rather than its documentation:
   - `CryptoResolver::resolve_dh` allows a custom `Dh` implementation, so `dh()` can delegate to `KeyStore::agree`
   - `Dh::privkey()` — the one method a hardware key cannot answer — is called in exactly one place, `Builder::generate_keypair`, a convenience method Tradr never calls because keys come from the `KeyStore`. **It is never reached during a handshake**
   - The builder resolves the static and ephemeral keys as **two separate `Dh` instances**, so the static key can delegate to hardware while the ephemeral key, which is per-handshake and needs no protection, stays in software

4. **Nothing else in the stack objects.** `rustls` supports P-256 for the self-signed certificate at least as well as Ed25519, and ECDSA's signing nonce — the part that is dangerous to get wrong in software — is generated inside the secure element on every platform that has one.

## Consequences

- **`Device ID` is `BLAKE3(identity_pub)[0..16]`** and every derived identifier follows the renamed fields. Because this changes what a Device ID *is*, deciding it after keys existed would have invalidated every Device ID, every pinned Fingerprint, and every stored ABK at once. That is why it was closed inside M0, before WI-M0-007 generated a key.
- **Per-device curve agility is rejected.** Noise's pattern name fixes the DH for both parties, so mixed curves would force a negotiation round trip onto the BLE path and open a downgrade. One curve per protocol version instead.
- **ECDSA is more failure-prone than Ed25519 when implemented in software**, since a repeated or biased signing nonce leaks the private key. On platforms with a secure element the nonce never leaves it. On Linux, where the key is software anyway, the `p256` crate's RFC 6979 deterministic signing removes the failure mode.
- **`snow` gains the `use-p256` feature**, and the custom `CryptoResolver` becomes a required piece of `tradr-identity` rather than an optional refinement.
- The post-quantum note in [docs/05](../05-security.md#algorithms) still applies; the hybrid patterns it mentions are orthogonal to this choice.

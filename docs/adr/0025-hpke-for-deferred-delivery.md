# ADR-0025: HPKE to the recipient's agreement key carries a Deferred Delivery, and the sender signs it

- **Status**: Accepted
- **Date**: 2026-10-03

## Context

[docs/13](../13-deferred-delivery.md) parks a Transfer on a Brokr for a device that is offline. Every live transfer is protected by a channel both ends are present for -- mutual TLS on QUIC, `Noise_XX` on BLE -- and neither works when the recipient is absent. The delivery has to be encrypted to a key the recipient already holds and authenticated as coming from the sender, with a Brokr in between that may be compromised.

The recipient's long-lived agreement key is a P-256 key behind `KeyStore::agree` ([ADR-0011](0011-keystore-exposes-operations.md), [ADR-0012](0012-p256-for-device-keys.md)), possibly in a secure element, so the private key cannot be handed to a library.

## Decision

**HPKE, RFC 9180, base mode, with the suite `DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`**, encrypting to the recipient's agreement public key. The sender's ephemeral key is generated through the `Rng` port (rule B7). The recipient's decapsulation performs its one Diffie-Hellman through `KeyStore::agree` and the rest of the KEM and key schedule in software, so **the KEM and the key schedule are implemented in this repository against RFC 9180's published test vectors** rather than taken from a crate that would need the raw private key.

**The sender is authenticated by a signature from its identity key**, under a new `DomainTag::DeferredDelivery`, over the HPKE `enc`, both Device IDs, `created_at`, the `transfer_id` and the item list, carried inside the encrypted manifest with the sender's `KeyBinding` and Attestation. HPKE's auth mode is not used: it needs the sender's static agreement key in the KEM, which works only where that key's DH can be called the way the library expects, and it would authenticate an agreement key where Tradr's identity, and its Attestation, are bound to the identity key.

**The body is a sequence of HPKE-sealed records**, 1 MiB of plaintext each (invariant I6), with the sequence number and a final-record flag in each record's associated data, so a record cannot be reordered, dropped or truncated without the open failing.

## Consequences

- A Brokr sees routing and sizes only; it cannot read, alter, re-address or forge a delivery
- Opening an envelope is a Critical Module: the Supervisor writes its tests first, including RFC 9180's vectors for the suite
- **HPKE and the envelope live in `tradr-identity`**, the Layer 3 crate that already holds the Device Key code and P-256, with HKDF and ChaCha20-Poly1305 from the RustCrypto crates the lockfile already carries. `tradr-core` gains only the `DeferredDelivery` domain tag. The recipient's DH arrives as a function, so `KeyStore::agree` is what production passes and a test passes RFC 9180's recipient key
- The domain tag list in docs/05 gains `DeferredDelivery`

## Alternatives rejected

- **Reusing `Noise_XX` or TLS**: both need the recipient present
- **A Noise one-way pattern (`Noise_X` / `Noise_K`)**: workable, but it is a second construction where a standard with published vectors exists, and its single message would have to be chunked by hand anyway
- **HPKE auth mode**: see above; it authenticates the wrong key
- **Encrypting to a key the Brokr distributes**: the Brokr could substitute it; docs/13 takes the key from a direct handshake instead

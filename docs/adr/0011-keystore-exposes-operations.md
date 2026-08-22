# ADR-0011: The KeyStore exposes operations, never key bytes

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

[docs/05](../05-security.md#key-storage) promises hardware backing where the platform offers it: StrongBox or the TEE on Android, a TPM through CNG on Windows, the Secure Enclave on macOS.

**A key held in any of those cannot be read out.** That is what they are for. The private key is generated inside the element and never exists as bytes outside it; the only thing available is a handle and a set of operations performed on the caller's behalf.

So the shape of the `KeyStore` trait decides whether the promise is keepable. A trait that returns key material —

```rust
fn device_private_key(&self) -> Result<[u8; 32]>;
```

— cannot be implemented by StrongBox, by a TPM, or by the Secure Enclave. Every implementation degrades to a software key in a file the OS happens to encrypt at rest. The promise becomes false on all four platforms at once, and it does so silently: the code works everywhere.

This was not an explicit decision. It is the default outcome of writing the obvious signature, which is why it needs recording before the trait is first written.

## Decision

**`KeyStore` is declared in Layer 1 as a set of operations. No method returns private key material.**

```rust
trait KeyStore {
    fn public_identity(&self) -> Result<PublicIdentity>;
    fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature>;
    fn agree(&self, peer_public: &PeerPublicKey) -> Result<SharedSecret>;
    fn backing(&self) -> Backing;   // Hardware { .. } | Software { reason }
}
```

- `sign` covers the Attestation nonce signature and the self-signed TLS certificate
- `agree` covers Noise's static-key Diffie-Hellman
- `backing` is reported so the UI can state the truth rather than assume it
- **There is no `export`, and no migration path that moves a key.** Enrolling a new device means new keys, as [docs/05](../05-security.md#key-storage) already says

## Reasoning

1. **It is the only shape that admits a hardware implementation.** Everything else follows from that.

2. **A software implementation fits it trivially; the reverse is not true.** Layer 1 gains nothing from holding bytes, since the only things done with the private key are signing and agreement.

3. **`backing()` prevents a quiet lie.** Hardware backing fails for ordinary reasons — no TPM, an old Keymint, no Secret Service on a headless Linux box. Making the result a value the UI must render forces the fallback into the open instead of leaving it to an assumption.

4. **It localizes the algorithm question.** Which curve a platform can protect (see [docs/05](../05-security.md#hardware-backing-and-the-curve)) is a property of the implementation, not of the calling code. With an operation-shaped trait, changing the answer touches Layer 3 and the wire format, not the use cases.

## Consequences

- **Noise's DH must run through `agree`.** Any Noise implementation that insists on being handed a static private key is disqualified regardless of its other merits. This is a selection criterion for the crate, checked before it is adopted.
- **The self-signed TLS certificate is signed through `sign`**, so the TLS stack must accept an external signer for the server certificate's key.
- **Tests use a software implementation with a pinned `Rng`**, satisfying B7 and keeping `tradr-core` free of platform code.
- **`Backing` appears in the UI**, which is a small amount of user-facing surface created by an internal decision. That is intended.

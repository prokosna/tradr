//! Supervisor-authored tests for the software `KeyStore`, written before the
//! implementation. Device Key generation is a Critical Module (CLAUDE.md
//! section 6): a weak key fails no build, no test and no handshake. Verified
//! through `p256` and `blake3` directly, never through the crate under test,
//! so a broken implementation cannot agree with itself.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use std::cell::Cell;
use tradr_core::{Backing, DomainTag, KeyStore, Rng, RngError, Separation};
use tradr_identity::SoftwareKeyStore;

/// A deterministic byte stream, so "same seed, same key" is a testable
/// claim. Counter-based rather than a constant byte: an implementation may
/// reject-sample a scalar, and a constant stream would make that loop.
struct SeededRng {
    state: Cell<u64>,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self {
            state: Cell::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
        }
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        for slot in buf.iter_mut() {
            let mut x = self.state.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state.set(x);
            *slot = (x >> 24) as u8;
        }
        Ok(())
    }
}

/// Succeeds while returning a constant that P-256 always rejects, which is
/// what a stuck hardware source or a misconfigured stub looks like. Gives up
/// after `LIMIT` calls so the test terminates whatever the implementation
/// does, and counts calls so the test can tell which of the two ended it.
struct StuckRng {
    calls: Cell<usize>,
}

impl StuckRng {
    const LIMIT: usize = 4096;

    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }
}

impl Rng for StuckRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() >= Self::LIMIT {
            return Err(RngError::Source("stuck source exhausted".into()));
        }
        buf.fill(0x00);
        Ok(())
    }
}

/// Reports failure on every call, to prove generation propagates it rather
/// than falling back to anything.
struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _buf: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::Source("no entropy source".into()))
    }
}

fn store(seed: u64) -> SoftwareKeyStore {
    match SoftwareKeyStore::generate(&SeededRng::new(seed)) {
        Ok(s) => s,
        Err(e) => panic!("generation from a working rng must succeed, got {e}"),
    }
}

fn identity_of(store: &SoftwareKeyStore) -> tradr_core::PublicIdentity {
    match store.public_identity() {
        Ok(id) => id,
        Err(e) => panic!("public_identity must succeed, got {e}"),
    }
}

// Built from the tag rather than from a literal, so a test cannot agree
// with a wrong implementation by having been written against the same
// mistake. The pure half of this is crates/tradr-core/tests/domain_tag.rs.
fn signed_payload(domain: DomainTag, message: &[u8]) -> Vec<u8> {
    match domain.payload(message) {
        Ok(payload) => payload.into_owned(),
        Err(e) => panic!("payload must succeed for a well-formed message, got {e}"),
    }
}

// A message each tag accepts: the four tagged ones take anything, and the
// two structural ones must arrive already carrying their own preamble.
fn well_formed_message(domain: DomainTag) -> Vec<u8> {
    match domain.separation() {
        Separation::Prepended(_) => b"message".to_vec(),
        Separation::Required(required) => {
            let mut message = required.to_vec();
            message.extend_from_slice(b"the rest of the structure");
            message
        }
    }
}

// Verifies through `p256` rather than through the crate under test.
fn verifies(store: &SoftwareKeyStore, domain: DomainTag, message: &[u8], signature: &[u8]) -> bool {
    let identity = identity_of(store);
    let Ok(key) = VerifyingKey::from_sec1_bytes(identity.identity_pub().as_bytes()) else {
        panic!("identity_pub must be a valid SEC-1 point");
    };
    let Ok(parsed) = P256Signature::from_slice(signature) else {
        return false;
    };
    key.verify(&signed_payload(domain, message), &parsed)
        .is_ok()
}

fn sign(store: &SoftwareKeyStore, domain: DomainTag, message: &[u8]) -> Vec<u8> {
    match store.sign(domain, message) {
        Ok(sig) => sig.as_bytes().to_vec(),
        Err(e) => panic!("signing must succeed, got {e}"),
    }
}

// --- Generation ---------------------------------------------------------

#[test]
fn the_same_seed_produces_the_same_identity() {
    // The injected Rng must be the only source of entropy. A generator that
    // also reaches for the clock or the OS would fail this.
    assert_eq!(identity_of(&store(7)), identity_of(&store(7)));
}

#[test]
fn different_seeds_produce_different_identities() {
    // The complement: a hardcoded key would satisfy the test above alone.
    assert_ne!(identity_of(&store(7)), identity_of(&store(8)));
}

#[test]
fn both_public_keys_are_uncompressed_sec1_points() {
    let identity = identity_of(&store(1));
    for point in [identity.identity_pub(), identity.agreement_pub()] {
        let bytes = point.as_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04, "uncompressed SEC-1 starts with 0x04");
        assert!(
            VerifyingKey::from_sec1_bytes(bytes).is_ok(),
            "the point must be on the curve"
        );
    }
}

#[test]
fn the_identity_and_agreement_keys_are_distinct() {
    // One key used for both signing and ECDH is a known cryptographic
    // error, and nothing else in this suite would notice it.
    let identity = identity_of(&store(3));
    assert_ne!(identity.identity_pub(), identity.agreement_pub());
}

#[test]
fn the_device_id_is_the_blake3_prefix_of_the_identity_key() {
    // CONTEXT.md: the first 16 bytes of BLAKE3 over the 65-byte point.
    // Computed here independently of the implementation.
    let identity = identity_of(&store(11));
    let expected = blake3::hash(identity.identity_pub().as_bytes());
    assert_eq!(
        identity.device_id().as_bytes(),
        &expected.as_bytes()[..16],
        "device id must be BLAKE3(identity_pub) truncated to 16 bytes"
    );
}

#[test]
fn generation_fails_when_the_rng_fails() {
    // The one outcome that must never happen quietly: a key that exists
    // because randomness did not.
    assert!(
        SoftwareKeyStore::generate(&FailingRng).is_err(),
        "a failing rng must produce an error, never a fallback key"
    );
}

#[test]
fn generation_gives_up_rather_than_retrying_forever() {
    // An all-zero scalar is rejected by P-256, so a source stuck at 0x00
    // never yields a key. Rejection sampling must be bounded: unbounded, a
    // stuck source hangs the caller with no diagnostic, which in the UI is
    // an application that never finishes starting.
    let rng = StuckRng::new();
    let result = SoftwareKeyStore::generate(&rng);

    assert!(
        result.is_err(),
        "a source that never yields a key must fail"
    );
    assert!(
        rng.calls.get() < StuckRng::LIMIT,
        "generation made {} draws and only stopped because the source gave up; \
         the retry loop must bound itself",
        rng.calls.get()
    );
}

// --- Signing ------------------------------------------------------------

#[test]
fn a_signature_verifies_under_every_one_of_the_six_contexts() {
    for domain in DomainTag::ALL {
        let s = store(5);
        let message = well_formed_message(*domain);
        let signature = sign(&s, *domain, &message);
        assert!(
            verifies(&s, *domain, &message, &signature),
            "{domain:?} signature must verify against identity_pub"
        );
    }
}

#[test]
fn a_structural_context_signs_the_message_with_nothing_added() {
    // A peer checking the certificate reconstructs the TBS bytes and
    // nothing else, so a store that prepends anything here produces a
    // signature no peer can verify, surfacing as a handshake that never
    // completes rather than as anything naming the cause.
    let s = store(5);
    let tbs = well_formed_message(DomainTag::CertificateTbs);
    let signature = sign(&s, DomainTag::CertificateTbs, &tbs);

    let identity = identity_of(&s);
    let Ok(key) = VerifyingKey::from_sec1_bytes(identity.identity_pub().as_bytes()) else {
        panic!("identity_pub must be a valid SEC-1 point");
    };
    let Ok(parsed) = P256Signature::from_slice(&signature) else {
        panic!("a signature must be 64 raw bytes");
    };

    assert!(
        key.verify(&tbs, &parsed).is_ok(),
        "the signature must be over the TBS bytes exactly as given"
    );
}

#[test]
fn signing_is_refused_when_a_structural_context_has_no_preamble() {
    let s = store(5);

    for domain in [DomainTag::CertificateTbs, DomainTag::TlsCertificateVerify] {
        assert!(
            s.sign(domain, b"opaque bytes somebody handed me").is_err(),
            "{domain:?} must refuse a message that carries no separation"
        );
    }
}

#[test]
fn a_structural_context_refuses_a_tagged_contexts_message() {
    // What stops the two prefixless contexts from becoming the escape
    // hatch docs/05 says the closed set exists to prevent.
    let s = store(5);
    let mut borrowed = b"tradr-hello-v1".to_vec();
    borrowed.extend_from_slice(b"a peer's nonce");

    assert!(
        s.sign(DomainTag::CertificateTbs, &borrowed).is_err(),
        "a Hello message must not be signable as a certificate"
    );
}

#[test]
fn a_structural_signature_does_not_verify_under_a_tagged_context() {
    let s = store(5);
    let tbs = well_formed_message(DomainTag::CertificateTbs);
    let signature = sign(&s, DomainTag::CertificateTbs, &tbs);

    assert!(
        !verifies(&s, DomainTag::Hello, &tbs, &signature),
        "a certificate signature must not verify as a Hello signature"
    );
}

#[test]
fn a_signature_does_not_verify_under_another_domain_tag() {
    // DCR-009's whole defence: a Brokr handing a device a peer's Hello
    // nonce as a registration challenge must not collect a reusable answer.
    let s = store(5);
    let signature = sign(&s, DomainTag::Hello, b"nonce");
    assert!(
        !verifies(&s, DomainTag::BrokrChallenge, b"nonce", &signature),
        "a Hello signature must not verify as a Brokr challenge"
    );
    assert!(
        !verifies(&s, DomainTag::KeyBind, b"nonce", &signature),
        "a Hello signature must not verify as a key binding"
    );
}

#[test]
fn every_domain_tag_produces_a_different_signature_over_one_message() {
    // Begins with DER's 0x30, so five of the six tags accept it: the four
    // that prepend, and CertificateTbs. No message reaches all six, since
    // the two structural tags require first bytes that exclude each other,
    // and the sixth is asserted to refuse it rather than left out.
    let message = [0x30u8, 0x82, 0x01, 0x0a, 0x02, 0x03];
    let s = store(5);
    let mut seen = std::collections::HashSet::new();

    for domain in [
        DomainTag::KeyBind,
        DomainTag::Hello,
        DomainTag::BrokrChallenge,
        DomainTag::Revoke,
        DomainTag::CertificateTbs,
    ] {
        assert!(
            seen.insert(sign(&s, domain, &message)),
            "{domain:?} produced a signature already seen under another tag"
        );
    }

    assert!(
        s.sign(DomainTag::TlsCertificateVerify, &message).is_err(),
        "no single message is well formed for both structural tags"
    );
}

#[test]
fn a_signature_is_sixty_four_raw_bytes() {
    // docs/05: r || s, 32 bytes each, never DER. A fixed length is what
    // makes a length check a real check.
    assert_eq!(sign(&store(5), DomainTag::Hello, b"m").len(), 64);
}

#[test]
fn signing_an_empty_message_works() {
    let s = store(5);
    let signature = sign(&s, DomainTag::Revoke, b"");
    assert!(verifies(&s, DomainTag::Revoke, b"", &signature));
}

#[test]
fn two_signatures_over_different_messages_do_not_share_a_nonce() {
    // The sharpest edge in the design, docs/05: two ECDSA signatures made
    // under one nonce expose the private key. An implementation drawing its
    // nonce from the injected Rng looks correct and passes every other test
    // here, because this Rng is deterministic. r is the first 32 bytes.
    let s = store(5);
    let first = sign(&s, DomainTag::Hello, b"message one");
    let second = sign(&s, DomainTag::Hello, b"message two");
    assert_ne!(
        &first[..32],
        &second[..32],
        "equal r means one nonce signed both messages, which leaks the key"
    );
}

#[test]
fn the_signature_scalar_is_normalized_to_the_lower_half() {
    // docs/05: (r, s) and (r, n - s) both verify, so one signature must not
    // have two valid spellings.
    let s = store(5);
    for message in [b"a".as_slice(), b"b", b"c", b"d", b"e"] {
        let signature = sign(&s, DomainTag::Hello, message);
        let Ok(parsed) = P256Signature::from_slice(&signature) else {
            panic!("a signature must parse as 64-byte r || s");
        };
        assert!(
            parsed.normalize_s().is_none(),
            "s must already be in the lower half of the curve order"
        );
    }
}

// --- Agreement ----------------------------------------------------------

#[test]
fn agreement_is_symmetric_between_two_devices() {
    let a = store(21);
    let b = store(22);
    let a_id = identity_of(&a);
    let b_id = identity_of(&b);

    let Ok(from_a) = a.agree(b_id.agreement_pub()) else {
        panic!("agreement must succeed on a valid point");
    };
    let Ok(from_b) = b.agree(a_id.agreement_pub()) else {
        panic!("agreement must succeed on a valid point");
    };

    assert_eq!(from_a.as_bytes(), from_b.as_bytes());
}

#[test]
fn agreement_with_different_peers_yields_different_secrets() {
    let a = store(21);
    let b_id = identity_of(&store(22));
    let c_id = identity_of(&store(23));

    let (Ok(with_b), Ok(with_c)) = (a.agree(b_id.agreement_pub()), a.agree(c_id.agreement_pub()))
    else {
        panic!("agreement must succeed on valid points");
    };

    assert_ne!(with_b.as_bytes(), with_c.as_bytes());
}

#[test]
fn agreement_uses_the_agreement_key_and_not_the_identity_key() {
    // Detects the substitution without seeing any private key. Correct:
    // a_agreement x B_identity and b_agreement x A_identity are unrelated.
    // Wrong, using the identity key for both: both sides compute
    // a_identity x b_identity, and ECDH symmetry makes them equal.
    let a = store(31);
    let b = store(32);
    let a_id = identity_of(&a);
    let b_id = identity_of(&b);

    let (Ok(from_a), Ok(from_b)) = (a.agree(b_id.identity_pub()), b.agree(a_id.identity_pub()))
    else {
        panic!("agreement must succeed on valid points");
    };

    assert_ne!(
        from_a.as_bytes(),
        from_b.as_bytes(),
        "equal here means agree used the identity key, not the agreement key"
    );
}

#[test]
fn agreement_rejects_a_point_that_is_not_on_the_curve() {
    // An invalid-curve attack recovers a private key from the results of
    // agreeing with crafted points, so this must be an error and never a
    // secret computed anyway.
    let a = store(21);
    let mut bytes = *identity_of(&store(22)).agreement_pub().as_bytes();
    bytes[40] ^= 0xff;
    let Ok(off_curve) = tradr_core::PublicKeyPoint::from_bytes(&bytes) else {
        panic!("the type accepts any 65 bytes; the curve check belongs here");
    };

    assert!(
        a.agree(&off_curve).is_err(),
        "a point off the curve must be rejected, not agreed with"
    );
}

#[test]
fn agreement_rejects_the_point_at_infinity() {
    let a = store(21);
    let Ok(zero) = tradr_core::PublicKeyPoint::from_bytes(&[0u8; 65]) else {
        panic!("the type accepts any 65 bytes");
    };

    assert!(a.agree(&zero).is_err());
}

// --- Backing and non-leakage --------------------------------------------

#[test]
fn a_software_store_never_claims_hardware_backing() {
    // ADR-0011: backing() exists so the UI states the truth rather than
    // assuming it. A software store claiming Hardware is a silent lie.
    match store(1).backing() {
        Backing::Software(_) => {}
        Backing::Hardware => panic!("a software key store must not report Hardware"),
    }
}

#[test]
fn the_debug_representation_reveals_nothing_derived_from_the_key() {
    // Two stores with different keys must format identically. A Debug that
    // reveals nothing is the only one that cannot reveal too much, and the
    // public half is reachable through public_identity for anyone wanting it.
    assert_eq!(format!("{:?}", store(41)), format!("{:?}", store(42)));
}

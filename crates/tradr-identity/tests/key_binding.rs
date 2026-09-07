//! Supervisor-authored tests for the `KeyBinding` verifier port, written
//! before the implementation (CLAUDE.md section 6). Noise authenticates the
//! *agreement* key and `SecureChannel::peer` answers with a `DeviceId` over
//! the *identity* key; this port is the only thing joining the two, and a
//! join that accepts the wrong binding names the wrong device (ADR-0020).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tradr_core::{
    Clock, DeviceId, KeyBinding, KeyBindingRefused, KeyBindingVerifier, Monotonic, PublicKeyPoint,
    Signature, UnixTime,
};
use tradr_identity::key_binding::{ClockKeyBindingVerifier, verify_key_binding};

// ---- Fixtures ----------------------------------------------------------

// A device: an identity key that signs and an agreement key that is signed
// over. Both are fixed, so a failure reproduces.
struct Device {
    identity: p256::SecretKey,
    agreement: p256::SecretKey,
}

impl Device {
    fn new(seed: u8) -> Self {
        Self {
            identity: secret_key(seed),
            agreement: secret_key(seed.wrapping_add(128)),
        }
    }

    fn identity_pub(&self) -> PublicKeyPoint {
        point(&self.identity)
    }

    fn agreement_pub(&self) -> PublicKeyPoint {
        point(&self.agreement)
    }

    fn device_id(&self) -> DeviceId {
        let digest = blake3::hash(self.identity_pub().as_bytes());
        DeviceId::from_identity_digest(digest.as_bytes())
    }

    // The binding this device would publish: its identity key over
    // "tradr-keybind-v1" || its own agreement key (docs/04, check 3).
    fn binding(&self, not_after: i64) -> KeyBinding {
        self.binding_over(&self.agreement_pub(), not_after)
    }

    // A binding whose signature really covers `covered`, so a test can put a
    // valid signature over the wrong key rather than a broken one.
    fn binding_over(&self, covered: &PublicKeyPoint, not_after: i64) -> KeyBinding {
        KeyBinding::new(
            covered.clone(),
            keybind_signature(&self.identity, covered),
            UnixTime::from_secs(not_after),
        )
    }
}

fn secret_key(seed: u8) -> p256::SecretKey {
    let mut bytes = [seed; 32];
    bytes[0] = seed | 1;
    p256::SecretKey::from_bytes(&bytes.into()).expect("a non-zero scalar under the order")
}

fn point(secret: &p256::SecretKey) -> PublicKeyPoint {
    let encoded = secret.public_key().to_encoded_point(false);
    PublicKeyPoint::from_bytes(encoded.as_bytes()).expect("an uncompressed P-256 point is 65 bytes")
}

// Signs the way docs/05's domain tag table says, through `p256` directly and
// not through the code under test.
fn keybind_signature(identity: &p256::SecretKey, covered: &PublicKeyPoint) -> Signature {
    let signing = SigningKey::from(identity);
    let mut payload = b"tradr-keybind-v1".to_vec();
    payload.extend_from_slice(covered.as_bytes());
    let raw: P256Signature = signing.sign(&payload);
    let normalized = raw.normalize_s().unwrap_or(raw);
    Signature::from_bytes(normalized.to_bytes().to_vec())
}

struct FixedClock(AtomicI64);

impl FixedClock {
    fn at(secs: i64) -> Self {
        Self(AtomicI64::new(secs))
    }

    fn advance_to(&self, secs: i64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.0.load(Ordering::SeqCst))
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(Instant::now())
    }
}

const NOW: i64 = 1_800_000_000;
const LATER: i64 = NOW + 30 * 24 * 3600;

// ---- The function -------------------------------------------------------

#[test]
fn a_good_binding_yields_the_device_id_of_the_identity_key() {
    let device = Device::new(3);

    let joined = verify_key_binding(
        &device.identity_pub(),
        &device.binding(LATER),
        &device.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect("a binding this device signed over its own agreement key verifies");

    assert_eq!(joined, device.device_id());
}

#[test]
fn the_device_id_is_blake3_of_the_identity_key_and_never_of_the_agreement_key() {
    let device = Device::new(7);

    let joined = verify_key_binding(
        &device.identity_pub(),
        &device.binding(LATER),
        &device.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect("verifies");

    let from_agreement =
        DeviceId::from_identity_digest(blake3::hash(device.agreement_pub().as_bytes()).as_bytes());
    assert_ne!(
        joined, from_agreement,
        "a DeviceId derived from the agreement key is the defect this port exists to prevent"
    );
}

#[test]
fn a_binding_covering_another_key_than_the_channel_authenticated_is_refused() {
    // The attack: an attacker holds its own agreement key, completes the
    // Noise handshake with it, and replays a victim's identity key together
    // with the victim's genuine binding. Every signature in that message is
    // valid; the only thing that refuses it is the covered-key comparison.
    let victim = Device::new(3);
    let attacker = Device::new(9);

    let refusal = verify_key_binding(
        &victim.identity_pub(),
        &victim.binding(LATER),
        &attacker.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("a binding over the victim's key does not join the attacker's");

    assert_eq!(refusal, KeyBindingRefused::NotForThisAgreementKey);
}

#[test]
fn a_binding_signed_by_another_identity_key_is_refused() {
    // The covered key is right and the signer is not: an attacker signing
    // over the key it really holds, while claiming the victim's identity.
    let victim = Device::new(3);
    let attacker = Device::new(9);
    let forged = attacker.binding_over(&attacker.agreement_pub(), LATER);

    let refusal = verify_key_binding(
        &victim.identity_pub(),
        &forged,
        &attacker.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("the victim's identity key did not sign this");

    assert_eq!(refusal, KeyBindingRefused::SignatureInvalid);
}

#[test]
fn a_signature_over_the_key_without_the_domain_tag_is_refused() {
    // docs/05: every signature carries a domain tag. A binding verified
    // against the bare agreement key would accept a signature minted for
    // another purpose over the same bytes.
    let device = Device::new(3);
    let signing = SigningKey::from(&device.identity);
    let raw: P256Signature = signing.sign(device.agreement_pub().as_bytes());
    let untagged = KeyBinding::new(
        device.agreement_pub(),
        Signature::from_bytes(raw.normalize_s().unwrap_or(raw).to_bytes().to_vec()),
        UnixTime::from_secs(LATER),
    );

    let refusal = verify_key_binding(
        &device.identity_pub(),
        &untagged,
        &device.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("an untagged signature is not a KeyBinding");

    assert_eq!(refusal, KeyBindingRefused::SignatureInvalid);
}

#[test]
fn a_binding_whose_not_after_has_passed_is_refused() {
    let device = Device::new(3);

    let refusal = verify_key_binding(
        &device.identity_pub(),
        &device.binding(NOW - 1),
        &device.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("an expired binding is refused");

    assert_eq!(
        refusal,
        KeyBindingRefused::Expired {
            not_after: UnixTime::from_secs(NOW - 1),
            now: UnixTime::from_secs(NOW),
        }
    );
}

#[test]
fn a_binding_expiring_exactly_now_is_still_valid() {
    // docs/04 refuses when `not_after` is *before* now, which is the
    // comparison `on_peer_hello` already makes. An off-by-one here rejects a
    // binding on the second it was still good for.
    let device = Device::new(3);

    verify_key_binding(
        &device.identity_pub(),
        &device.binding(NOW),
        &device.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect("a binding is valid up to and including not_after");
}

#[test]
fn an_identity_key_that_is_not_a_p256_point_is_refused() {
    let device = Device::new(3);
    let mut bytes = *device.identity_pub().as_bytes();
    bytes[1] ^= 0xff;
    let bogus = PublicKeyPoint::from_bytes(&bytes).expect("65 bytes with a 0x04 prefix");

    let refusal = verify_key_binding(
        &bogus,
        &device.binding(LATER),
        &device.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("a point that is not on the curve verifies nothing");

    assert_eq!(refusal, KeyBindingRefused::MalformedIdentityKey);
}

#[test]
fn the_covered_key_is_compared_before_the_signature_is_verified() {
    // Cheapest first, the order docs/04 states for check 3. A binding that
    // is wrong in both ways must report the comparison, not the signature.
    let victim = Device::new(3);
    let attacker = Device::new(9);
    let forged = attacker.binding_over(&victim.agreement_pub(), LATER);

    let refusal = verify_key_binding(
        &victim.identity_pub(),
        &forged,
        &attacker.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("wrong covered key and wrong signer");

    assert_eq!(refusal, KeyBindingRefused::NotForThisAgreementKey);
}

#[test]
fn the_signature_is_verified_before_expiry_is_consulted() {
    // The same ordering rule one step further along: an expired binding
    // whose signature is also forged reports the signature.
    let victim = Device::new(3);
    let attacker = Device::new(9);
    let forged = attacker.binding_over(&attacker.agreement_pub(), NOW - 1);

    let refusal = verify_key_binding(
        &victim.identity_pub(),
        &forged,
        &attacker.agreement_pub(),
        UnixTime::from_secs(NOW),
    )
    .expect_err("forged and expired");

    assert_eq!(refusal, KeyBindingRefused::SignatureInvalid);
}

// ---- The port -----------------------------------------------------------

#[test]
fn the_port_reads_its_clock_at_the_moment_of_the_join() {
    // One verifier, one clock, two calls. A verifier that read the time at
    // construction would answer the same both times, and would go on
    // accepting a binding that expired while the process ran.
    let device = Device::new(3);
    let binding = device.binding(NOW);
    let clock = Arc::new(FixedClock::at(NOW));
    let verifier = ClockKeyBindingVerifier::new(Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>);

    assert_eq!(
        verifier
            .device_id_for_agreement_key(&device.identity_pub(), &binding, &device.agreement_pub())
            .expect("valid at not_after"),
        device.device_id()
    );

    clock.advance_to(NOW + 1);
    assert!(matches!(
        verifier.device_id_for_agreement_key(
            &device.identity_pub(),
            &binding,
            &device.agreement_pub()
        ),
        Err(KeyBindingRefused::Expired { .. })
    ));
}

#[test]
fn the_port_refuses_everything_the_function_refuses() {
    let victim = Device::new(3);
    let attacker = Device::new(9);
    let verifier = ClockKeyBindingVerifier::new(Arc::new(FixedClock::at(NOW)));

    assert_eq!(
        verifier
            .device_id_for_agreement_key(
                &victim.identity_pub(),
                &victim.binding(LATER),
                &attacker.agreement_pub()
            )
            .expect_err("the port is not a second implementation"),
        KeyBindingRefused::NotForThisAgreementKey
    );
}

#[test]
fn the_port_is_usable_behind_a_trait_object() {
    // The transport is constructed with `Arc<dyn KeyBindingVerifier>`, which
    // needs `Send + Sync`. This fails to compile rather than to assert.
    let device = Device::new(3);
    let verifier: Arc<dyn KeyBindingVerifier> =
        Arc::new(ClockKeyBindingVerifier::new(Arc::new(FixedClock::at(NOW))));
    let moved = Arc::clone(&verifier);
    let joined = std::thread::spawn(move || {
        moved.device_id_for_agreement_key(
            &device.identity_pub(),
            &device.binding(LATER),
            &device.agreement_pub(),
        )
    })
    .join()
    .expect("the thread does not panic")
    .expect("verifies");

    assert_eq!(joined, Device::new(3).device_id());
}

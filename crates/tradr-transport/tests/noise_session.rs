//! Supervisor-written specification for `WI-M7-007b` (CLAUDE.md section 6).
//! Critical because Noise authenticates the *agreement* key while `peer()`
//! answers with a `DeviceId` over the *identity* key (ADR-0020): a join that
//! accepts a binding the handshake did not authenticate names the wrong
//! device, and every signature checked after it is perfectly valid.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tradr_core::{
    Backing, DeviceId, DomainTag, KeyBinding, KeyBindingRefused, KeyBindingVerifier, KeyStore,
    KeyStoreError, PublicIdentity, PublicKeyPoint, Rng, RngError, SharedSecret, Signature,
    SoftwareReason, UnixTime,
};
use tradr_transport::noise::{
    IDENTITY_JOIN_LEN, Initiator, MAX_PLAINTEXT_LEN, NoiseError, NoiseSession, Responder,
};

// The largest frame a BLE channel carries (docs/04, "Framing").
const BLE_MAX_FRAME_SIZE: usize = 512;

const NOW: i64 = 1_800_000_000;
const LATER: i64 = NOW + 30 * 24 * 3600;

// A KeyStore over two fixed P-256 scalars, counting the `agree` calls that
// prove the static Diffie-Hellman reached it rather than a software key.
struct CountingKeyStore {
    identity: p256::SecretKey,
    agreement: p256::SecretKey,
    agreements: AtomicUsize,
    refuse_agreement: bool,
}

impl CountingKeyStore {
    fn new(seed: u8) -> Self {
        Self {
            identity: secret_key(seed),
            agreement: secret_key(seed.wrapping_add(128)),
            agreements: AtomicUsize::new(0),
            refuse_agreement: false,
        }
    }

    fn refusing(seed: u8) -> Self {
        Self {
            refuse_agreement: true,
            ..Self::new(seed)
        }
    }

    fn agreements(&self) -> usize {
        self.agreements.load(Ordering::SeqCst)
    }

    fn identity_pub(&self) -> PublicKeyPoint {
        point(&self.identity)
    }

    fn agreement_pub(&self) -> PublicKeyPoint {
        point(&self.agreement)
    }

    fn agreement_scalar(&self) -> [u8; 32] {
        self.agreement.to_bytes().into()
    }

    fn device_id(&self) -> DeviceId {
        DeviceId::from_identity_digest(blake3::hash(self.identity_pub().as_bytes()).as_bytes())
    }

    // The binding this device publishes, over its own agreement key.
    fn binding(&self) -> KeyBinding {
        self.binding_over(&self.agreement_pub(), LATER)
    }

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

// Signs as docs/05's domain tag table says, through `p256` and not through
// the code under test.
fn keybind_signature(identity: &p256::SecretKey, covered: &PublicKeyPoint) -> Signature {
    let signing = SigningKey::from(identity);
    let mut payload = b"tradr-keybind-v1".to_vec();
    payload.extend_from_slice(covered.as_bytes());
    let raw: P256Signature = signing.sign(&payload);
    let normalized = raw.normalize_s().unwrap_or(raw);
    Signature::from_bytes(normalized.to_bytes().to_vec())
}

impl KeyStore for CountingKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        Ok(PublicIdentity::new(
            self.identity_pub(),
            self.agreement_pub(),
            self.device_id(),
        ))
    }

    fn sign(&self, _domain: DomainTag, _message: &[u8]) -> Result<Signature, KeyStoreError> {
        Ok(Signature::from_bytes(Vec::new()))
    }

    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        self.agreements.fetch_add(1, Ordering::SeqCst);
        if self.refuse_agreement {
            return Err(KeyStoreError::Backend(
                "this key store refuses to agree".into(),
            ));
        }
        let peer = p256::PublicKey::from_sec1_bytes(peer_public.as_bytes())
            .map_err(|_| KeyStoreError::Backend("peer point is not on P-256".into()))?;
        let shared =
            p256::ecdh::diffie_hellman(self.agreement.to_nonzero_scalar(), peer.as_affine());
        Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
    }

    fn backing(&self) -> Backing {
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    }
}

// A counter source: deterministic so a failure reproduces, and distinct per
// call so two handshakes cannot share an ephemeral key.
struct CounterRng {
    next: Mutex<u64>,
    refuse: bool,
}

impl CounterRng {
    fn new() -> Self {
        Self {
            next: Mutex::new(1),
            refuse: false,
        }
    }

    fn refusing() -> Self {
        Self {
            next: Mutex::new(1),
            refuse: true,
        }
    }
}

impl Rng for CounterRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        if self.refuse {
            return Err(RngError::Source("this source refuses to fill".into()));
        }
        let mut next = self.next.lock().expect("no test poisons this lock");
        for byte in buf.iter_mut() {
            *next = next.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *byte = (*next >> 33) as u8;
        }
        Ok(())
    }
}

// `tradr-transport` may not name `tradr-identity` (ci/layer-deps.sh rule 4),
// so the port arrives here as a test double that runs docs/04's check 3
// through `p256` directly. What the transport owes is that it consults the
// port and reports what it says; whether `tradr-identity`'s implementation
// is right is that crate's own specification.
struct TestVerifier {
    now: i64,
}

impl KeyBindingVerifier for TestVerifier {
    fn device_id_for_agreement_key(
        &self,
        identity_pub: &PublicKeyPoint,
        binding: &KeyBinding,
        authenticated_agreement_pub: &PublicKeyPoint,
    ) -> Result<DeviceId, KeyBindingRefused> {
        if binding.agreement_pub() != authenticated_agreement_pub {
            return Err(KeyBindingRefused::NotForThisAgreementKey);
        }
        let key = VerifyingKey::from_sec1_bytes(identity_pub.as_bytes())
            .map_err(|_| KeyBindingRefused::MalformedIdentityKey)?;
        let mut payload = b"tradr-keybind-v1".to_vec();
        payload.extend_from_slice(binding.agreement_pub().as_bytes());
        let raw = P256Signature::from_slice(binding.signature().as_bytes())
            .map_err(|_| KeyBindingRefused::SignatureInvalid)?;
        key.verify(&payload, &raw)
            .map_err(|_| KeyBindingRefused::SignatureInvalid)?;
        let now = UnixTime::from_secs(self.now);
        if binding.not_after() < now {
            return Err(KeyBindingRefused::Expired {
                not_after: binding.not_after(),
                now,
            });
        }
        Ok(DeviceId::from_identity_digest(
            blake3::hash(identity_pub.as_bytes()).as_bytes(),
        ))
    }
}

fn verifier_at(now: i64) -> Arc<dyn KeyBindingVerifier> {
    Arc::new(TestVerifier { now })
}

struct Pair {
    initiator_store: Arc<CountingKeyStore>,
    responder_store: Arc<CountingKeyStore>,
    rng: Arc<CounterRng>,
    verifier: Arc<dyn KeyBindingVerifier>,
}

impl Pair {
    fn new() -> Self {
        Self {
            initiator_store: Arc::new(CountingKeyStore::new(3)),
            responder_store: Arc::new(CountingKeyStore::new(5)),
            rng: Arc::new(CounterRng::new()),
            verifier: verifier_at(NOW),
        }
    }

    fn initiator(&self) -> Initiator {
        self.initiator_with(self.initiator_store.binding())
    }

    fn initiator_with(&self, binding: KeyBinding) -> Initiator {
        Initiator::new(
            Arc::clone(&self.initiator_store) as Arc<dyn KeyStore>,
            Arc::clone(&self.rng) as Arc<dyn Rng + Send + Sync>,
            Arc::clone(&self.verifier),
            binding,
        )
        .expect("an initiator builds from a working key store and its own binding")
    }

    fn responder(&self) -> Responder {
        self.responder_with(self.responder_store.binding())
    }

    fn responder_with(&self, binding: KeyBinding) -> Responder {
        Responder::new(
            Arc::clone(&self.responder_store) as Arc<dyn KeyStore>,
            Arc::clone(&self.rng) as Arc<dyn Rng + Send + Sync>,
            Arc::clone(&self.verifier),
            binding,
        )
        .expect("a responder builds from a working key store and its own binding")
    }
}

// The three messages of one complete handshake, with both sessions.
struct Handshake {
    initiator: NoiseSession,
    responder: NoiseSession,
    first: Vec<u8>,
    second: Vec<u8>,
    third: Vec<u8>,
}

fn handshake(pair: &Pair) -> Handshake {
    let (awaiting_response, first) = pair
        .initiator()
        .write_first()
        .expect("the first message is written");
    let (awaiting_confirmation, second) = pair
        .responder()
        .read_first(&first)
        .expect("the responder reads the first message")
        .write_second()
        .expect("the second message is written");
    let (initiator, third) = awaiting_response
        .read_second(&second)
        .expect("the initiator reads the second message")
        .write_third()
        .expect("the third message is written");
    let responder = awaiting_confirmation
        .read_third(&third)
        .expect("the responder reads the third message");
    Handshake {
        initiator,
        responder,
        first,
        second,
        third,
    }
}

// ---- The handshake ------------------------------------------------------

#[test]
fn a_full_handshake_lets_both_sides_exchange_a_message() {
    let pair = Pair::new();
    let mut hs = handshake(&pair);

    let to_responder = hs
        .initiator
        .encrypt(b"from the initiator")
        .expect("encrypts");
    assert_eq!(
        hs.responder.decrypt(&to_responder).expect("decrypts"),
        b"from the initiator"
    );

    let to_initiator = hs
        .responder
        .encrypt(b"from the responder")
        .expect("encrypts");
    assert_eq!(
        hs.initiator.decrypt(&to_initiator).expect("decrypts"),
        b"from the responder"
    );
}

#[test]
fn each_side_answers_peer_with_the_other_device_id() {
    let pair = Pair::new();
    let hs = handshake(&pair);

    assert_eq!(hs.initiator.peer(), pair.responder_store.device_id());
    assert_eq!(hs.responder.peer(), pair.initiator_store.device_id());
}

#[test]
fn peer_is_derived_from_the_identity_key_and_never_from_the_agreement_key() {
    // The defect this module exists to prevent: a `DeviceId` taken from the
    // key Noise authenticated is a valid handshake naming the wrong device.
    let pair = Pair::new();
    let hs = handshake(&pair);

    let from_agreement = DeviceId::from_identity_digest(
        blake3::hash(pair.responder_store.agreement_pub().as_bytes()).as_bytes(),
    );
    assert_ne!(hs.initiator.peer(), from_agreement);
}

#[test]
fn each_side_holds_the_agreement_key_the_handshake_authenticated() {
    let pair = Pair::new();
    let hs = handshake(&pair);

    assert_eq!(
        hs.initiator.peer_agreement_pub(),
        &pair.responder_store.agreement_pub()
    );
    assert_eq!(
        hs.responder.peer_agreement_pub(),
        &pair.initiator_store.agreement_pub()
    );
}

#[test]
fn every_static_diffie_hellman_reaches_the_key_store() {
    let pair = Pair::new();
    let _ = handshake(&pair);

    assert!(
        pair.initiator_store.agreements() > 0,
        "the initiator's static key must be exercised through KeyStore::agree"
    );
    assert!(
        pair.responder_store.agreements() > 0,
        "the responder's static key must be exercised through KeyStore::agree"
    );
}

#[test]
fn all_three_messages_fit_one_ble_frame() {
    let pair = Pair::new();
    let hs = handshake(&pair);

    for (name, message) in [
        ("first", &hs.first),
        ("second", &hs.second),
        ("third", &hs.third),
    ] {
        assert!(
            message.len() <= BLE_MAX_FRAME_SIZE,
            "the {name} message is {} bytes",
            message.len()
        );
    }
}

#[test]
fn the_identity_join_is_the_length_the_design_counted() {
    // ADR-0020 counts 137 bytes: identity_pub 65, signature 64, not_after 8.
    // The constant is what the message sizes in that ADR were derived from.
    assert_eq!(IDENTITY_JOIN_LEN, 137);
}

// ---- The identity join --------------------------------------------------

#[test]
fn a_responder_replaying_another_devices_join_is_refused_by_the_initiator() {
    // The substitution, staged where it can actually be staged: our own
    // constructors refuse a binding this device does not hold, so the
    // impostor is a reference peer. It completes the handshake with its own
    // static key and presents a victim's identity together with the
    // victim's genuine signature over the victim's agreement key.
    let pair = Pair::new();
    let attacker = CountingKeyStore::new(9);
    let victim = CountingKeyStore::new(11);
    let scalar = attacker.agreement_scalar();
    let mut reference = reference_builder(&scalar)
        .build_responder()
        .expect("builds");

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference.read_message(&first, &mut scratch).expect("reads");
    let mut second = vec![0u8; 65535];
    let len = reference
        .write_message(&identity_join(&victim), &mut second)
        .expect("writes");

    // The covered key is never on the wire: it is the key Noise
    // authenticated, so the comparison cannot fail and the signature is what
    // refuses the substitution (ADR-0020).
    assert!(matches!(
        awaiting_response.read_second(&second[..len]),
        Err(NoiseError::PeerKeyBinding(
            KeyBindingRefused::SignatureInvalid
        ))
    ));
}

#[test]
fn an_initiator_replaying_another_devices_join_is_refused_by_the_responder() {
    let pair = Pair::new();
    let attacker = CountingKeyStore::new(9);
    let victim = CountingKeyStore::new(11);
    let scalar = attacker.agreement_scalar();
    let mut reference = reference_builder(&scalar)
        .build_initiator()
        .expect("builds");

    let mut first = vec![0u8; 65535];
    let len = reference.write_message(&[], &mut first).expect("writes");
    let (awaiting_confirmation, second) = pair
        .responder()
        .read_first(&first[..len])
        .expect("reads")
        .write_second()
        .expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference
        .read_message(&second, &mut scratch)
        .expect("reads");
    let mut third = vec![0u8; 65535];
    let len = reference
        .write_message(&identity_join(&victim), &mut third)
        .expect("writes");

    assert!(matches!(
        awaiting_confirmation.read_third(&third[..len]),
        Err(NoiseError::PeerKeyBinding(
            KeyBindingRefused::SignatureInvalid
        ))
    ));
}

#[test]
fn a_peer_whose_binding_is_signed_by_another_identity_key_is_refused() {
    let pair = Pair::new();
    let forger = CountingKeyStore::new(11);
    let forged = forger.binding_over(&pair.responder_store.agreement_pub(), LATER);

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let (_, second) = pair
        .responder_with(forged)
        .read_first(&first)
        .expect("reads")
        .write_second()
        .expect("writes");

    // The identity key on the wire is the responder's own, so the covered
    // key matches and only the signature refuses.
    assert!(matches!(
        awaiting_response.read_second(&second),
        Err(NoiseError::PeerKeyBinding(
            KeyBindingRefused::SignatureInvalid
        ))
    ));
}

#[test]
fn a_peer_whose_binding_has_expired_is_refused() {
    let pair = Pair::new();
    let stale = pair
        .responder_store
        .binding_over(&pair.responder_store.agreement_pub(), NOW - 1);

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let (_, second) = pair
        .responder_with(stale)
        .read_first(&first)
        .expect("reads")
        .write_second()
        .expect("writes");

    assert!(matches!(
        awaiting_response.read_second(&second),
        Err(NoiseError::PeerKeyBinding(
            KeyBindingRefused::Expired { .. }
        ))
    ));
}

#[test]
fn a_side_constructed_with_a_binding_over_a_key_it_does_not_hold_refuses_to_build() {
    // A local misconfiguration, caught here rather than by the peer: the
    // failure a peer reports is indistinguishable from an attack.
    let stranger = CountingKeyStore::new(11);

    assert!(matches!(
        Initiator::new(
            Arc::new(CountingKeyStore::new(3)) as Arc<dyn KeyStore>,
            Arc::new(CounterRng::new()) as Arc<dyn Rng + Send + Sync>,
            verifier_at(NOW),
            stranger.binding(),
        ),
        Err(NoiseError::LocalKeyBinding)
    ));
    assert!(matches!(
        Responder::new(
            Arc::new(CountingKeyStore::new(3)) as Arc<dyn KeyStore>,
            Arc::new(CounterRng::new()) as Arc<dyn Rng + Send + Sync>,
            verifier_at(NOW),
            stranger.binding(),
        ),
        Err(NoiseError::LocalKeyBinding)
    ));
}

#[test]
fn a_local_binding_whose_signature_is_not_sixty_four_bytes_refuses_to_build() {
    // The join is a fixed 137 bytes with no length prefix, so a signature of
    // any other length would make it a different message. That is a broken
    // local key store, and the peer's refusal for it names the wrong side.
    let store = Arc::new(CountingKeyStore::new(3));
    let short = KeyBinding::new(
        store.agreement_pub(),
        Signature::from_bytes(vec![0u8; 63]),
        UnixTime::from_secs(LATER),
    );

    assert!(matches!(
        Initiator::new(
            Arc::clone(&store) as Arc<dyn KeyStore>,
            Arc::new(CounterRng::new()) as Arc<dyn Rng + Send + Sync>,
            verifier_at(NOW),
            short,
        ),
        Err(NoiseError::LocalKeyBinding)
    ));
}

#[test]
fn the_verifier_is_consulted_rather_than_the_check_being_reimplemented() {
    // A verifier that refuses everything must refuse this handshake. An
    // implementation that verified the binding itself would pass anyway,
    // which is the shape ADR-0020's "one home" rule forbids.
    struct RefuseEverything;
    impl KeyBindingVerifier for RefuseEverything {
        fn device_id_for_agreement_key(
            &self,
            _identity_pub: &PublicKeyPoint,
            _binding: &KeyBinding,
            _authenticated_agreement_pub: &PublicKeyPoint,
        ) -> Result<DeviceId, KeyBindingRefused> {
            Err(KeyBindingRefused::SignatureInvalid)
        }
    }

    let store = Arc::new(CountingKeyStore::new(3));
    let responder_store = Arc::new(CountingKeyStore::new(5));
    let rng = Arc::new(CounterRng::new());
    let refusing: Arc<dyn KeyBindingVerifier> = Arc::new(RefuseEverything);

    let (awaiting_response, first) = Initiator::new(
        Arc::clone(&store) as Arc<dyn KeyStore>,
        Arc::clone(&rng) as Arc<dyn Rng + Send + Sync>,
        Arc::clone(&refusing),
        store.binding(),
    )
    .expect("builds")
    .write_first()
    .expect("writes");
    let (_, second) = Responder::new(
        Arc::clone(&responder_store) as Arc<dyn KeyStore>,
        Arc::clone(&rng) as Arc<dyn Rng + Send + Sync>,
        verifier_at(NOW),
        responder_store.binding(),
    )
    .expect("builds")
    .read_first(&first)
    .expect("reads")
    .write_second()
    .expect("writes");

    assert!(matches!(
        awaiting_response.read_second(&second),
        Err(NoiseError::PeerKeyBinding(
            KeyBindingRefused::SignatureInvalid
        ))
    ));
}

// ---- Malformed messages -------------------------------------------------

#[test]
fn a_truncated_first_message_is_refused() {
    let pair = Pair::new();
    let (_, first) = pair.initiator().write_first().expect("writes");

    assert!(matches!(
        pair.responder().read_first(&first[..first.len() - 1]),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_modified_first_message_is_caught_at_the_second_and_not_before() {
    // `Noise_XX`'s first message is a bare ephemeral key with no tag over it,
    // so it is refused where the key it carried is first used -- the
    // responder computing `ee` for message 2 -- and not where it arrives.
    // Asserting a refusal at `read_first` asserts authentication the pattern
    // does not have, and passing it needs a check in the wrong layer.
    let pair = Pair::new();
    let (_, mut first) = pair.initiator().write_first().expect("writes");
    let last = first.len() - 1;
    first[last] ^= 0x01;

    let Ok(awaiting_reply) = pair.responder().read_first(&first) else {
        panic!("message 1 carries nothing a responder could refuse it by");
    };

    assert!(matches!(
        awaiting_reply.write_second(),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_flipped_bit_in_the_second_message_is_refused() {
    let pair = Pair::new();
    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let (_, mut second) = pair
        .responder()
        .read_first(&first)
        .expect("reads")
        .write_second()
        .expect("writes");
    let last = second.len() - 1;
    second[last] ^= 0x01;

    assert!(matches!(
        awaiting_response.read_second(&second),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_flipped_bit_in_the_third_message_is_refused() {
    let pair = Pair::new();
    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let (awaiting_confirmation, second) = pair
        .responder()
        .read_first(&first)
        .expect("reads")
        .write_second()
        .expect("writes");
    let (_, mut third) = awaiting_response
        .read_second(&second)
        .expect("reads")
        .write_third()
        .expect("writes");
    let last = third.len() - 1;
    third[last] ^= 0x01;

    assert!(matches!(
        awaiting_confirmation.read_third(&third),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_handshake_payload_that_is_not_the_join_length_is_refused() {
    // A reference peer that completes the handshake correctly and sends a
    // payload of the wrong size is a malformed message, not a bad binding.
    let pair = Pair::new();
    let responder_scalar = pair.responder_store.agreement_scalar();
    let mut reference = reference_builder(&responder_scalar)
        .build_responder()
        .expect("builds");

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference.read_message(&first, &mut scratch).expect("reads");

    let mut short = identity_join(&pair.responder_store);
    short.truncate(IDENTITY_JOIN_LEN - 1);
    let mut second = vec![0u8; 65535];
    let len = reference
        .write_message(&short, &mut second)
        .expect("writes");

    assert!(matches!(
        awaiting_response.read_second(&second[..len]),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_handshake_payload_longer_than_the_join_is_refused() {
    // The join has no length prefix because nothing in it is variable, so a
    // peer appending bytes is sending a different message. Accepting it and
    // reading the first 137 bytes would let trailing content pass unread.
    let pair = Pair::new();
    let responder_scalar = pair.responder_store.agreement_scalar();
    let mut reference = reference_builder(&responder_scalar)
        .build_responder()
        .expect("builds");

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference.read_message(&first, &mut scratch).expect("reads");

    let mut long = identity_join(&pair.responder_store);
    long.push(0x00);
    let mut second = vec![0u8; 65535];
    let len = reference.write_message(&long, &mut second).expect("writes");

    assert!(matches!(
        awaiting_response.read_second(&second[..len]),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn an_identity_key_that_is_not_a_point_is_refused_by_the_verifier() {
    // The first 65 bytes are read as a `PublicKeyPoint`, which checks the
    // length and not the curve. Whether they are a point is a cryptographic
    // question and the port answers it, so the transport must report what the
    // port said rather than screening for a `0x04` prefix of its own.
    let pair = Pair::new();
    let responder_scalar = pair.responder_store.agreement_scalar();
    let mut reference = reference_builder(&responder_scalar)
        .build_responder()
        .expect("builds");

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference.read_message(&first, &mut scratch).expect("reads");

    let mut bogus = identity_join(&pair.responder_store);
    bogus[0] = 0x02;
    let mut second = vec![0u8; 65535];
    let len = reference
        .write_message(&bogus, &mut second)
        .expect("writes");

    assert!(matches!(
        awaiting_response.read_second(&second[..len]),
        Err(NoiseError::PeerKeyBinding(
            KeyBindingRefused::MalformedIdentityKey
        ))
    ));
}

// ---- The session --------------------------------------------------------

#[test]
fn a_flipped_bit_in_a_session_message_is_refused() {
    let pair = Pair::new();
    let mut hs = handshake(&pair);

    let mut ciphertext = hs
        .initiator
        .encrypt(b"tampered in flight")
        .expect("encrypts");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(matches!(
        hs.responder.decrypt(&ciphertext),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn two_handshakes_do_not_produce_the_same_session_key() {
    let pair = Pair::new();
    let mut first = handshake(&pair);
    let mut second = handshake(&pair);

    let ciphertext = first
        .initiator
        .encrypt(b"belongs to the first session")
        .expect("encrypts");

    assert!(matches!(
        second.responder.decrypt(&ciphertext),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_plaintext_at_the_ceiling_is_carried_and_one_byte_over_is_refused() {
    let pair = Pair::new();
    let mut hs = handshake(&pair);

    let at_ceiling = vec![0x5a; MAX_PLAINTEXT_LEN];
    let ciphertext = hs
        .initiator
        .encrypt(&at_ceiling)
        .expect("the ceiling is carried");
    assert_eq!(
        hs.responder.decrypt(&ciphertext).expect("decrypts"),
        at_ceiling
    );

    let over = vec![0x5a; MAX_PLAINTEXT_LEN + 1];
    assert!(matches!(
        hs.initiator.encrypt(&over),
        Err(NoiseError::PayloadTooLarge(len)) if len == MAX_PLAINTEXT_LEN + 1
    ));
}

// ---- Local failures are not the peer's fault ----------------------------

#[test]
fn a_key_store_that_cannot_agree_reports_itself_rather_than_the_peer() {
    // `Noise_XX` is `-> e; <- e, ee, s, es; -> s, se`, so the initiator's
    // static key is first used by `se`, in message 3. Message 2 reaches only
    // its ephemeral, which is software. Asserting the refusal a message
    // earlier would be asserting a pattern this design does not use.
    let store = Arc::new(CountingKeyStore::refusing(3));
    let binding = store.binding();
    let responder_store = Arc::new(CountingKeyStore::new(5));
    let rng = Arc::new(CounterRng::new());

    let (awaiting_response, first) = Initiator::new(
        Arc::clone(&store) as Arc<dyn KeyStore>,
        Arc::clone(&rng) as Arc<dyn Rng + Send + Sync>,
        verifier_at(NOW),
        binding,
    )
    .expect("building consults public_identity, which this store answers")
    .write_first()
    .expect("the first message draws an ephemeral key and agrees nothing");
    let (_, second) = Responder::new(
        Arc::clone(&responder_store) as Arc<dyn KeyStore>,
        Arc::clone(&rng) as Arc<dyn Rng + Send + Sync>,
        verifier_at(NOW),
        responder_store.binding(),
    )
    .expect("builds")
    .read_first(&first)
    .expect("reads")
    .write_second()
    .expect("writes");

    assert!(matches!(
        awaiting_response
            .read_second(&second)
            .expect("the responder's own join is good")
            .write_third(),
        Err(NoiseError::KeyStore(_))
    ));
}

#[test]
fn a_randomness_source_that_cannot_fill_reports_itself_rather_than_the_peer() {
    let store = Arc::new(CountingKeyStore::new(3));
    let binding = store.binding();
    let initiator = Initiator::new(
        Arc::clone(&store) as Arc<dyn KeyStore>,
        Arc::new(CounterRng::refusing()) as Arc<dyn Rng + Send + Sync>,
        verifier_at(NOW),
        binding,
    )
    .expect("building draws no randomness");

    assert!(matches!(initiator.write_first(), Err(NoiseError::Rng(_))));
}

// ---- A second implementation --------------------------------------------

// A resolver that answers only for randomness, so a reference peer can use
// `DefaultResolver` for everything else: `use-getrandom` is off (DCR-091), so
// `DefaultResolver` has no source of its own and refuses to build without one.
struct ReferenceResolver;

struct ReferenceRandom {
    next: Mutex<u64>,
}

impl snow::types::Random for ReferenceRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        let mut next = self.next.lock().expect("no test poisons this lock");
        for byte in dest.iter_mut() {
            *next = next.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(7);
            *byte = (*next >> 33) as u8;
        }
        Ok(())
    }
}

impl snow::resolvers::CryptoResolver for ReferenceResolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        Some(Box::new(ReferenceRandom {
            next: Mutex::new(0x5eed),
        }))
    }

    fn resolve_dh(&self, _choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        None
    }

    fn resolve_hash(
        &self,
        _choice: &snow::params::HashChoice,
    ) -> Option<Box<dyn snow::types::Hash>> {
        None
    }

    fn resolve_cipher(
        &self,
        _choice: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        None
    }
}

// Builds a plain `snow` peer holding `scalar` in software. It shares no code
// with the implementation under test beyond `snow` itself, so it disagrees
// wherever a cryptographic parameter does -- the instrument RECORD.md names
// for a wrong `dh_len`, which no test between two copies of one side catches.
fn reference_builder(scalar: &[u8; 32]) -> snow::Builder<'_> {
    let params: snow::params::NoiseParams = "Noise_XX_P256_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("the pattern this design fixes is valid Noise syntax");
    let resolver = snow::resolvers::FallbackResolver::new(
        Box::new(ReferenceResolver),
        Box::new(snow::resolvers::DefaultResolver),
    );
    snow::Builder::with_resolver(params, Box::new(resolver))
        .local_private_key(scalar)
        .expect("a 32-byte scalar is accepted once")
}

// The 137 bytes ADR-0020 specifies, assembled here rather than by the code
// under test: identity_pub, the signature, and `not_after` big-endian.
fn identity_join(store: &CountingKeyStore) -> Vec<u8> {
    let mut join = Vec::with_capacity(IDENTITY_JOIN_LEN);
    join.extend_from_slice(store.identity_pub().as_bytes());
    join.extend_from_slice(store.binding().signature().as_bytes());
    join.extend_from_slice(&LATER.to_be_bytes());
    assert_eq!(join.len(), IDENTITY_JOIN_LEN);
    join
}

#[test]
fn a_reference_snow_responder_completes_the_handshake_and_reads_a_message() {
    let pair = Pair::new();
    let scalar = pair.responder_store.agreement_scalar();
    let mut reference = reference_builder(&scalar)
        .build_responder()
        .expect("the reference responder builds");

    let (awaiting_response, first) = pair.initiator().write_first().expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference
        .read_message(&first, &mut scratch)
        .expect("a reference peer accepts our first message");
    let mut second = vec![0u8; 65535];
    let len = reference
        .write_message(&identity_join(&pair.responder_store), &mut second)
        .expect("the reference peer replies");
    let (mut session, third) = awaiting_response
        .read_second(&second[..len])
        .expect("we accept the reference peer's reply")
        .write_third()
        .expect("writes");
    let read = reference
        .read_message(&third, &mut scratch)
        .expect("the reference peer accepts our third message");
    assert_eq!(
        &scratch[..read],
        identity_join(&pair.initiator_store).as_slice(),
        "the join we write is the one ADR-0020 counts, byte for byte"
    );

    let mut reference = reference
        .into_transport_mode()
        .expect("the reference handshake finished");
    let ciphertext = session
        .encrypt(b"read by a peer we share no code with")
        .expect("encrypts");
    let mut plaintext = vec![0u8; 65535];
    let len = reference
        .read_message(&ciphertext, &mut plaintext)
        .expect("the reference peer decrypts what we encrypted");

    assert_eq!(&plaintext[..len], b"read by a peer we share no code with");
    assert_eq!(session.peer(), pair.responder_store.device_id());
}

#[test]
fn a_reference_snow_initiator_completes_the_handshake_and_reads_a_message() {
    let pair = Pair::new();
    let scalar = pair.initiator_store.agreement_scalar();
    let mut reference = reference_builder(&scalar)
        .build_initiator()
        .expect("the reference initiator builds");

    let mut first = vec![0u8; 65535];
    let len = reference
        .write_message(&[], &mut first)
        .expect("the reference peer opens");
    let (awaiting_confirmation, second) = pair
        .responder()
        .read_first(&first[..len])
        .expect("we accept the reference peer's first message")
        .write_second()
        .expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference
        .read_message(&second, &mut scratch)
        .expect("the reference peer accepts our reply");
    let mut third = vec![0u8; 65535];
    let len = reference
        .write_message(&identity_join(&pair.initiator_store), &mut third)
        .expect("the reference peer confirms");
    let mut session = awaiting_confirmation
        .read_third(&third[..len])
        .expect("we accept the reference peer's third message");

    let mut reference = reference
        .into_transport_mode()
        .expect("the reference handshake finished");
    let mut ciphertext = vec![0u8; 65535];
    let len = reference
        .write_message(b"written by a peer we share no code with", &mut ciphertext)
        .expect("the reference peer encrypts");
    let seen = session
        .decrypt(&ciphertext[..len])
        .expect("we decrypt what the reference peer encrypted");

    assert_eq!(seen, b"written by a peer we share no code with");
    assert_eq!(session.peer(), pair.initiator_store.device_id());
}

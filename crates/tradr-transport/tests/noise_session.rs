//! Supervisor-written specification for `WI-M7-007a` (CLAUDE.md section 6).
//! Noise_IK over a byte stream is a Critical Module because a resolver that
//! hands the software `Dh` to the static slot completes every handshake
//! between two Tradr devices, making one placeholder key the static key of
//! the whole fleet (docs/05, "What the `snow` resolver decides").

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use tradr_core::{
    Backing, DeviceId, DomainTag, KeyStore, KeyStoreError, PublicIdentity, PublicKeyPoint, Rng,
    RngError, SharedSecret, Signature, SoftwareReason,
};
use tradr_transport::noise::{Initiator, MAX_PLAINTEXT_LEN, NoiseError, NoiseSession, Responder};

// The largest frame a BLE channel carries (docs/04, "Framing").
const BLE_MAX_FRAME_SIZE: usize = 512;

// A KeyStore over a fixed P-256 scalar, counting the `agree` calls that
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

    fn agreement_pub(&self) -> PublicKeyPoint {
        point(&self.agreement)
    }

    fn agreement_scalar(&self) -> [u8; 32] {
        self.agreement.to_bytes().into()
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

impl KeyStore for CountingKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        let identity_pub = point(&self.identity);
        let digest = blake3::hash(identity_pub.as_bytes());
        Ok(PublicIdentity::new(
            identity_pub,
            point(&self.agreement),
            DeviceId::from_identity_digest(digest.as_bytes()),
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

struct Pair {
    initiator_store: Arc<CountingKeyStore>,
    responder_store: Arc<CountingKeyStore>,
    rng: Arc<CounterRng>,
}

impl Pair {
    fn new() -> Self {
        Self {
            initiator_store: Arc::new(CountingKeyStore::new(3)),
            responder_store: Arc::new(CountingKeyStore::new(5)),
            rng: Arc::new(CounterRng::new()),
        }
    }

    fn initiator(&self, dialling: &PublicKeyPoint) -> Initiator {
        Initiator::new(
            Arc::clone(&self.initiator_store) as Arc<dyn KeyStore>,
            Arc::clone(&self.rng) as Arc<dyn Rng + Send + Sync>,
            dialling,
        )
        .expect("an initiator builds from a working key store")
    }

    fn responder(&self) -> Responder {
        Responder::new(
            Arc::clone(&self.responder_store) as Arc<dyn KeyStore>,
            Arc::clone(&self.rng) as Arc<dyn Rng + Send + Sync>,
        )
        .expect("a responder builds from a working key store")
    }
}

// Drives both sides to a session, returning the initiator's and the
// responder's, plus the two handshake messages the test may inspect.
fn handshake(pair: &Pair) -> (NoiseSession, NoiseSession, Vec<u8>, Vec<u8>) {
    let dialling = pair.responder_store.agreement_pub();
    let (awaiting_response, first) = pair
        .initiator(&dialling)
        .write_first()
        .expect("the first message is written");
    let (session_r, second) = pair
        .responder()
        .read_first(&first)
        .expect("the responder reads the first message")
        .write_second()
        .expect("the second message is written");
    let session_i = awaiting_response
        .read_second(&second)
        .expect("the initiator reads the second message");
    (session_i, session_r, first, second)
}

#[test]
fn a_full_handshake_lets_both_sides_exchange_a_message() {
    let pair = Pair::new();
    let (mut session_i, mut session_r, _, _) = handshake(&pair);

    let to_responder = session_i.encrypt(b"from the initiator").expect("encrypts");
    let seen = session_r.decrypt(&to_responder).expect("decrypts");
    assert_eq!(seen, b"from the initiator");

    let to_initiator = session_r.encrypt(b"from the responder").expect("encrypts");
    let seen = session_i.decrypt(&to_initiator).expect("decrypts");
    assert_eq!(seen, b"from the responder");
}

#[test]
fn the_responder_learns_the_initiators_agreement_key() {
    let pair = Pair::new();
    let (_, session_r, _, _) = handshake(&pair);

    assert_eq!(
        session_r.peer_agreement_pub(),
        &pair.initiator_store.agreement_pub()
    );
}

#[test]
fn the_initiator_holds_the_agreement_key_it_dialled() {
    let pair = Pair::new();
    let (session_i, _, _, _) = handshake(&pair);

    assert_eq!(
        session_i.peer_agreement_pub(),
        &pair.responder_store.agreement_pub()
    );
}

#[test]
fn every_static_diffie_hellman_reaches_the_key_store() {
    let pair = Pair::new();
    let (_, _, _, _) = handshake(&pair);

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
fn a_handshake_against_a_third_partys_agreement_key_is_refused() {
    let pair = Pair::new();
    let stranger = CountingKeyStore::new(11);

    let (_, first) = pair
        .initiator(&stranger.agreement_pub())
        .write_first()
        .expect("the first message is written whatever it is addressed to");

    assert!(matches!(
        pair.responder().read_first(&first),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_truncated_first_message_is_refused() {
    let pair = Pair::new();
    let dialling = pair.responder_store.agreement_pub();
    let (_, first) = pair.initiator(&dialling).write_first().expect("writes");

    assert!(matches!(
        pair.responder().read_first(&first[..first.len() - 1]),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_flipped_bit_in_the_first_message_is_refused() {
    let pair = Pair::new();
    let dialling = pair.responder_store.agreement_pub();
    let (_, mut first) = pair.initiator(&dialling).write_first().expect("writes");
    let last = first.len() - 1;
    first[last] ^= 0x01;

    assert!(matches!(
        pair.responder().read_first(&first),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_flipped_bit_in_the_second_message_is_refused() {
    let pair = Pair::new();
    let dialling = pair.responder_store.agreement_pub();
    let (awaiting_response, first) = pair.initiator(&dialling).write_first().expect("writes");
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
fn a_flipped_bit_in_a_session_message_is_refused() {
    let pair = Pair::new();
    let (mut session_i, mut session_r, _, _) = handshake(&pair);

    let mut ciphertext = session_i.encrypt(b"tampered in flight").expect("encrypts");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(matches!(
        session_r.decrypt(&ciphertext),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn two_handshakes_do_not_produce_the_same_session_key() {
    let pair = Pair::new();
    let (mut first_i, _, _, _) = handshake(&pair);
    let (_, mut second_r, _, _) = handshake(&pair);

    let ciphertext = first_i
        .encrypt(b"belongs to the first session")
        .expect("encrypts");

    assert!(matches!(
        second_r.decrypt(&ciphertext),
        Err(NoiseError::Refused)
    ));
}

#[test]
fn a_plaintext_at_the_ceiling_is_carried_and_one_byte_over_is_refused() {
    let pair = Pair::new();
    let (mut session_i, mut session_r, _, _) = handshake(&pair);

    let at_ceiling = vec![0x5a; MAX_PLAINTEXT_LEN];
    let ciphertext = session_i
        .encrypt(&at_ceiling)
        .expect("the ceiling is carried");
    assert_eq!(
        session_r.decrypt(&ciphertext).expect("decrypts"),
        at_ceiling
    );

    let over = vec![0x5a; MAX_PLAINTEXT_LEN + 1];
    assert!(matches!(
        session_i.encrypt(&over),
        Err(NoiseError::PayloadTooLarge(len)) if len == MAX_PLAINTEXT_LEN + 1
    ));
}

#[test]
fn a_key_store_that_cannot_agree_reports_itself_rather_than_the_peer() {
    let store = Arc::new(CountingKeyStore::refusing(3));
    let responder_store = CountingKeyStore::new(5);
    let initiator = Initiator::new(
        store as Arc<dyn KeyStore>,
        Arc::new(CounterRng::new()) as Arc<dyn Rng + Send + Sync>,
        &responder_store.agreement_pub(),
    )
    .expect("building consults public_identity, which this store answers");

    assert!(matches!(
        initiator.write_first(),
        Err(NoiseError::KeyStore(_))
    ));
}

#[test]
fn a_randomness_source_that_cannot_fill_reports_itself_rather_than_the_peer() {
    let store = Arc::new(CountingKeyStore::new(3));
    let responder_store = CountingKeyStore::new(5);
    let initiator = Initiator::new(
        store as Arc<dyn KeyStore>,
        Arc::new(CounterRng::refusing()) as Arc<dyn Rng + Send + Sync>,
        &responder_store.agreement_pub(),
    )
    .expect("building draws no randomness");

    assert!(matches!(initiator.write_first(), Err(NoiseError::Rng(_))));
}

#[test]
fn both_handshake_messages_fit_one_ble_frame() {
    let pair = Pair::new();
    let (_, _, first, second) = handshake(&pair);

    assert!(
        first.len() <= BLE_MAX_FRAME_SIZE,
        "the first message is {} bytes",
        first.len()
    );
    assert!(
        second.len() <= BLE_MAX_FRAME_SIZE,
        "the second message is {} bytes",
        second.len()
    );
}

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
// wherever a cryptographic parameter does.
fn reference_builder(scalar: &[u8; 32]) -> snow::Builder<'_> {
    let params: snow::params::NoiseParams = "Noise_IK_P256_ChaChaPoly_BLAKE2s"
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

#[test]
fn a_reference_snow_responder_completes_the_handshake_and_reads_a_message() {
    let pair = Pair::new();
    let scalar = pair.responder_store.agreement_scalar();
    let mut reference = reference_builder(&scalar)
        .build_responder()
        .expect("the reference responder builds");

    let (awaiting_response, first) = pair
        .initiator(&pair.responder_store.agreement_pub())
        .write_first()
        .expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference
        .read_message(&first, &mut scratch)
        .expect("a reference peer accepts our first message");
    let mut second = vec![0u8; 65535];
    let len = reference
        .write_message(&[], &mut second)
        .expect("the reference peer replies");
    let mut session = awaiting_response
        .read_second(&second[..len])
        .expect("we accept the reference peer's reply");

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
}

#[test]
fn a_reference_snow_initiator_completes_the_handshake_and_reads_a_message() {
    let pair = Pair::new();
    let scalar = pair.initiator_store.agreement_scalar();
    let mut reference = reference_builder(&scalar)
        .remote_public_key(pair.responder_store.agreement_pub().as_bytes())
        .expect("the responder's key is a 65-byte point")
        .build_initiator()
        .expect("the reference initiator builds");

    let mut first = vec![0u8; 65535];
    let len = reference
        .write_message(&[], &mut first)
        .expect("the reference peer opens");
    let (mut session, second) = pair
        .responder()
        .read_first(&first[..len])
        .expect("we accept the reference peer's first message")
        .write_second()
        .expect("writes");
    let mut scratch = vec![0u8; 65535];
    reference
        .read_message(&second, &mut scratch)
        .expect("the reference peer accepts our reply");

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
}

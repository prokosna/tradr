//! Supervisor-authored tests for the `Hello` exchange, written before the
//! implementation (CLAUDE.md section 6): this is where a channel's
//! authenticated Device Key is joined to the account a `Hello` claims, and
//! a wrong join is impersonation every signature check still passes. Each
//! claim is checked through `p256` and `blake3`, not the code under test.

use std::cell::Cell;
use std::time::Instant;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use tradr_core::{
    Capabilities, Clock, DeviceId, DomainTag, HelloNonce, KeyBinding, KeyStore, Monotonic,
    PeerHello, PeerHelloAck, PublicIdentity, Rng, RngError, Signature, TrustTier, UnixTime,
    VersionRange,
};
use tradr_identity::SoftwareKeyStore;
use tradr_identity::hello::{HelloRefused, MIN_NEGOTIABLE_FRAME_SIZE, Session, open};

// ---- Fakes -------------------------------------------------------------

// Counter-based rather than a constant byte: `SoftwareKeyStore::generate`
// may reject-sample a scalar, and a constant stream would make that loop.
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

// Returns one fixed byte, so a nonce drawn through it is predictable and
// the test can assert exactly which bytes reached the `Hello`.
struct ConstantRng(u8);

impl Rng for ConstantRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(self.0);
        Ok(())
    }
}

// Rule E3 forbids waiting on wall-clock time, so expiry is expressed by
// choosing the clock rather than by letting one run.
struct FixedClock {
    secs: i64,
    started: Instant,
}

impl FixedClock {
    fn at(secs: i64) -> Self {
        Self {
            secs,
            started: Instant::now(),
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.secs)
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(self.started)
    }
}

// ---- Builders ----------------------------------------------------------

const NOW: i64 = 1_800_000_000;
const LATER: i64 = NOW + 86_400;
const FRAME_SIZE: u32 = 1 << 20;

fn device(seed: u64) -> SoftwareKeyStore {
    SoftwareKeyStore::generate(&SeededRng::new(seed)).expect("a seeded generate must succeed")
}

fn identity(store: &SoftwareKeyStore) -> PublicIdentity {
    store.public_identity().expect("a generated store has one")
}

// A `KeyBinding` this device really signed: `DomainTag::KeyBind` over its
// own agreement key. Built through `KeyStore::sign` because the device's
// own signing is already tested; the exchange is what is under test here.
fn binding_for(store: &SoftwareKeyStore, not_after: i64) -> KeyBinding {
    let id = identity(store);
    let signature = store
        .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
        .expect("signing under KeyBind must succeed");
    KeyBinding::new(
        id.agreement_pub().clone(),
        signature,
        UnixTime::from_secs(not_after),
    )
}

fn versions() -> VersionRange {
    VersionRange::new(1, 1).expect("a single supported version is valid")
}

// A `Hello` a device would really send: its own keys, its own binding.
fn hello_from(store: &SoftwareKeyStore, nonce: HelloNonce) -> PeerHello {
    let id = identity(store);
    PeerHello::new(
        versions(),
        id.identity_pub().clone(),
        id.agreement_pub().clone(),
        "header.payload.signature".to_string(),
        binding_for(store, LATER),
        nonce,
        Capabilities::empty(),
    )
}

fn nonce_of(byte: u8) -> HelloNonce {
    HelloNonce::from_bytes([byte; 16])
}

// Signs `message` under `domain` with `store`'s identity key, for building
// a peer's `HelloAck` by hand.
fn sign(store: &SoftwareKeyStore, domain: DomainTag, message: &[u8]) -> Signature {
    store.sign(domain, message).expect("signing must succeed")
}

fn device_id_of(store: &SoftwareKeyStore) -> DeviceId {
    identity(store).device_id()
}

// Drives one side from `open` through to a `Session`, given what the peer
// sent and what our own Attestation verification concluded.
fn run_exchange(
    ours: &SoftwareKeyStore,
    our_nonce: HelloNonce,
    peer_hello: PeerHello,
    authenticated: DeviceId,
    tier: TrustTier,
    peer_ack: impl FnOnce(&PeerHello) -> PeerHelloAck,
) -> Result<Session, HelloRefused> {
    let (awaiting, our_hello) = open(
        &ConstantRng(our_nonce.as_bytes()[0]),
        versions(),
        &identity(ours),
        "header.payload.signature".to_string(),
        binding_for(ours, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");
    let clock = FixedClock::at(NOW);
    let (awaiting, _request) = awaiting.on_peer_hello(peer_hello.clone(), authenticated, &clock)?;
    let (awaiting, _our_ack) = awaiting
        .on_verified(tier, ours, FRAME_SIZE)
        .expect("signing our HelloAck must succeed");
    let _ = our_hello;
    awaiting.on_peer_hello_ack(peer_ack(&peer_hello))
}

// The `HelloAck` an honest peer sends: our nonce, signed by the peer.
fn honest_ack(peer: &SoftwareKeyStore, our_nonce: &HelloNonce, tier: TrustTier) -> PeerHelloAck {
    PeerHelloAck::new(
        1,
        FRAME_SIZE,
        sign(peer, DomainTag::Hello, our_nonce.as_bytes()),
        tier,
    )
}

// ---- P1: the positive path ---------------------------------------------

#[test]
fn two_devices_complete_the_exchange_and_agree_on_the_version() {
    let alice = device(1);
    let bob = device(2);
    let alice_nonce = nonce_of(0xa1);

    let session = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| honest_ack(&bob, &alice_nonce, TrustTier::SameAccount),
    )
    .expect("an honest exchange between two real key stores must complete");

    assert_eq!(session.peer(), device_id_of(&bob));
    assert_eq!(session.tier(), TrustTier::SameAccount);
    assert_eq!(session.negotiated_version(), 1);
    assert_eq!(session.peer_max_frame_size(), FRAME_SIZE);
}

#[test]
fn our_hello_carries_the_nonce_drawn_through_the_rng_trait() {
    let alice = device(1);
    let (_awaiting, our_hello) = open(
        &ConstantRng(0x5c),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    assert_eq!(our_hello.nonce().as_bytes(), &[0x5c; 16]);
}

// ---- V: version negotiation --------------------------------------------

#[test]
fn disjoint_version_ranges_are_refused_before_any_attestation_is_asked_for() {
    let alice = device(1);
    let bob = device(2);

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        VersionRange::new(1, 1).expect("valid"),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    let mut peer = hello_from(&bob, nonce_of(0xb2));
    peer = PeerHello::new(
        VersionRange::new(7, 9).expect("valid"),
        peer.identity_pub().clone(),
        peer.agreement_pub().clone(),
        peer.attestation_token().to_string(),
        binding_for(&bob, LATER),
        peer.nonce(),
        Capabilities::empty(),
    );

    let refusal = awaiting
        .on_peer_hello(peer, device_id_of(&bob), &FixedClock::at(NOW))
        .expect_err("ranges 1..1 and 7..9 have no common version");

    // The refusal itself is the evidence no Attestation was requested: the
    // request is only produced on the Ok branch.
    assert!(matches!(refusal, HelloRefused::NoCommonVersion(_)));
}

// ---- K: the key join ---------------------------------------------------

#[test]
fn a_wholly_valid_hello_is_refused_on_a_channel_that_authenticated_another_device() {
    let alice = device(1);
    let bob = device(2);
    let mallory = device(3);

    // Bob's genuine Hello, unaltered. Only the channel differs.
    let refusal = run_exchange(
        &alice,
        nonce_of(0xa1),
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&mallory),
        TrustTier::SameAccount,
        |_| honest_ack(&bob, &nonce_of(0xa1), TrustTier::SameAccount),
    )
    .expect_err("a Hello for Bob presented on Mallory's channel must be refused");

    match refusal {
        HelloRefused::KeyDoesNotMatchChannel {
            authenticated,
            claimed,
        } => {
            assert_eq!(authenticated, device_id_of(&mallory));
            assert_eq!(claimed, device_id_of(&bob));
        }
        other => panic!("expected KeyDoesNotMatchChannel, got {other:?}"),
    }
}

#[test]
fn the_relayed_attestation_is_refused_before_it_is_ever_verified() {
    let alice = device(1);
    let bob = device(2);
    let mallory = device(3);

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    // Mallory relays Bob's Hello verbatim over Mallory's own channel. Every
    // signature in it is genuine and every one of them verifies.
    let outcome = awaiting.on_peer_hello(
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&mallory),
        &FixedClock::at(NOW),
    );

    assert!(
        outcome.is_err(),
        "the join must refuse a relayed Hello, and must do it before an AttestationRequest exists"
    );
}

#[test]
fn the_claimed_device_id_is_blake3_of_the_identity_key_truncated_to_sixteen_bytes() {
    let bob = device(2);
    let identity_pub = identity(&bob).identity_pub().clone();

    // Derived here through blake3 directly rather than through the crate,
    // so the exchange cannot pass by agreeing with itself.
    let digest: [u8; 32] = blake3::hash(identity_pub.as_bytes()).into();
    let expected = DeviceId::from_identity_digest(&digest);

    let alice = device(1);
    let session = run_exchange(
        &alice,
        nonce_of(0xa1),
        hello_from(&bob, nonce_of(0xb2)),
        expected,
        TrustTier::SameAccount,
        |_| honest_ack(&bob, &nonce_of(0xa1), TrustTier::SameAccount),
    )
    .expect("the independently derived DeviceId must be the one the join accepts");

    assert_eq!(session.peer(), expected);
}

// ---- B: the KeyBinding -------------------------------------------------

#[test]
fn a_key_binding_signed_over_a_different_agreement_key_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let other = device(9);

    let bob_id = identity(&bob);
    // Bob signs somebody else's agreement key, so the signature is valid
    // over the wrong message.
    let signature = sign(
        &bob,
        DomainTag::KeyBind,
        identity(&other).agreement_pub().as_bytes(),
    );
    let bad = KeyBinding::new(
        bob_id.agreement_pub().clone(),
        signature,
        UnixTime::from_secs(LATER),
    );

    let peer = PeerHello::new(
        versions(),
        bob_id.identity_pub().clone(),
        bob_id.agreement_pub().clone(),
        "header.payload.signature".to_string(),
        bad,
        nonce_of(0xb2),
        Capabilities::empty(),
    );

    let refusal = run_exchange(
        &alice,
        nonce_of(0xa1),
        peer,
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| honest_ack(&bob, &nonce_of(0xa1), TrustTier::SameAccount),
    )
    .expect_err("a binding over another key must be refused");

    assert!(matches!(
        refusal,
        HelloRefused::KeyBindingSignatureInvalid | HelloRefused::KeyBindingNotForThisAgreementKey
    ));
}

#[test]
fn a_key_binding_signed_by_a_different_identity_key_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let mallory = device(3);

    let bob_id = identity(&bob);
    // Mallory signs Bob's agreement key. The message is right, the signer
    // is not.
    let signature = sign(
        &mallory,
        DomainTag::KeyBind,
        bob_id.agreement_pub().as_bytes(),
    );
    let bad = KeyBinding::new(
        bob_id.agreement_pub().clone(),
        signature,
        UnixTime::from_secs(LATER),
    );

    let peer = PeerHello::new(
        versions(),
        bob_id.identity_pub().clone(),
        bob_id.agreement_pub().clone(),
        "header.payload.signature".to_string(),
        bad,
        nonce_of(0xb2),
        Capabilities::empty(),
    );

    let refusal = run_exchange(
        &alice,
        nonce_of(0xa1),
        peer,
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| honest_ack(&bob, &nonce_of(0xa1), TrustTier::SameAccount),
    )
    .expect_err("a binding signed by another device must be refused");

    assert!(matches!(refusal, HelloRefused::KeyBindingSignatureInvalid));
}

#[test]
fn an_expired_key_binding_is_refused() {
    let alice = device(1);
    let bob = device(2);

    let bob_id = identity(&bob);
    let peer = PeerHello::new(
        versions(),
        bob_id.identity_pub().clone(),
        bob_id.agreement_pub().clone(),
        "header.payload.signature".to_string(),
        binding_for(&bob, NOW - 1),
        nonce_of(0xb2),
        Capabilities::empty(),
    );

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    let refusal = awaiting
        .on_peer_hello(peer, device_id_of(&bob), &FixedClock::at(NOW))
        .expect_err("a binding whose not_after has passed must be refused");

    assert!(matches!(refusal, HelloRefused::KeyBindingExpired { .. }));
}

#[test]
fn a_key_binding_expiring_exactly_now_is_still_valid() {
    let alice = device(1);
    let bob = device(2);

    let bob_id = identity(&bob);
    // "Not after" means the instant itself is inside the window. Pinned
    // here so an implementation cannot pick the other reading.
    let peer = PeerHello::new(
        versions(),
        bob_id.identity_pub().clone(),
        bob_id.agreement_pub().clone(),
        "header.payload.signature".to_string(),
        binding_for(&bob, NOW),
        nonce_of(0xb2),
        Capabilities::empty(),
    );

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    assert!(
        awaiting
            .on_peer_hello(peer, device_id_of(&bob), &FixedClock::at(NOW))
            .is_ok(),
        "not_after == now is inside the window, not outside it"
    );
}

// ---- N: the nonce signature in step 4 ----------------------------------

#[test]
fn a_hello_ack_signed_over_the_peers_own_nonce_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let bob_nonce = nonce_of(0xb2);

    // The reflection attack: Bob signs the nonce Bob chose, not ours. A
    // relay can obtain such a signature without holding any key of ours.
    let refusal = run_exchange(
        &alice,
        nonce_of(0xa1),
        hello_from(&bob, bob_nonce),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |peer| {
            PeerHelloAck::new(
                1,
                FRAME_SIZE,
                sign(&bob, DomainTag::Hello, peer.nonce().as_bytes()),
                TrustTier::SameAccount,
            )
        },
    )
    .expect_err("a signature over the peer's own nonce proves nothing");

    assert!(matches!(refusal, HelloRefused::NonceSignatureInvalid));
}

#[test]
fn a_hello_ack_signed_by_a_different_key_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let mallory = device(3);
    let alice_nonce = nonce_of(0xa1);

    let refusal = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| honest_ack(&mallory, &alice_nonce, TrustTier::SameAccount),
    )
    .expect_err("the ack must be signed by the device the Hello named");

    assert!(matches!(refusal, HelloRefused::NonceSignatureInvalid));
}

#[test]
fn a_hello_ack_signed_under_a_different_domain_tag_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let alice_nonce = nonce_of(0xa1);

    // Right key, right message, wrong context. This is what the domain tag
    // exists for, so it is checked rather than assumed.
    let refusal = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| {
            PeerHelloAck::new(
                1,
                FRAME_SIZE,
                sign(&bob, DomainTag::KeyBind, alice_nonce.as_bytes()),
                TrustTier::SameAccount,
            )
        },
    )
    .expect_err("a signature under KeyBind must not satisfy the Hello context");

    assert!(matches!(refusal, HelloRefused::NonceSignatureInvalid));
}

#[test]
fn our_hello_ack_signs_the_peers_nonce_under_the_hello_tag() {
    let alice = device(1);
    let bob = device(2);
    let bob_nonce = nonce_of(0xb2);

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");
    let (awaiting, _request) = awaiting
        .on_peer_hello(
            hello_from(&bob, bob_nonce),
            device_id_of(&bob),
            &FixedClock::at(NOW),
        )
        .expect("an honest Hello must be accepted");
    let (_awaiting, our_ack) = awaiting
        .on_verified(TrustTier::SameAccount, &alice, FRAME_SIZE)
        .expect("signing must succeed");

    // Verified through p256 directly against the exact bytes DomainTag
    // says are signed, never by asking the crate what it signed.
    let expected = DomainTag::Hello
        .payload(bob_nonce.as_bytes())
        .expect("Hello prepends its tag");
    let key = VerifyingKey::from_sec1_bytes(identity(&alice).identity_pub().as_bytes())
        .expect("a generated identity key is a valid point");
    let signature =
        P256Signature::from_slice(our_ack.nonce_signature().as_bytes()).expect("a P-256 signature");

    assert!(key.verify(expected.as_ref(), &signature).is_ok());
}

// ---- T: the three rules that are not checks ----------------------------

#[test]
fn a_peer_claiming_a_higher_tier_does_not_receive_one() {
    let alice = device(1);
    let bob = device(2);
    let alice_nonce = nonce_of(0xa1);

    // Our own verification said NearbyEphemeral. Bob's HelloAck claims
    // SameAccount, which is what Bob granted us and says nothing about
    // what we granted Bob.
    let session = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::NearbyEphemeral,
        |_| honest_ack(&bob, &alice_nonce, TrustTier::SameAccount),
    )
    .expect("a tier disagreement is not a refusal");

    assert_eq!(
        session.tier(),
        TrustTier::NearbyEphemeral,
        "the tier a side enforces is the one it computed"
    );
}

#[test]
fn a_rejected_peer_still_completes_the_exchange_and_still_gets_a_signature() {
    let alice = device(1);
    let bob = device(2);
    let bob_nonce = nonce_of(0xb2);

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");
    let (awaiting, _request) = awaiting
        .on_peer_hello(
            hello_from(&bob, bob_nonce),
            device_id_of(&bob),
            &FixedClock::at(NOW),
        )
        .expect("the Hello itself is well formed");

    let (_awaiting, our_ack) = awaiting
        .on_verified(TrustTier::Rejected, &alice, FRAME_SIZE)
        .expect("Rejected is an outcome, not an error");

    assert_eq!(our_ack.assigned_tier(), TrustTier::Rejected);

    // The signature is real, per docs/04: the domain tag is what makes
    // signing an attacker-chosen sixteen bytes safe.
    let expected = DomainTag::Hello
        .payload(bob_nonce.as_bytes())
        .expect("Hello prepends its tag");
    let key = VerifyingKey::from_sec1_bytes(identity(&alice).identity_pub().as_bytes())
        .expect("valid point");
    let signature =
        P256Signature::from_slice(our_ack.nonce_signature().as_bytes()).expect("a P-256 signature");
    assert!(key.verify(expected.as_ref(), &signature).is_ok());
}

// ---- DCR-052: the peer's HelloAck claims -------------------------------

#[test]
fn a_hello_ack_naming_a_different_negotiated_version_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let alice_nonce = nonce_of(0xa1);

    let refusal = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| {
            PeerHelloAck::new(
                2,
                FRAME_SIZE,
                sign(&bob, DomainTag::Hello, alice_nonce.as_bytes()),
                TrustTier::SameAccount,
            )
        },
    )
    .expect_err("negotiation is symmetric, so there is exactly one right answer");

    match refusal {
        HelloRefused::VersionDisagreement { ours, theirs } => {
            assert_eq!(ours, 1);
            assert_eq!(theirs, 2);
        }
        other => panic!("expected VersionDisagreement, got {other:?}"),
    }
}

#[test]
fn a_hello_ack_advertising_less_than_the_minimum_frame_size_is_refused() {
    let alice = device(1);
    let bob = device(2);
    let alice_nonce = nonce_of(0xa1);

    let refusal = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| {
            PeerHelloAck::new(
                1,
                MIN_NEGOTIABLE_FRAME_SIZE - 1,
                sign(&bob, DomainTag::Hello, alice_nonce.as_bytes()),
                TrustTier::SameAccount,
            )
        },
    )
    .expect_err("below the ble-gatt bound there is no usable session");

    assert!(matches!(refusal, HelloRefused::FrameSizeTooSmall { .. }));
}

#[test]
fn a_hello_ack_advertising_exactly_the_minimum_frame_size_is_accepted() {
    let alice = device(1);
    let bob = device(2);
    let alice_nonce = nonce_of(0xa1);

    let session = run_exchange(
        &alice,
        alice_nonce,
        hello_from(&bob, nonce_of(0xb2)),
        device_id_of(&bob),
        TrustTier::SameAccount,
        |_| {
            PeerHelloAck::new(
                1,
                MIN_NEGOTIABLE_FRAME_SIZE,
                sign(&bob, DomainTag::Hello, alice_nonce.as_bytes()),
                TrustTier::SameAccount,
            )
        },
    )
    .expect("512 is a legal bound, not a refused one");

    assert_eq!(session.peer_max_frame_size(), MIN_NEGOTIABLE_FRAME_SIZE);
}

// ---- A: what the module must never do ----------------------------------

#[test]
fn the_attestation_request_does_not_print_the_token_it_carries() {
    let alice = device(1);
    let bob = device(2);
    let token = "header.payload.signature";

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        token.to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    let (_awaiting, request) = awaiting
        .on_peer_hello(
            hello_from(&bob, nonce_of(0xb2)),
            device_id_of(&bob),
            &FixedClock::at(NOW),
        )
        .expect("an honest Hello must be accepted");

    // An id_token is a bearer credential, so rule F4 puts it out of every
    // log the same way `tradr_core::PeerHello` does.
    let printed = format!("{request:?}");
    assert!(
        !printed.contains(token),
        "Debug must not print the id_token: {printed}"
    );
    assert!(printed.contains("redacted"));
}

#[test]
fn the_attestation_request_carries_the_token_and_both_keys_and_no_verdict() {
    let alice = device(1);
    let bob = device(2);
    let bob_id = identity(&bob);

    let (awaiting, _our_hello) = open(
        &ConstantRng(0xa1),
        versions(),
        &identity(&alice),
        "header.payload.signature".to_string(),
        binding_for(&alice, LATER),
        Capabilities::empty(),
    )
    .expect("open must succeed");

    let (_awaiting, request) = awaiting
        .on_peer_hello(
            hello_from(&bob, nonce_of(0xb2)),
            device_id_of(&bob),
            &FixedClock::at(NOW),
        )
        .expect("an honest Hello must be accepted");

    // The exchange verifies no Attestation and reaches no verdict about
    // one: it hands out exactly what verify_attestation needs and stops.
    assert_eq!(request.token(), "header.payload.signature");
    assert_eq!(request.identity_pub(), bob_id.identity_pub());
    assert_eq!(request.agreement_pub(), bob_id.agreement_pub());
}

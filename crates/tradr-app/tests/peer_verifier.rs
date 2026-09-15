//! Supervisor-authored tests for DF-72 (CLAUDE.md section 6). Whether the
//! tier `classify` decided is the tier the closure returns, and whether the
//! account and the links are read when it is called rather than when it is
//! built. Every token is issued at `NOW`, so freshness is decided by its
//! own `iat` and never by the machine's calendar (rule E3).

mod common;

use std::sync::{Arc, Mutex};

use common::{
    AUD, CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, clock_at, device_store, document,
    profile, published_key, token,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_app::sign_in::{SignInState, finish_sign_in, peer_verifier};
use tradr_core::{
    Capabilities, DomainTag, HelloNonce, KeyBinding, KeyStore, LinkSecret, PublicIdentity, Rng,
    RngError, TrustTier, UnixTime, VersionRange,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{AccountId, Link, LinkRegistry, SoftwareKeyStore, derive_link_id, hello};
use tradr_secrets::FileStore;

const LINKED_SUB: &str = "linked-subject";
const STRANGER_SUB: &str = "stranger-subject";
const LATER: i64 = NOW + 86_400;

// A nonce this test never inspects: `peer_verifier` reads the token and
// the two keys out of the request and nothing else.
struct FixedRng;

impl Rng for FixedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(7);
        Ok(())
    }
}

fn identity_of(store: &SoftwareKeyStore) -> PublicIdentity {
    store.public_identity().expect("a generated store has one")
}

fn binding_for(store: &SoftwareKeyStore) -> KeyBinding {
    let id = identity_of(store);
    let signature = store
        .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
        .expect("signing under KeyBind must succeed");
    KeyBinding::new(
        id.agreement_pub().clone(),
        signature,
        UnixTime::from_secs(LATER),
    )
}

// The request `perform_handshake` would hand the verifier, produced by
// the same `on_peer_hello` the live path runs rather than assembled here:
// `AttestationRequest` has no public constructor, and that is the reason
// this file drives the Hello state machine instead of the closure alone.
fn request_from(
    us: &SoftwareKeyStore,
    peer: &SoftwareKeyStore,
    peer_token: &str,
) -> AttestationRequest {
    let our_id = identity_of(us);
    let peer_id = identity_of(peer);
    let versions = VersionRange::new(1, 2).expect("a valid range");

    let (state, _our_hello) = hello::open(
        &FixedRng,
        versions,
        &our_id,
        "our-token".to_string(),
        binding_for(us),
        Capabilities::empty(),
    )
    .expect("a fixed rng fills a nonce");

    let peer_hello = tradr_core::PeerHello::new(
        versions,
        peer_id.identity_pub().clone(),
        peer_id.agreement_pub().clone(),
        peer_token.to_string(),
        binding_for(peer),
        HelloNonce::from_bytes([9u8; 16]),
        Capabilities::empty(),
    );

    let (_awaiting, request) = state
        .on_peer_hello(peer_hello, peer_id.device_id(), &clock_at(NOW))
        .expect("checks 1 to 3 pass for a well-formed peer Hello");
    request
}

fn trust_holding_the_providers_key() -> Arc<PeerTrust> {
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    trust
        .install(JWKS_URI, &document(&[published_key(KID)]))
        .expect("a well-formed document");
    Arc::new(trust)
}

fn empty_registry(dir: &std::path::Path) -> Arc<Mutex<LinkRegistry>> {
    let registry = LinkRegistry::load(&dir.join("links.json")).expect("a missing file is empty");
    Arc::new(Mutex::new(registry))
}

fn link_to(registry: &Mutex<LinkRegistry>, sub: &str, dir: &std::path::Path) {
    let secret = LinkSecret::from_bytes(&[3u8; 32]).expect("32 bytes builds a link secret");
    let link = Link::new(
        derive_link_id(&secret),
        AccountId::new(ISS, sub),
        UnixTime::from_secs(NOW),
    );
    let secrets = FileStore::new(dir.join("secrets"));
    registry
        .lock()
        .expect("an uncontended registry")
        .add(link, &secret, &secrets)
        .expect("a fresh account and a matching secret");
}

async fn sign_in_as(sub: &str, us: &SoftwareKeyStore, trust: &PeerTrust, state: &SignInState) {
    let our_id = identity_of(us);
    let id_token = token(KID, sub, AUD, &our_id, NOW);
    finish_sign_in(&profile(), &our_id, id_token, trust, state, &clock_at(NOW))
        .await
        .expect("a token this provider signed, bound to this device");
}

#[tokio::test]
async fn a_stranger_is_refused_rather_than_handed_this_accounts_own_tier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;
    let links = empty_registry(dir.path());

    let peer_token = token(KID, STRANGER_SUB, AUD, &identity_of(&peer), NOW);
    let verify = peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
    );

    let outcome = verify(request_from(&us, &peer, &peer_token)).await;

    assert!(
        outcome.is_err(),
        "an account that is neither this device's own nor linked is refused, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_peer_of_this_devices_own_account_is_same_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;
    let links = empty_registry(dir.path());

    let peer_token = token(KID, OWN_SUB, AUD, &identity_of(&peer), NOW);
    let verify = peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
    );

    let outcome = verify(request_from(&us, &peer, &peer_token)).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
}

#[tokio::test]
async fn the_account_signed_in_after_the_verifier_was_built_is_the_one_it_classifies_against() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    let links = empty_registry(dir.path());

    // Built while this device has no account at all, which is the state a
    // listener started before sign-in is in.
    let verify = peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
    );
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;

    let peer_token = token(KID, OWN_SUB, AUD, &identity_of(&peer), NOW);
    let outcome = verify(request_from(&us, &peer, &peer_token)).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
}

#[tokio::test]
async fn a_link_the_registry_gained_after_the_verifier_was_built_is_honoured() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;
    let links = empty_registry(dir.path());

    let verify = peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
    );
    link_to(&links, LINKED_SUB, dir.path());

    let peer_token = token(KID, LINKED_SUB, AUD, &identity_of(&peer), NOW);
    let outcome = verify(request_from(&us, &peer, &peer_token)).await;

    assert_eq!(
        outcome,
        Ok(TrustTier::Linked),
        "the accounts the registry holds must reach classification, and be read when the verifier is called"
    );
}

//! Supervisor-authored tests for WI-M6-001, written before the
//! implementation (CLAUDE.md section 6). Verification itself is already
//! tested in `tradr-identity`; what is new here is the join the live path
//! makes -- which policy it builds, what it does before a sign-in, and how
//! many outbound fetches a peer can drive.

use std::sync::Arc;

mod common;

use common::{
    AUD, CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, STALENESS_LIMIT_SECS, clock_at, document,
    identity, impostor_key, profile, published_key, token,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_core::{PublicIdentity, TrustTier};
use tradr_identity::{AccountId, Jwk};

const ROTATED_KID: &str = "provider-key-2";
const OTHER_AUD: &str = "someone-elses-deployment.apps.googleusercontent.com";
const LINKED_SUB: &str = "linked-subject";
const STRANGER_SUB: &str = "stranger-subject";

// A PeerTrust already holding `keys`, so a test that is not about
// fetching never reaches the network seam at all.
fn trust_holding(keys: &[Jwk], fetch: Arc<CountingFetch>) -> PeerTrust {
    let trust = PeerTrust::new(profile(), fetch);
    trust
        .install(JWKS_URI, &document(keys))
        .expect("a well-formed document");
    trust
}

fn own_account() -> AccountId {
    AccountId::new(ISS, OWN_SUB)
}

fn linked_account() -> AccountId {
    AccountId::new(ISS, LINKED_SUB)
}

async fn classify(
    trust: &PeerTrust,
    presented_by: &PublicIdentity,
    token: &str,
    own: Option<&AccountId>,
    linked: &[AccountId],
) -> Result<TrustTier, String> {
    trust
        .classify(
            token,
            presented_by.identity_pub(),
            presented_by.agreement_pub(),
            own,
            linked,
            &clock_at(NOW),
        )
        .await
}

#[tokio::test]
async fn a_device_that_has_not_signed_in_grants_no_tier_at_all() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, None, &[]).await;

    let message = outcome.expect_err("no sign-in means no account to classify against");
    assert!(
        message.contains("sign in"),
        "the refusal must name what is missing, got {message}"
    );
    assert_eq!(
        fetch.calls(),
        0,
        "a device with no account must not be made to fetch"
    );
}

#[tokio::test]
async fn a_peer_of_this_devices_own_account_is_same_account() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
}

#[tokio::test]
async fn a_peer_of_a_linked_account_is_linked() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, LINKED_SUB, AUD, &peer, NOW);

    let outcome = classify(
        &trust,
        &peer,
        &token,
        Some(&own_account()),
        &[linked_account()],
    )
    .await;

    assert_eq!(outcome, Ok(TrustTier::Linked));
}

#[tokio::test]
async fn a_peer_of_an_account_that_is_neither_is_refused_rather_than_downgraded() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, STRANGER_SUB, AUD, &peer, NOW);

    let outcome = classify(
        &trust,
        &peer,
        &token,
        Some(&own_account()),
        &[linked_account()],
    )
    .await;

    assert!(
        outcome.is_err(),
        "ephemeral receive is off, so an unknown account is a refusal and never a lower tier, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_bound_to_another_devices_keys_is_refused_when_replayed() {
    let victim = identity(1);
    let attacker = identity(9);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    // Google really signed this, for the victim's account and the
    // victim's keys. The attacker presents it unaltered over a channel
    // authenticated as their own device.
    let stolen = token(KID, OWN_SUB, AUD, &victim, NOW);

    let outcome = classify(&trust, &attacker, &stolen, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "the nonce binds the victim's keys, not the presenter's, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_signed_by_a_key_the_provider_never_published_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[impostor_key(KID)],
        CountingFetch::serving(&[impostor_key(KID)]),
    );
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "the kid resolves and the signature does not verify under it, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_older_than_the_staleness_limit_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let issued = NOW - (STALENESS_LIMIT_SECS as i64) - 1;
    let token = token(KID, OWN_SUB, AUD, &peer, issued);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "an Attestation older than docs/05's limit is refused, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_for_another_deployments_audience_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, OWN_SUB, OTHER_AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "aud must be in this deployment's client set, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_rotated_key_is_fetched_once_and_then_verifies() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID), published_key(ROTATED_KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(ROTATED_KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
    assert_eq!(fetch.calls(), 1, "exactly one fetch, and no retry loop");
    assert_eq!(
        fetch.uris(),
        vec![JWKS_URI.to_string()],
        "a refetch goes to the provider's JWKS uri and to nothing else"
    );
}

#[tokio::test]
async fn the_cache_stays_warm_across_connections() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID), published_key(ROTATED_KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(ROTATED_KID, OWN_SUB, AUD, &peer, NOW);

    for _ in 0..3 {
        let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;
        assert_eq!(outcome, Ok(TrustTier::SameAccount));
    }

    assert_eq!(
        fetch.calls(),
        1,
        "the document a connection fetched must serve the connections after it"
    );
}

#[tokio::test]
async fn a_peer_naming_an_unknown_key_cannot_drive_a_fetch_per_connection() {
    let peer = identity(1);
    // The document never carries the kid the peer names, so every
    // verification ends unresolved. Only the refetch budget stands
    // between that and one outbound request per connection.
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token("a-kid-nobody-published", OWN_SUB, AUD, &peer, NOW);

    for _ in 0..5 {
        let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;
        assert!(outcome.is_err(), "an unresolvable kid grants nothing");
    }

    assert_eq!(
        fetch.calls(),
        1,
        "docs/05's refetch floor bounds this at one, whatever the peer sends"
    );
}

#[tokio::test]
async fn a_fetch_that_fails_refuses_rather_than_granting_a_tier() {
    let peer = identity(1);
    let fetch = CountingFetch::failing();
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(ROTATED_KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "an unreachable provider is a refusal, never a tier, got {outcome:?}"
    );
    assert_eq!(fetch.calls(), 1);
}

#[tokio::test]
async fn a_malformed_token_is_refused_without_reaching_the_provider() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());

    let outcome = classify(&trust, &peer, "not-a-jwt", Some(&own_account()), &[]).await;

    assert!(outcome.is_err(), "a malformed token grants nothing");
    assert_eq!(
        fetch.calls(),
        0,
        "a token that does not parse must not cost an outbound request"
    );
}

#[tokio::test]
async fn an_empty_token_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );

    let outcome = classify(&trust, &peer, "", Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "the empty token a device carries before it signs in grants nothing"
    );
}

// The four below are WI-M7-012's, written before the implementation
// (CLAUDE.md section 6) against DCR-110. What they are about is the state
// of the cache at the moment the first peer arrives, which every test
// above reaches past by warming a fixture by hand.

#[tokio::test]
async fn a_cold_cache_cannot_classify_anyone_with_the_provider_unreachable() {
    let peer = identity(1);
    let fetch = CountingFetch::failing();
    let trust = PeerTrust::new(profile(), fetch.clone());
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "this is the defect DCR-110 names: a device that went offline refuses \
         the first peer it meets after every start"
    );
    assert_eq!(
        fetch.calls(),
        1,
        "and it refuses it having gone to the network for a key it could have held"
    );
}

#[tokio::test]
async fn a_cache_warmed_at_sign_in_classifies_a_peer_with_the_provider_unreachable() {
    let peer = identity(1);
    let fetch = CountingFetch::failing();
    let trust = PeerTrust::new(profile(), fetch.clone());
    trust
        .install(JWKS_URI, &document(&[published_key(KID)]))
        .expect("the document this device's own sign-in already fetched");
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert_eq!(
        outcome,
        Ok(TrustTier::SameAccount),
        "offline verification against an existing cache is what keeps Tier 0 serverless"
    );
    assert_eq!(
        fetch.calls(),
        0,
        "a warm cache reaches no network at all, which is the whole property"
    );
}

#[tokio::test]
async fn a_document_offered_under_another_uri_is_refused() {
    let trust = PeerTrust::new(profile(), CountingFetch::failing());

    let outcome = trust.install(
        "https://impostor.example/certs",
        &document(&[published_key(KID)]),
    );

    assert!(
        outcome.is_err(),
        "a cache bound to one provider must not accept a document a caller \
         says came from another"
    );
}

#[tokio::test]
async fn a_refused_document_installs_nothing() {
    let peer = identity(1);
    let fetch = CountingFetch::failing();
    let trust = PeerTrust::new(profile(), fetch.clone());
    let refused = trust.install(
        "https://impostor.example/certs",
        &document(&[published_key(KID)]),
    );
    assert!(refused.is_err(), "the precondition this test stands on");
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "a refusal that still installed the keys would be a refusal in the \
         message and nowhere else"
    );
    assert_eq!(
        fetch.calls(),
        1,
        "the cache is still cold, so the classification still reaches for a fetch"
    );
}

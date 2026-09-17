//! Supervisor-authored tests for WI-M8-003, written before the
//! implementation (CLAUDE.md section 6). Verification itself is tested in
//! `tradr-identity`; what is new here is the wiring DF-60 recorded as
//! unreachable -- which uri a completed sign-in fetches, what it installs,
//! and what a peer connection can read out of the cache afterwards.

mod common;

use std::sync::Arc;

use common::{
    AUD, CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, STALENESS_LIMIT_SECS, clock_at, identity,
    impostor_key, profile, published_key, token,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_app::sign_in::{OAuthConfig, SignInState, finish_sign_in, provider_profile};
use tradr_core::{PublicIdentity, TrustTier};
use tradr_identity::AccountId;

// The device signing in. A second seed is another device, which is what
// the replay test presents.
fn this_device() -> PublicIdentity {
    identity(1)
}

fn trust_over(fetch: Arc<CountingFetch>) -> PeerTrust {
    PeerTrust::new(profile(), fetch)
}

async fn complete(
    state: &SignInState,
    trust: &PeerTrust,
    device: &PublicIdentity,
    id_token: &str,
) -> Result<(), String> {
    finish_sign_in(
        &profile(),
        device,
        id_token.to_string(),
        trust,
        state,
        &clock_at(NOW),
    )
    .await
    .map(|_| ())
}

fn own_account() -> AccountId {
    AccountId::new(ISS, OWN_SUB)
}

#[tokio::test]
async fn a_completed_sign_in_records_the_account_its_token_names() {
    let device = this_device();
    let state = SignInState::empty();
    let trust = trust_over(CountingFetch::serving(&[published_key(KID)]));
    let id_token = token(KID, OWN_SUB, AUD, &device, NOW);

    complete(&state, &trust, &device, &id_token)
        .await
        .expect("a token this provider signed, bound to this device");

    assert_eq!(state.own_account(), Some(own_account()));
    assert_eq!(state.id_token().as_deref(), Some(id_token.as_str()));
}

#[tokio::test]
async fn a_sign_in_fetches_the_providers_jwks_uri_and_nothing_else() {
    let device = this_device();
    let state = SignInState::empty();
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_over(fetch.clone());
    let id_token = token(KID, OWN_SUB, AUD, &device, NOW);

    complete(&state, &trust, &device, &id_token)
        .await
        .expect("a token this provider signed, bound to this device");

    assert_eq!(fetch.uris(), vec![JWKS_URI.to_string()]);
}

#[tokio::test]
async fn a_sign_in_warms_the_cache_the_next_peer_connection_reads() {
    let device = this_device();
    let peer = identity(7);
    let state = SignInState::empty();
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_over(fetch.clone());

    complete(
        &state,
        &trust,
        &device,
        &token(KID, OWN_SUB, AUD, &device, NOW),
    )
    .await
    .expect("a token this provider signed, bound to this device");

    let tier = trust
        .classify(
            &token(KID, OWN_SUB, AUD, &peer, NOW),
            peer.identity_pub(),
            peer.agreement_pub(),
            state.own_account().as_ref(),
            &[],
            &clock_at(NOW),
        )
        .await
        .expect("the sign-in published this key already");

    assert_eq!(tier, TrustTier::SameAccount);
    assert_eq!(
        fetch.calls(),
        1,
        "the peer connection refetched, so the sign-in installed nothing"
    );
}

#[tokio::test]
async fn a_token_signed_by_a_key_the_provider_never_published_leaves_the_device_signed_out() {
    let device = this_device();
    let state = SignInState::empty();
    let trust = trust_over(CountingFetch::serving(&[impostor_key(KID)]));
    let id_token = token(KID, OWN_SUB, AUD, &device, NOW);

    let refusal = complete(&state, &trust, &device, &id_token).await;

    assert!(refusal.is_err(), "got {refusal:?}");
    assert_eq!(state.own_account(), None);
    assert_eq!(state.id_token(), None);
}

#[tokio::test]
async fn a_provider_that_cannot_be_reached_leaves_the_device_signed_out() {
    let device = this_device();
    let state = SignInState::empty();
    let trust = trust_over(CountingFetch::failing());
    let id_token = token(KID, OWN_SUB, AUD, &device, NOW);

    let refusal = complete(&state, &trust, &device, &id_token).await;

    assert!(refusal.is_err(), "got {refusal:?}");
    assert_eq!(state.id_token(), None);
}

#[tokio::test]
async fn a_token_older_than_the_staleness_limit_leaves_the_device_signed_out() {
    let device = this_device();
    let state = SignInState::empty();
    let trust = trust_over(CountingFetch::serving(&[published_key(KID)]));
    let issued = NOW - (STALENESS_LIMIT_SECS as i64) - 1;
    let id_token = token(KID, OWN_SUB, AUD, &device, issued);

    let refusal = complete(&state, &trust, &device, &id_token).await;

    assert!(refusal.is_err(), "got {refusal:?}");
    assert_eq!(state.id_token(), None);
}

#[tokio::test]
async fn a_token_bound_to_another_devices_keys_leaves_this_device_signed_out() {
    let device = this_device();
    let other = identity(9);
    let state = SignInState::empty();
    let trust = trust_over(CountingFetch::serving(&[published_key(KID)]));
    let id_token = token(KID, OWN_SUB, AUD, &other, NOW);

    let refusal = complete(&state, &trust, &device, &id_token).await;

    assert!(refusal.is_err(), "got {refusal:?}");
    assert_eq!(state.id_token(), None);
}

#[tokio::test]
async fn a_second_sign_in_replaces_the_token_a_peer_is_handed() {
    let device = this_device();
    let state = SignInState::empty();
    let trust = trust_over(CountingFetch::serving(&[published_key(KID)]));
    let first = token(KID, OWN_SUB, AUD, &device, NOW - 60);
    let second = token(KID, OWN_SUB, AUD, &device, NOW);

    complete(&state, &trust, &device, &first)
        .await
        .expect("a token this provider signed, bound to this device");
    complete(&state, &trust, &device, &second)
        .await
        .expect("a token this provider signed, bound to this device");

    assert_ne!(
        first, second,
        "the fixture must produce two distinct tokens"
    );
    assert_eq!(state.id_token().as_deref(), Some(second.as_str()));
}

#[test]
fn oauth_config_new_survives_real_value() {
    let cfg = OAuthConfig::new(
        Some("client-id-123".to_string()),
        Some("client-secret-xyz".to_string()),
    );
    assert_eq!(cfg.client_ids.as_deref(), Some("client-id-123"));
    assert_eq!(cfg.client_secret.as_deref(), Some("client-secret-xyz"));
}

#[test]
fn oauth_config_new_empty_string_becomes_none() {
    let cfg = OAuthConfig::new(Some("".to_string()), Some("".to_string()));
    assert_eq!(cfg.client_ids, None);
    assert_eq!(cfg.client_secret, None);
}

#[test]
fn oauth_config_new_whitespace_only_becomes_none() {
    let cfg = OAuthConfig::new(Some("   ".to_string()), Some("   ".to_string()));
    assert_eq!(cfg.client_ids, None);
    assert_eq!(cfg.client_secret, None);
}

#[test]
fn oauth_config_new_trims_surrounding_whitespace() {
    let cfg = OAuthConfig::new(
        Some("  client-id-123 \t ".to_string()),
        Some(" \n client-secret-xyz  ".to_string()),
    );
    assert_eq!(cfg.client_ids.as_deref(), Some("client-id-123"));
    assert_eq!(cfg.client_secret.as_deref(), Some("client-secret-xyz"));
}

#[test]
#[cfg(not(target_os = "android"))]
fn a_desktop_profile_carries_the_configured_client_secret() {
    let profile = provider_profile(&OAuthConfig::new(
        Some("desktop:desktop-id,web:web-id".to_string()),
        Some("  desktop-secret  ".to_string()),
    ))
    .expect("valid desktop oauth config");
    assert_eq!(profile.client_id, "desktop-id");
    assert_eq!(profile.client_secret.as_deref(), Some("desktop-secret"));
}

#[test]
#[cfg(not(target_os = "android"))]
fn a_desktop_profile_with_no_client_secret_is_refused() {
    let result = provider_profile(&OAuthConfig::new(
        Some("desktop:desktop-id,web:web-id".to_string()),
        None,
    ));
    assert!(result.is_err());
}

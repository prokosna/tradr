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
#[cfg(not(target_os = "android"))]
use tradr_app::sign_in::{
    CALLBACK_PORT, bind_callback_listener, bind_callback_with_fallback,
    browser_unavailable_message, callback_bind_addresses, code_from_pasted, ssh_forward_command,
};
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

#[test]
#[cfg(not(target_os = "android"))]
fn callback_bind_addresses_answers_the_default_port_then_an_ephemeral_fallback() {
    let (default_addr, fallback_addr) =
        callback_bind_addresses().expect("callback bind addresses must parse");

    assert_eq!(default_addr.port(), CALLBACK_PORT);
    assert_eq!(default_addr.port(), 21821);
    assert_eq!(fallback_addr.port(), 0);
    assert_eq!(
        default_addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        fallback_addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
}

#[test]
#[cfg(not(target_os = "android"))]
fn bind_callback_listener_falls_back_to_ephemeral_port_when_default_is_taken() {
    let _holder = std::net::TcpListener::bind("127.0.0.1:21821").ok();
    let listener = bind_callback_listener().expect("bind must succeed on fallback port");
    let bound_port = listener.local_addr().expect("local address").port();
    assert_ne!(bound_port, 21821);
    assert_ne!(bound_port, 0);
}

#[test]
#[cfg(not(target_os = "android"))]
fn bind_callback_with_fallback_binds_default_when_free() {
    let s1 = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    let free_port = s1.local_addr().expect("local addr").port();
    drop(s1);
    let s2 = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    let fallback_port = s2.local_addr().expect("local addr").port();
    drop(s2);

    let default_addr = std::net::SocketAddr::from(([127, 0, 0, 1], free_port));
    let fallback_addr = std::net::SocketAddr::from(([127, 0, 0, 1], fallback_port));

    let listener = bind_callback_with_fallback(default_addr, fallback_addr)
        .expect("bind must succeed on free default address");
    assert_eq!(listener.local_addr().expect("local addr").port(), free_port);
}

#[test]
#[cfg(not(target_os = "android"))]
fn ssh_forward_command_names_the_port_actually_bound() {
    let line = ssh_forward_command(21821);
    assert_eq!(line, "ssh -L 21821:localhost:21821 USER@HOST");

    let _holder = std::net::TcpListener::bind("127.0.0.1:21821").ok();
    let listener = bind_callback_listener().expect("bind callback listener");
    let bound_port = listener.local_addr().expect("local address").port();
    let fallback_line = ssh_forward_command(bound_port);
    assert_eq!(
        fallback_line,
        format!("ssh -L {bound_port}:localhost:{bound_port} USER@HOST")
    );
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_isolates_auth_url_on_its_own_line() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error =
        format!("Launcher \"xdg-open\" \"{url}\" failed with ExitStatus(unix_wait_status(768))");
    let message = browser_unavailable_message(url, &launcher_error, 21821, false);

    assert_eq!(message.matches(url).count(), 1);
    assert_eq!(message.lines().filter(|&line| line == url).count(), 1);
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_preserves_launcher_name_and_exit_status() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error =
        format!("Launcher \"xdg-open\" \"{url}\" failed with ExitStatus(unix_wait_status(768))");
    let message = browser_unavailable_message(url, &launcher_error, 21821, false);

    assert!(
        message.contains(
            "Launcher \"xdg-open\" \"<url>\" failed with ExitStatus(unix_wait_status(768))"
        )
    );
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_redacts_multiple_url_occurrences_in_launcher_error() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error =
        format!("Launcher \"xdg-open\" \"{url}\" failed; fallback \"gio\" \"{url}\" failed");
    let message = browser_unavailable_message(url, &launcher_error, 21821, false);

    assert_eq!(message.matches(url).count(), 1);
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_preserves_launcher_error_without_url() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error = "No such file or directory (os error 2)";
    let message = browser_unavailable_message(url, launcher_error, 21821, false);

    assert_eq!(message.matches(url).count(), 1);
    assert!(message.contains(launcher_error));
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_includes_port_forward_command() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error = "No such file or directory (os error 2)";
    let message = browser_unavailable_message(url, launcher_error, 43210, false);

    let expected_forward = ssh_forward_command(43210);
    assert!(message.lines().any(|line| line == expected_forward));
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_with_paste_orders_paste_before_forward() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error = "No such file or directory (os error 2)";
    let message = browser_unavailable_message(url, launcher_error, 21821, true);

    assert_eq!(message.matches(url).count(), 1);
    assert_eq!(message.lines().filter(|&line| line == url).count(), 1);

    let paste_line = "after signing in, that browser lands on a page that does not load; copy its whole address and paste it here, then press Enter";
    let forward_line = ssh_forward_command(21821);

    let lines: Vec<&str> = message.lines().collect();
    assert_eq!(lines.len(), 6);
    assert!(lines.contains(&paste_line));
    assert!(lines.contains(&forward_line.as_str()));

    let paste_idx = lines
        .iter()
        .position(|&l| l == paste_line)
        .expect("paste line present");
    let forward_idx = lines
        .iter()
        .position(|&l| l == forward_line.as_str())
        .expect("forward line present");
    assert_eq!(paste_idx, 2);
    assert_eq!(forward_idx, 4);
    assert!(paste_idx < forward_idx);
}

#[test]
#[cfg(not(target_os = "android"))]
fn browser_unavailable_message_with_false_omits_paste() {
    let url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=0123&nonce=xyz";
    let launcher_error = "No such file or directory (os error 2)";
    let message = browser_unavailable_message(url, launcher_error, 21821, false);

    assert!(!message.lines().any(|line| line.contains("paste")));
}

#[test]
#[cfg(not(target_os = "android"))]
fn code_from_pasted_accepts_valid_address_formats() {
    let full = "http://127.0.0.1:21821/callback?code=abc&state=s1";
    assert_eq!(code_from_pasted(full, "s1"), Ok("abc".to_string()));

    let bare = "code=abc&state=s1";
    assert_eq!(code_from_pasted(bare, "s1"), Ok("abc".to_string()));

    let leading_q = "?code=abc&state=s1";
    assert_eq!(code_from_pasted(leading_q, "s1"), Ok("abc".to_string()));

    let padded = "  http://127.0.0.1:21821/callback?code=abc&state=s1  \n";
    assert_eq!(code_from_pasted(padded, "s1"), Ok("abc".to_string()));
}

#[test]
#[cfg(not(target_os = "android"))]
fn code_from_pasted_accepts_code_containing_question_mark() {
    let address = "http://127.0.0.1:21821/callback?code=abc?def&state=s1";
    assert_eq!(code_from_pasted(address, "s1"), Ok("abc?def".to_string()));
}

#[test]
#[cfg(not(target_os = "android"))]
fn code_from_pasted_refuses_invalid_inputs() {
    assert_eq!(
        code_from_pasted("", "s1"),
        Err("nothing was pasted".to_string())
    );
    assert_eq!(
        code_from_pasted("   \n\t  ", "s1"),
        Err("nothing was pasted".to_string())
    );

    let wrong_state = "http://127.0.0.1:21821/callback?code=abc&state=wrong";
    assert!(code_from_pasted(wrong_state, "s1").is_err());

    let error_resp = "http://127.0.0.1:21821/callback?error=access_denied&state=s1";
    let error_res = code_from_pasted(error_resp, "s1");
    assert!(error_res.is_err());
    assert!(error_res.unwrap_err().contains("access_denied"));

    let repeated = "http://127.0.0.1:21821/callback?code=abc&code=def&state=s1";
    let repeated_res = code_from_pasted(repeated, "s1");
    assert!(repeated_res.is_err());
    assert!(repeated_res.unwrap_err().contains("repeated"));
}

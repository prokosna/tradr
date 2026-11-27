//! Background renewal: when it is due, and what a silent request does with
//! a provider that refuses to answer without a person.
#![cfg(not(target_os = "android"))]

mod common;

use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

use common::profile;
use tradr_app::kept_sign_in::{RENEWAL_AFTER_SECS, SIGN_IN_REUSE_LIMIT_SECS, renewal_due};
use tradr_app::sign_in::obtain_id_token_silent_desktop;
use tradr_core::UnixTime;

const IAT: i64 = 1_800_000_000;

fn due_at(age_secs: i64) -> bool {
    renewal_due(
        UnixTime::from_secs(IAT),
        UnixTime::from_secs(IAT + age_secs),
    )
}

#[test]
fn renewal_is_due_at_exactly_fourteen_days() {
    assert!(due_at(RENEWAL_AFTER_SECS as i64));
}

#[test]
fn renewal_is_not_due_one_second_before_fourteen_days() {
    assert!(!due_at(RENEWAL_AFTER_SECS as i64 - 1));
}

#[test]
fn renewal_is_due_for_a_token_past_the_reuse_limit() {
    assert!(due_at(SIGN_IN_REUSE_LIMIT_SECS as i64 + 1));
}

#[test]
fn renewal_is_not_due_for_a_token_dated_in_the_future() {
    assert!(!due_at(-1));
    assert!(!due_at(-(RENEWAL_AFTER_SECS as i64) * 10));
}

fn query_value(url: &str, key: &str) -> String {
    reqwest::Url::parse(url)
        .expect("authorization url parses")
        .query_pairs()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("{key} missing from {url}"))
        .1
        .into_owned()
}

// Plays the provider: reports the url it was opened with, then answers the
// loopback redirect with `callback_query` (its `{state}` filled in).
fn provider_answering(
    callback_query: String,
    seen: mpsc::Sender<String>,
) -> impl FnOnce(&str) -> Result<(), String> {
    move |auth_url: &str| {
        let state = query_value(auth_url, "state");
        let redirect = query_value(auth_url, "redirect_uri");
        let port: u16 = redirect
            .strip_prefix("http://127.0.0.1:")
            .and_then(|rest| rest.split('/').next())
            .and_then(|p| p.parse().ok())
            .expect("loopback redirect with a port");
        seen.send(auth_url.to_string()).expect("test is listening");
        let query = callback_query.replace("{state}", &state);
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to callback");
            let request = format!("GET /callback?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .expect("write callback");
        });
        Ok(())
    }
}

// A token endpoint that is not https makes any exchange attempt fail with a
// message of its own, so "no exchange happened" is observable.
fn profile_that_cannot_exchange() -> tradr_identity::ProviderProfile {
    let mut p = profile();
    p.token_uri = "http://token.invalid/".to_string();
    p
}

#[tokio::test]
async fn a_login_required_callback_is_a_failure_and_no_exchange_is_attempted() {
    for error in ["login_required", "consent_required", "interaction_required"] {
        let (tx, rx) = mpsc::channel();
        let query = format!("error={error}&state={{state}}");
        let result = obtain_id_token_silent_desktop(
            &profile_that_cannot_exchange(),
            "the-nonce",
            "own-subject",
            provider_answering(query, tx),
            Duration::from_secs(30),
        )
        .await;

        let message = result.expect_err("a refusal is not a token");
        assert!(message.contains(error), "{message}");
        assert!(
            !message.contains("not https"),
            "exchange attempted: {message}"
        );

        let url = rx.recv().expect("the browser was opened");
        assert_eq!(query_value(&url, "prompt"), "none");
        assert_eq!(query_value(&url, "login_hint"), "own-subject");
        assert_eq!(query_value(&url, "nonce"), "the-nonce");
    }
}

#[tokio::test]
async fn a_callback_nobody_sends_times_out_instead_of_waiting() {
    let result = obtain_id_token_silent_desktop(
        &profile_that_cannot_exchange(),
        "the-nonce",
        "own-subject",
        |_| Ok(()),
        Duration::ZERO,
    )
    .await;

    assert_eq!(
        result,
        Err("sign-in was not completed in time; try again".to_string())
    );
}

#[tokio::test]
async fn a_browser_that_cannot_open_is_a_failure_without_waiting() {
    let result = obtain_id_token_silent_desktop(
        &profile_that_cannot_exchange(),
        "the-nonce",
        "own-subject",
        |_| Err("no browser".to_string()),
        Duration::from_secs(30),
    )
    .await;

    assert_eq!(result, Err("no browser".to_string()));
}

// A renewal adopts a token only for the account already signed in, so a
// silent flow that picks another Google account cannot switch accounts.
mod account_pinning {
    use super::common::{
        AUD, CountingFetch, ISS, KID, NOW, OWN_SUB, clock_at, identity, profile, published_key,
        token,
    };
    use tradr_app::peer_trust::PeerTrust;
    use tradr_app::sign_in::{SignInState, finish_renewal, finish_sign_in};
    use tradr_identity::AccountId;

    #[tokio::test]
    async fn a_renewal_for_another_account_is_refused_and_changes_nothing() {
        let device = identity(1);
        let state = SignInState::empty();
        let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
        let first = token(KID, OWN_SUB, AUD, &device, NOW);
        finish_sign_in(
            &profile(),
            &device,
            first.clone(),
            &trust,
            &state,
            &clock_at(NOW),
        )
        .await
        .expect("initial sign-in");
        let current = AccountId::new(ISS, OWN_SUB);

        let other = token(KID, "someone-else", AUD, &device, NOW + 60);
        let err = finish_renewal(
            &profile(),
            &device,
            other,
            &trust,
            &state,
            &current,
            &clock_at(NOW + 60),
        )
        .await
        .expect_err("a different account is refused");

        assert!(err.contains("different account"), "{err}");
        assert_eq!(state.own_account(), Some(current));
        assert_eq!(state.id_token().as_deref(), Some(first.as_str()));
    }

    #[tokio::test]
    async fn a_renewal_for_the_same_account_is_adopted() {
        let device = identity(1);
        let state = SignInState::empty();
        let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
        finish_sign_in(
            &profile(),
            &device,
            token(KID, OWN_SUB, AUD, &device, NOW),
            &trust,
            &state,
            &clock_at(NOW),
        )
        .await
        .expect("initial sign-in");
        let current = AccountId::new(ISS, OWN_SUB);

        let renewed = token(KID, OWN_SUB, AUD, &device, NOW + 60);
        finish_renewal(
            &profile(),
            &device,
            renewed.clone(),
            &trust,
            &state,
            &current,
            &clock_at(NOW + 60),
        )
        .await
        .expect("same account is adopted");

        assert_eq!(state.id_token().as_deref(), Some(renewed.as_str()));
    }
}

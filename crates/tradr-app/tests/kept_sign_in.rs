//! Tests for kept sign-in loading, keeping, and resumption (WI-M8-040, DCR-150).

mod common;

use std::path::Path;

use common::{
    AUD, CountingFetch, KID, NOW, OWN_SUB, STALENESS_LIMIT_SECS, clock_at, identity, profile,
    published_key, token,
};
use tradr_app::kept_sign_in::{SIGN_IN_REUSE_LIMIT_SECS, keep_token, load_kept_token};
use tradr_app::paths;
use tradr_app::peer_trust::PeerTrust;
use tradr_app::sign_in::{SignInState, resume_sign_in};

#[tokio::test]
async fn resume_sign_in_accepts_a_token_issued_at_now_and_sets_the_states_id_token() {
    let device = identity(1);
    let state = SignInState::empty();
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    let id_token = token(KID, OWN_SUB, AUD, &device, NOW);

    let outcome = resume_sign_in(
        &profile(),
        &device,
        id_token.clone(),
        &trust,
        &state,
        &clock_at(NOW),
    )
    .await;

    assert!(outcome.is_ok(), "got {outcome:?}");
    assert_eq!(state.id_token().as_deref(), Some(id_token.as_str()));
}

#[tokio::test]
async fn resume_sign_in_accepts_a_token_exactly_sign_in_reuse_limit_secs_old() {
    let device = identity(1);
    let state = SignInState::empty();
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    let issued = NOW - (SIGN_IN_REUSE_LIMIT_SECS as i64);
    let id_token = token(KID, OWN_SUB, AUD, &device, issued);

    let outcome = resume_sign_in(
        &profile(),
        &device,
        id_token.clone(),
        &trust,
        &state,
        &clock_at(NOW),
    )
    .await;

    assert!(outcome.is_ok(), "got {outcome:?}");
    assert_eq!(state.id_token().as_deref(), Some(id_token.as_str()));
}

#[tokio::test]
async fn resume_sign_in_refuses_one_second_older_with_the_exact_error_text_and_leaves_state_id_token_none()
 {
    let device = identity(1);
    let state = SignInState::empty();
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    let issued = NOW - (SIGN_IN_REUSE_LIMIT_SECS as i64) - 1;
    let id_token = token(KID, OWN_SUB, AUD, &device, issued);

    let outcome = resume_sign_in(
        &profile(),
        &device,
        id_token,
        &trust,
        &state,
        &clock_at(NOW),
    )
    .await;

    assert_eq!(
        outcome.unwrap_err(),
        "kept sign-in is 21 days old, past the 21 day reuse limit"
    );
    assert_eq!(state.id_token(), None);
}

#[tokio::test]
async fn resume_sign_in_refuses_a_token_bound_to_another_devices_keys_and_leaves_the_state_none() {
    let device = identity(1);
    let other = identity(9);
    let state = SignInState::empty();
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    let id_token = token(KID, OWN_SUB, AUD, &other, NOW);

    let outcome = resume_sign_in(
        &profile(),
        &device,
        id_token,
        &trust,
        &state,
        &clock_at(NOW),
    )
    .await;

    assert!(outcome.is_err(), "got {outcome:?}");
    assert_eq!(state.id_token(), None);
}

#[test]
fn sign_in_reuse_limit_secs_equals_literal_and_is_below_staleness_limit() {
    assert_eq!(SIGN_IN_REUSE_LIMIT_SECS, 21 * 24 * 60 * 60);
    const { assert!(SIGN_IN_REUSE_LIMIT_SECS < STALENESS_LIMIT_SECS) };
}

#[test]
fn load_kept_token_on_a_missing_path_is_ok_none_and_on_whitespace_only_file_is_ok_none() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let missing = temp_dir.path().join("missing");
    assert_eq!(load_kept_token(&missing), Ok(None));

    let whitespace_path = temp_dir.path().join("whitespace");
    std::fs::write(&whitespace_path, "   \n\t  \r\n").expect("write whitespace");
    assert_eq!(load_kept_token(&whitespace_path), Ok(None));
}

#[test]
fn keep_token_then_load_kept_token_round_trips_a_token_and_a_second_keep_token_replaces_the_first()
{
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let token_path = temp_dir.path().join("attestation");

    keep_token(&token_path, "first-token").expect("first keep_token");
    assert_eq!(
        load_kept_token(&token_path),
        Ok(Some("first-token".to_string()))
    );

    keep_token(&token_path, "second-token").expect("second keep_token");
    assert_eq!(
        load_kept_token(&token_path),
        Ok(Some("second-token".to_string()))
    );
}

#[test]
fn keep_token_creates_a_missing_parent_directory() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let nested_path = temp_dir
        .path()
        .join("nested")
        .join("dir")
        .join("attestation");
    assert!(!nested_path.parent().expect("parent").exists());

    keep_token(&nested_path, "nested-token").expect("keep_token nested");
    assert_eq!(
        load_kept_token(&nested_path),
        Ok(Some("nested-token".to_string()))
    );
}

#[test]
#[cfg(unix)]
fn on_unix_the_kept_files_mode_is_0o600() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let token_path = temp_dir.path().join("attestation");

    keep_token(&token_path, "secret-token").expect("keep_token");
    let metadata = std::fs::metadata(&token_path).expect("metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[test]
fn paths_attestation_path_ends_in_attestation_under_dir() {
    let dir = Path::new("/some/app/data");
    assert_eq!(paths::attestation_path(dir), dir.join("attestation"));
}

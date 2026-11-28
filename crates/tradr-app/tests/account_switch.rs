//! Signing in as a different account: what counts as the previous account,
//! when the switch must be confirmed, and that verifying a token is not
//! adopting it.

mod common;

use common::{
    AUD, CountingFetch, ISS, KID, NOW, OWN_SUB, clock_at, identity, profile, published_key, token,
};
use tradr_app::account_switch::{
    PendingSwitch, keep_account_of_record, load_account_of_record, needs_confirmation,
    previous_account,
};
use tradr_app::paths::account_path;
use tradr_app::peer_trust::PeerTrust;
use tradr_app::sign_in::{SignInState, VerifiedSignIn, finish_sign_in, verify_sign_in};
use tradr_core::PublicIdentity;
use tradr_identity::AccountId;

const OTHER_SUB: &str = "other-subject";

fn this_device() -> PublicIdentity {
    identity(1)
}

fn trust() -> PeerTrust {
    PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]))
}

fn own_account() -> AccountId {
    AccountId::new(ISS, OWN_SUB)
}

fn other_account() -> AccountId {
    AccountId::new(ISS, OTHER_SUB)
}

async fn verified(sub: &str) -> VerifiedSignIn {
    let device = this_device();
    verify_sign_in(
        &profile(),
        &device,
        token(KID, sub, AUD, &device, NOW),
        &trust(),
        &clock_at(NOW),
    )
    .await
    .expect("a token this provider signed, bound to this device")
}

async fn signed_in_as(sub: &str) -> SignInState {
    let device = this_device();
    let state = SignInState::empty();
    finish_sign_in(
        &profile(),
        &device,
        token(KID, sub, AUD, &device, NOW),
        &trust(),
        &state,
        &clock_at(NOW),
    )
    .await
    .expect("a token this provider signed, bound to this device");
    state
}

// --- Verifying is not adopting ---

#[tokio::test]
async fn verifying_a_sign_in_names_its_account_and_leaves_the_device_as_it_was() {
    let state = signed_in_as(OWN_SUB).await;

    let pending = verified(OTHER_SUB).await;

    assert_eq!(pending.account(), other_account());
    assert_eq!(state.own_account(), Some(own_account()));
}

#[tokio::test]
async fn adopting_a_verified_sign_in_makes_it_the_devices_account_and_attestation() {
    let state = signed_in_as(OWN_SUB).await;
    let pending = verified(OTHER_SUB).await;
    let presented = pending.id_token().to_string();

    let outcome = state.adopt(pending);

    assert_eq!(outcome.subject, OTHER_SUB);
    assert_eq!(state.own_account(), Some(other_account()));
    assert_eq!(state.id_token().as_deref(), Some(presented.as_str()));
}

// --- Which account came before ---

#[tokio::test]
async fn the_live_sign_in_is_the_previous_account_over_the_record() {
    let state = signed_in_as(OWN_SUB).await;

    let previous = previous_account(&state, Some(other_account()));

    assert_eq!(previous, Some(own_account()));
}

#[test]
fn a_signed_out_device_falls_back_to_the_account_of_record() {
    let state = SignInState::empty();

    let previous = previous_account(&state, Some(own_account()));

    assert_eq!(previous, Some(own_account()));
}

#[test]
fn a_device_that_never_signed_in_has_no_previous_account() {
    assert_eq!(previous_account(&SignInState::empty(), None), None);
}

// --- When to ask ---

#[test]
fn a_first_sign_in_needs_no_confirmation() {
    assert!(!needs_confirmation(None, &own_account()));
}

#[test]
fn signing_in_as_the_same_account_needs_no_confirmation() {
    assert!(!needs_confirmation(Some(&own_account()), &own_account()));
}

#[test]
fn signing_in_as_another_account_needs_confirmation() {
    assert!(needs_confirmation(Some(&own_account()), &other_account()));
}

#[test]
fn the_same_subject_under_another_issuer_is_another_account() {
    let elsewhere = AccountId::new("https://issuer.example", OWN_SUB);

    assert!(needs_confirmation(Some(&own_account()), &elsewhere));
}

// --- The account of record on disk ---

#[test]
fn the_account_of_record_survives_a_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = account_path(dir.path());

    keep_account_of_record(&path, &own_account()).expect("keep");

    assert_eq!(
        load_account_of_record(&path).expect("load"),
        Some(own_account())
    );
}

#[test]
fn a_device_without_a_record_has_no_account_of_record() {
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(
        load_account_of_record(&account_path(dir.path())).expect("load"),
        None
    );
}

#[test]
fn an_unreadable_record_is_an_error_rather_than_no_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = account_path(dir.path());
    std::fs::write(&path, b"not a record").expect("write");

    assert!(load_account_of_record(&path).is_err());
}

// --- The switch waiting for an answer ---

#[tokio::test]
async fn a_held_switch_is_handed_out_once() {
    let pending = PendingSwitch::default();
    pending.hold(verified(OTHER_SUB).await);

    let taken = pending.take().expect("the held switch");

    assert_eq!(taken.account(), other_account());
    assert!(pending.take().is_none());
}

#[tokio::test]
async fn a_discarded_switch_cannot_be_confirmed() {
    let pending = PendingSwitch::default();
    pending.hold(verified(OTHER_SUB).await);

    pending.discard();

    assert!(pending.take().is_none());
}

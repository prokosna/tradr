//! Tests for `Invite` (docs/11-account-linking.md, "What the Invite
//! carries, and how it travels"). Each negative case here was checked to
//! genuinely fail against a broken implementation before being restored
//! (rule E1).

use tradr_core::{DisplayName, HalfSecret, Invite, InviteId, PublicKeyPoint, UnixTime};

fn invite_id(fill: u8) -> InviteId {
    InviteId::from_bytes(&[fill; 16]).expect("16 bytes must construct")
}

fn identity_pub() -> PublicKeyPoint {
    PublicKeyPoint::from_bytes(&[0x01; 65]).expect("65 bytes must construct")
}

fn agreement_pub() -> PublicKeyPoint {
    PublicKeyPoint::from_bytes(&[0x02; 65]).expect("65 bytes must construct")
}

fn half_secret(fill: u8) -> HalfSecret {
    HalfSecret::from_bytes(&[fill; 16]).expect("16 bytes must construct")
}

fn invite() -> Invite {
    Invite::new(
        invite_id(0x11),
        identity_pub(),
        agreement_pub(),
        "an-attestation-token".to_string(),
        half_secret(0x22),
        UnixTime::from_secs(1_000),
    )
}

#[test]
fn accessors_return_fields_unchanged() {
    let invite = invite();

    assert_eq!(invite.invite_id(), &invite_id(0x11));
    assert_eq!(invite.identity_pub(), &identity_pub());
    assert_eq!(invite.agreement_pub(), &agreement_pub());
    assert_eq!(invite.attestation_token(), "an-attestation-token");
    assert_eq!(
        invite.half_secret().as_bytes(),
        half_secret(0x22).as_bytes()
    );
    assert_eq!(invite.expires_at(), UnixTime::from_secs(1_000));
    assert_eq!(invite.display_name(), None);
}

#[test]
fn with_display_name_sets_it() {
    let name = DisplayName::new("Alice's Phone").expect("valid display name");
    let invite = invite().with_display_name(name.clone());

    assert_eq!(invite.display_name(), Some(&name));
}

#[test]
fn debug_redacts_the_attestation_token() {
    // The token is chosen to be easy to search for, so removing the
    // redaction makes this test fail rather than pass by coincidence.
    let secret_token = "SEARCHABLE-BEARER-TOKEN-VALUE";
    let invite = Invite::new(
        invite_id(0x33),
        identity_pub(),
        agreement_pub(),
        secret_token.to_string(),
        half_secret(0x22),
        UnixTime::from_secs(1_000),
    );

    let rendered = format!("{invite:?}").to_lowercase();

    // A !contains check alone would still pass if the field vanished from
    // Debug entirely, so the field's presence is asserted too.
    assert!(rendered.contains("attestation_token"));
    assert!(!rendered.contains(&secret_token.to_lowercase()));
    assert!(rendered.contains("[redacted]"));
}

#[test]
fn debug_redacts_the_half_secret_in_hex_and_decimal() {
    // 0xAB is chosen to be easy to search for in either rendering: hex
    // ("ab") or the decimal a derived `Debug` on `[u8; 16]` would print
    // ("171"), so removing the redaction makes this fail rather than pass
    // by coincidence.
    let invite = Invite::new(
        invite_id(0x33),
        identity_pub(),
        agreement_pub(),
        "token".to_string(),
        half_secret(0xAB),
        UnixTime::from_secs(1_000),
    );

    let rendered = format!("{invite:?}").to_lowercase();

    assert!(!rendered.contains("ab"));
    assert!(!rendered.contains("171"));
    assert!(rendered.contains("halfsecret(<redacted>)"));
}

#[test]
fn is_expired_is_false_strictly_before_the_expiry() {
    let invite = invite();

    assert!(!invite.is_expired(UnixTime::from_secs(999), 0));
}

#[test]
fn is_expired_is_false_at_exactly_the_expiry() {
    let invite = invite();

    assert!(!invite.is_expired(UnixTime::from_secs(1_000), 0));
}

#[test]
fn is_expired_is_false_at_exactly_expiry_plus_skew() {
    let invite = invite();

    assert!(!invite.is_expired(UnixTime::from_secs(1_060), 60));
}

#[test]
fn is_expired_is_true_one_second_past_expiry_plus_skew() {
    let invite = invite();

    assert!(invite.is_expired(UnixTime::from_secs(1_061), 60));
}

#[test]
fn is_expired_is_true_one_second_past_expiry_with_zero_skew() {
    let invite = invite();

    assert!(invite.is_expired(UnixTime::from_secs(1_001), 0));
}

#[test]
fn is_expired_with_max_skew_never_reports_expired() {
    let invite = invite();

    assert!(!invite.is_expired(UnixTime::from_secs(i64::MAX), u64::MAX));
}

#[test]
fn is_expired_with_max_expires_at_never_reports_expired() {
    let invite = Invite::new(
        invite_id(0x11),
        identity_pub(),
        agreement_pub(),
        "token".to_string(),
        half_secret(0x22),
        UnixTime::from_secs(i64::MAX),
    );

    assert!(!invite.is_expired(UnixTime::from_secs(i64::MAX), 0));
}

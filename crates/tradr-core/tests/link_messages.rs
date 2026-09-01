//! Tests for the three linking messages (docs/11-account-linking.md, "What
//! the three linking messages carry"). Each negative case here was checked
//! to genuinely fail against a broken implementation before being restored
//! (rule E1).

use tradr_core::{
    DisplayName, HalfSecret, InviteId, LinkApprove, LinkDecline, LinkDeclineReason,
    LinkDeclineReasonError, LinkId, LinkReply, PublicKeyPoint,
};

fn invite_id(fill: u8) -> InviteId {
    InviteId::from_bytes(&[fill; 16]).expect("16 bytes must construct")
}

fn link_id(fill: u8) -> LinkId {
    LinkId::from_bytes(&[fill; 16]).expect("16 bytes must construct")
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

#[test]
fn link_reply_accessors_return_fields_unchanged() {
    let reply = LinkReply::new(
        invite_id(0x11),
        identity_pub(),
        agreement_pub(),
        "an-attestation-token".to_string(),
        half_secret(0x22),
    );

    assert_eq!(reply.invite_id(), &invite_id(0x11));
    assert_eq!(reply.identity_pub(), &identity_pub());
    assert_eq!(reply.agreement_pub(), &agreement_pub());
    assert_eq!(reply.attestation_token(), "an-attestation-token");
    assert_eq!(reply.half_secret().as_bytes(), half_secret(0x22).as_bytes());
    assert_eq!(reply.display_name(), None);
}

#[test]
fn link_reply_with_display_name_sets_it() {
    let name = DisplayName::new("Bob's Pixel").expect("valid display name");
    let reply = LinkReply::new(
        invite_id(0x11),
        identity_pub(),
        agreement_pub(),
        "token".to_string(),
        half_secret(0x22),
    )
    .with_display_name(name.clone());

    assert_eq!(reply.display_name(), Some(&name));
}

#[test]
fn link_reply_debug_redacts_the_attestation_token_and_half_secret() {
    // Values chosen to be easy to search for, so removing the redaction
    // makes this test fail rather than pass by coincidence. The search is
    // case-folded and checks both hex and decimal, so an upper-hex or a
    // decimal `Debug` rendering of the secret is caught too.
    let secret_token = "SEARCHABLE-BEARER-TOKEN-VALUE";
    let reply = LinkReply::new(
        invite_id(0x33),
        identity_pub(),
        agreement_pub(),
        secret_token.to_string(),
        half_secret(0xAB),
    );

    let rendered = format!("{reply:?}").to_lowercase();

    assert!(!rendered.contains(&secret_token.to_lowercase()));
    assert!(!rendered.contains("ab"));
    assert!(!rendered.contains("171"));
    assert!(rendered.contains("[redacted]"));
    assert!(rendered.contains("halfsecret(<redacted>)"));
}

#[test]
fn link_approve_accessors_round_trip() {
    let approve = LinkApprove::new(invite_id(0x44), link_id(0x55));

    assert_eq!(approve.invite_id(), &invite_id(0x44));
    assert_eq!(approve.link_id(), link_id(0x55));
}

#[test]
fn link_decline_accessors_round_trip() {
    let decline = LinkDecline::new(invite_id(0x66), Some(LinkDeclineReason::UserDeclined));

    assert_eq!(decline.invite_id(), &invite_id(0x66));
    assert_eq!(decline.reason(), Some(LinkDeclineReason::UserDeclined));
}

#[test]
fn link_decline_accepts_no_reason() {
    let decline = LinkDecline::new(invite_id(0x77), None);

    assert_eq!(decline.reason(), None);
}

#[test]
fn link_decline_reason_try_from_rejects_unspecified_and_unknown() {
    assert_eq!(
        LinkDeclineReason::try_from(0),
        Err(LinkDeclineReasonError::Unspecified)
    );
    assert_eq!(
        LinkDeclineReason::try_from(99),
        Err(LinkDeclineReasonError::Unknown(99))
    );
}

#[test]
fn link_decline_reason_round_trips_through_i32_for_every_variant() {
    for reason in [
        LinkDeclineReason::UserDeclined,
        LinkDeclineReason::InviteExpired,
        LinkDeclineReason::VerificationFailed,
    ] {
        assert_eq!(LinkDeclineReason::try_from(i32::from(reason)), Ok(reason));
    }
}

#[test]
fn link_decline_reason_wire_numbers_are_pinned() {
    // Pinned by value, not merely round-tripped: a round trip alone would
    // still pass if every number shifted by one in the same direction.
    assert_eq!(i32::from(LinkDeclineReason::UserDeclined), 1);
    assert_eq!(i32::from(LinkDeclineReason::InviteExpired), 2);
    assert_eq!(i32::from(LinkDeclineReason::VerificationFailed), 3);
}

//! Tests `tradr_proto::invite`'s conversion between the wire `Invite` and
//! `tradr_core`'s native `Invite`, and the base64url blob it is carried
//! in (docs/11-account-linking.md, "What the Invite carries, and how it
//! travels"). Round trips first, then one hostile test per thing an
//! untrusted paste can get wrong.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message;

use tradr_core::DisplayName;
use tradr_proto::invite::{
    INVITE_BLOB_MAX_CHARS, INVITE_BLOB_VERSION, InviteBlobError, InviteWireError, invite_from_blob,
    invite_from_wire, invite_to_blob, invite_to_wire,
};
use tradr_proto::v1;

// A `v1::Invite` where every field is valid, so tests corrupt exactly one
// field at a time and know the rest cannot be the cause of a refusal.
fn valid_invite() -> v1::Invite {
    v1::Invite {
        invite_id: vec![1u8; 16],
        device: Some(v1::DeviceInfo {
            device_id: vec![9, 9],
            identity_pub: vec![3u8; 65],
            agreement_pub: vec![4u8; 65],
            display_name: "kitchen-laptop".to_string(),
            platform: v1::Platform::Linux as i32,
            capabilities: 0b0101,
        }),
        attestation: Some(v1::Attestation {
            id_token: "token-abc".to_string(),
            issuer: "google".to_string(),
            issued_at: 1_700_000_000,
        }),
        half_secret: vec![5u8; 16],
        expires_at: 1_700_000_300,
    }
}

fn valid_invite_without_display_name() -> v1::Invite {
    let mut wire = valid_invite();
    wire.device.as_mut().unwrap().display_name = String::new();
    wire
}

// ---- Round trips ----

#[test]
fn invite_with_display_name_round_trips_through_wire() {
    let wire = valid_invite();
    let native = invite_from_wire(wire.clone()).expect("valid Invite must convert");
    let back = invite_to_wire(&native);

    assert_eq!(back.invite_id, wire.invite_id);
    assert_eq!(
        back.device.as_ref().unwrap().identity_pub,
        wire.device.as_ref().unwrap().identity_pub
    );
    assert_eq!(
        back.device.as_ref().unwrap().agreement_pub,
        wire.device.as_ref().unwrap().agreement_pub
    );
    assert_eq!(
        back.device.as_ref().unwrap().display_name,
        wire.device.as_ref().unwrap().display_name
    );
    assert_eq!(
        back.attestation.as_ref().unwrap().id_token,
        wire.attestation.as_ref().unwrap().id_token
    );
    assert_eq!(back.half_secret, wire.half_secret);
    assert_eq!(back.expires_at, wire.expires_at);
}

#[test]
fn invite_with_display_name_round_trips_through_blob() {
    let native = invite_from_wire(valid_invite()).expect("valid Invite must convert");

    let blob = invite_to_blob(&native);
    let parsed = invite_from_blob(&blob).expect("a blob this crate produced must parse");

    assert_eq!(parsed.invite_id(), native.invite_id());
    assert_eq!(parsed.identity_pub(), native.identity_pub());
    assert_eq!(parsed.agreement_pub(), native.agreement_pub());
    assert_eq!(parsed.attestation_token(), native.attestation_token());
    assert_eq!(
        parsed.half_secret().as_bytes(),
        native.half_secret().as_bytes()
    );
    assert_eq!(parsed.expires_at(), native.expires_at());
    assert_eq!(parsed.display_name(), native.display_name());
}

// Written with the version byte as a literal rather than
// INVITE_BLOB_VERSION: two builds that disagree about this byte cannot
// read each other's invites, and no round trip within a single build can
// ever notice that, since both halves of the round trip share the
// constant.
#[test]
fn a_blob_opens_with_the_byte_0x01() {
    let native = invite_from_wire(valid_invite()).expect("valid Invite must convert");

    let blob = invite_to_blob(&native);
    let bytes = URL_SAFE_NO_PAD
        .decode(&blob)
        .expect("invite_to_blob must produce valid base64url");

    assert_eq!(bytes[0], 0x01);
}

#[test]
fn invite_without_display_name_round_trips_through_blob() {
    let native =
        invite_from_wire(valid_invite_without_display_name()).expect("valid Invite must convert");
    assert_eq!(native.display_name(), None);

    let blob = invite_to_blob(&native);
    let parsed = invite_from_blob(&blob).expect("a blob this crate produced must parse");

    assert_eq!(parsed.invite_id(), native.invite_id());
    assert_eq!(parsed.identity_pub(), native.identity_pub());
    assert_eq!(parsed.agreement_pub(), native.agreement_pub());
    assert_eq!(parsed.attestation_token(), native.attestation_token());
    assert_eq!(
        parsed.half_secret().as_bytes(),
        native.half_secret().as_bytes()
    );
    assert_eq!(parsed.expires_at(), native.expires_at());
    assert_eq!(parsed.display_name(), None);
}

// ---- display_name: kept when valid, dropped when invalid ----

#[test]
fn valid_display_name_is_kept() {
    let wire = valid_invite();
    let name = wire.device.as_ref().unwrap().display_name.clone();

    let invite = invite_from_wire(wire).expect("valid Invite must convert");
    assert_eq!(
        invite.display_name(),
        Some(&DisplayName::new(&name).expect("kitchen-laptop is a valid display name"))
    );
}

#[test]
fn invalid_display_name_is_dropped_not_refused() {
    let mut wire = valid_invite();
    wire.device.as_mut().unwrap().display_name = "a".repeat(33);

    let invite = invite_from_wire(wire).expect("an over-long display_name must not refuse");
    assert_eq!(invite.display_name(), None);
}

// ---- device_id, platform, capabilities are read by nothing ----

#[test]
fn device_id_platform_and_capabilities_change_nothing_in_the_parsed_invite() {
    let plain = invite_from_wire(valid_invite()).expect("valid Invite must convert");

    let mut wire = valid_invite();
    wire.device.as_mut().unwrap().device_id = vec![0xAB; 8];
    wire.device.as_mut().unwrap().platform = v1::Platform::Android as i32;
    wire.device.as_mut().unwrap().capabilities = 0xFFFF;
    let changed = invite_from_wire(wire).expect("valid Invite must convert");

    assert_eq!(plain.invite_id(), changed.invite_id());
    assert_eq!(plain.identity_pub(), changed.identity_pub());
    assert_eq!(plain.agreement_pub(), changed.agreement_pub());
    assert_eq!(plain.attestation_token(), changed.attestation_token());
    assert_eq!(plain.expires_at(), changed.expires_at());
    assert_eq!(plain.display_name(), changed.display_name());
}

// ---- issuer / issued_at are discarded ----

#[test]
fn issuer_and_issued_at_never_appear_in_invite() {
    let mut wire = valid_invite();
    wire.attestation.as_mut().unwrap().issuer = "not-the-real-issuer".to_string();
    wire.attestation.as_mut().unwrap().issued_at = 424_242;

    let invite = invite_from_wire(wire).expect("valid Invite must convert");
    assert_eq!(invite.attestation_token(), "token-abc");

    let debug = format!("{invite:?}");
    assert!(!debug.contains("not-the-real-issuer"));
    assert!(!debug.contains("424242"));
}

#[test]
fn to_wire_writes_issuer_and_issued_at_as_defaults() {
    let invite = invite_from_wire(valid_invite()).expect("valid Invite must convert");
    let back = invite_to_wire(&invite);

    assert_eq!(back.attestation.as_ref().unwrap().issuer, "");
    assert_eq!(back.attestation.as_ref().unwrap().issued_at, 0);
}

// ---- One hostile test per InviteWireError variant (field-table Refuse rows) ----

#[test]
fn absent_device_is_refused() {
    let mut wire = valid_invite();
    wire.device = None;

    let err = invite_from_wire(wire).expect_err("absent device must be refused");
    assert_eq!(err, InviteWireError::MissingDevice);
}

#[test]
fn absent_attestation_is_refused() {
    let mut wire = valid_invite();
    wire.attestation = None;

    let err = invite_from_wire(wire).expect_err("absent attestation must be refused");
    assert_eq!(err, InviteWireError::MissingAttestation);
}

#[test]
fn empty_attestation_token_is_refused() {
    let mut wire = valid_invite();
    wire.attestation.as_mut().unwrap().id_token = String::new();

    let err = invite_from_wire(wire).expect_err("empty id_token must be refused");
    assert_eq!(err, InviteWireError::EmptyAttestationToken);
}

#[test]
fn invite_id_of_15_bytes_is_refused() {
    let mut wire = valid_invite();
    wire.invite_id = vec![1u8; 15];

    let err = invite_from_wire(wire).expect_err("15-byte invite_id must be refused");
    assert!(matches!(err, InviteWireError::InvalidInviteId(_)));
}

#[test]
fn identity_pub_of_64_bytes_is_refused() {
    let mut wire = valid_invite();
    wire.device.as_mut().unwrap().identity_pub = vec![3u8; 64];

    let err = invite_from_wire(wire).expect_err("64-byte identity_pub must be refused");
    assert!(matches!(err, InviteWireError::InvalidIdentityPub(_)));
}

#[test]
fn agreement_pub_of_64_bytes_is_refused() {
    let mut wire = valid_invite();
    wire.device.as_mut().unwrap().agreement_pub = vec![4u8; 64];

    let err = invite_from_wire(wire).expect_err("64-byte agreement_pub must be refused");
    assert!(matches!(err, InviteWireError::InvalidAgreementPub(_)));
}

#[test]
fn half_secret_of_15_bytes_is_refused() {
    let mut wire = valid_invite();
    wire.half_secret = vec![5u8; 15];

    let err = invite_from_wire(wire).expect_err("15-byte half_secret must be refused");
    assert!(matches!(err, InviteWireError::InvalidHalfSecret(_)));
}

#[test]
fn expires_at_of_zero_is_refused() {
    let mut wire = valid_invite();
    wire.expires_at = 0;

    let err = invite_from_wire(wire).expect_err("expires_at of zero must be refused");
    assert_eq!(err, InviteWireError::ZeroExpiresAt);
}

// ---- Error Display never carries the attestation token ----

#[test]
fn error_display_never_carries_the_attestation_token() {
    let secret_token = "eyJhbGciOiJSUzI1NiJ9.super-secret-payload.sig";
    let mut wire = valid_invite();
    wire.attestation.as_mut().unwrap().id_token = secret_token.to_string();
    wire.half_secret = vec![5u8; 15]; // Fails after the token has already been read into the message.

    let err = invite_from_wire(wire).expect_err("15-byte half_secret must be refused");
    assert!(!err.to_string().contains(secret_token));
}

// ---- Blob-level refusals ----

fn wire_bytes() -> Vec<u8> {
    valid_invite().encode_to_vec()
}

#[test]
fn blob_one_character_over_the_limit_is_refused() {
    let blob = "A".repeat(INVITE_BLOB_MAX_CHARS + 1);

    let err = invite_from_blob(&blob).expect_err("over-length blob must be refused");
    assert!(matches!(
        err,
        InviteBlobError::TooLong { actual } if actual == INVITE_BLOB_MAX_CHARS + 1
    ));
}

#[test]
fn the_over_length_refusal_happens_before_decoding() {
    // "!" is not part of the URL-safe base64 alphabet, so this blob would
    // fail base64 decoding too -- a cap checked after decoding would
    // return InviteBlobError::Base64 instead, which is the wrong answer.
    let blob = "!".repeat(INVITE_BLOB_MAX_CHARS + 1);

    let err = invite_from_blob(&blob).expect_err("over-length blob must be refused");
    assert!(matches!(
        err,
        InviteBlobError::TooLong { actual } if actual == INVITE_BLOB_MAX_CHARS + 1
    ));
}

// The two tests below write the boundary lengths as literals rather than
// INVITE_BLOB_MAX_CHARS + 1 / INVITE_BLOB_MAX_CHARS, so a change that
// shrinks or grows the cap's actual value is caught here even though the
// existing pair above, expressed in terms of the constant, follows it.

#[test]
fn a_blob_of_4097_characters_is_refused_as_too_long() {
    let blob = "A".repeat(4097);

    let err = invite_from_blob(&blob).expect_err("a 4097-character blob must be refused");
    assert!(matches!(err, InviteBlobError::TooLong { actual } if actual == 4097));
}

#[test]
fn a_blob_of_4096_characters_is_not_refused_for_length() {
    let blob = "A".repeat(4096);

    let err = invite_from_blob(&blob).expect_err("garbage decoded bytes must still be refused");
    assert!(!matches!(err, InviteBlobError::TooLong { .. }));
}

#[test]
fn blob_that_is_not_base64url_is_refused() {
    let blob = "not valid base64url!!";

    let err = invite_from_blob(blob).expect_err("non-base64url blob must be refused");
    assert!(matches!(err, InviteBlobError::Base64(_)));
}

#[test]
fn blob_decoding_to_zero_bytes_is_refused() {
    let blob = URL_SAFE_NO_PAD.encode([]);

    let err = invite_from_blob(&blob).expect_err("empty decoded blob must be refused");
    assert!(matches!(err, InviteBlobError::Empty));
}

#[test]
fn blob_with_unsupported_version_byte_is_refused() {
    let mut bytes = vec![0x02u8];
    bytes.extend(wire_bytes());
    let blob = URL_SAFE_NO_PAD.encode(bytes);

    let err = invite_from_blob(&blob).expect_err("unsupported version byte must be refused");
    assert!(matches!(err, InviteBlobError::UnsupportedVersion(0x02)));
}

#[test]
fn blob_whose_body_is_not_a_valid_invite_message_is_refused() {
    // A single 0xFF byte is not a valid protobuf field tag, so decoding
    // the body must fail regardless of the wire-validation rules above.
    let mut bytes = vec![INVITE_BLOB_VERSION];
    bytes.push(0xFF);
    let blob = URL_SAFE_NO_PAD.encode(bytes);

    let err = invite_from_blob(&blob).expect_err("corrupt protobuf body must be refused");
    assert!(matches!(err, InviteBlobError::Decode(_)));
}

// ---- The blob path wraps a field-table refusal through InviteBlobError::Wire ----

#[test]
fn blob_with_absent_device_is_refused_via_wire_error() {
    let mut wire = valid_invite();
    wire.device = None;
    let mut bytes = vec![INVITE_BLOB_VERSION];
    bytes.extend(wire.encode_to_vec());
    let blob = URL_SAFE_NO_PAD.encode(bytes);

    let err = invite_from_blob(&blob).expect_err("absent device must be refused");
    assert!(matches!(
        err,
        InviteBlobError::Wire(InviteWireError::MissingDevice)
    ));
}

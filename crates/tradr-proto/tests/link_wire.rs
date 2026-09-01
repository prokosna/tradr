//! Tests `tradr_proto::link`'s conversions between the wire
//! `LinkReply`/`LinkApprove`/`LinkDecline` and `tradr_core`'s native
//! `LinkReply`/`LinkApprove`/`LinkDecline` (docs/11-account-linking.md,
//! "What the three linking messages carry"). Round trips first, then one
//! hostile test per thing an untrusted peer can get wrong.

use tradr_core::{DisplayName, LinkDeclineReason};
use tradr_proto::framing::{FrameDecoder, encode_frame};
use tradr_proto::link::{
    LinkFrameError, LinkWireError, decode_link_approve_frame, decode_link_decline_frame,
    decode_link_reply_frame, encode_link_approve_frame, encode_link_decline_frame,
    encode_link_reply_frame, link_approve_from_wire, link_approve_to_wire, link_decline_from_wire,
    link_decline_to_wire, link_reply_from_wire, link_reply_to_wire,
};
use tradr_proto::message_type::MessageType;
use tradr_proto::v1;

// A `v1::LinkReply` where every field is valid, so tests corrupt exactly
// one field at a time and know the rest cannot be the cause of a refusal.
fn valid_link_reply() -> v1::LinkReply {
    v1::LinkReply {
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
    }
}

fn valid_link_approve() -> v1::LinkApprove {
    v1::LinkApprove {
        invite_id: vec![1u8; 16],
        link_id: vec![2u8; 16],
    }
}

fn valid_link_decline() -> v1::LinkDecline {
    v1::LinkDecline {
        invite_id: vec![1u8; 16],
        reason: v1::LinkDeclineReason::UserDeclined as i32,
    }
}

// ---- Round trips ----

#[test]
fn link_reply_round_trips() {
    let wire = valid_link_reply();
    let native = link_reply_from_wire(wire.clone()).expect("valid LinkReply must convert");
    let back = link_reply_to_wire(&native);

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
}

#[test]
fn link_approve_round_trips() {
    let wire = valid_link_approve();
    let native = link_approve_from_wire(wire.clone()).expect("valid LinkApprove must convert");
    let back = link_approve_to_wire(&native);

    assert_eq!(back.invite_id, wire.invite_id);
    assert_eq!(back.link_id, wire.link_id);
}

#[test]
fn link_decline_round_trips() {
    let wire = valid_link_decline();
    let native = link_decline_from_wire(wire.clone()).expect("valid LinkDecline must convert");
    let back = link_decline_to_wire(&native);

    assert_eq!(back.invite_id, wire.invite_id);
    assert_eq!(back.reason, wire.reason);
}

// ---- display_name: kept when valid, dropped when invalid ----

#[test]
fn valid_display_name_is_kept() {
    let wire = valid_link_reply();
    let name = wire.device.as_ref().unwrap().display_name.clone();

    let reply = link_reply_from_wire(wire).expect("valid LinkReply must convert");
    assert_eq!(
        reply.display_name(),
        Some(&DisplayName::new(&name).expect("kitchen-laptop is a valid display name"))
    );
}

#[test]
fn invalid_display_name_is_dropped_not_refused() {
    let mut wire = valid_link_reply();
    wire.device.as_mut().unwrap().display_name = "a".repeat(33);

    let reply = link_reply_from_wire(wire).expect("an over-long display_name must not refuse");
    assert_eq!(reply.display_name(), None);
}

// ---- One hostile test per LinkWireError variant ----

#[test]
fn absent_device_is_refused() {
    let mut wire = valid_link_reply();
    wire.device = None;

    let err = link_reply_from_wire(wire).expect_err("absent device must be refused");
    assert_eq!(err, LinkWireError::MissingDevice);
}

#[test]
fn absent_attestation_is_refused() {
    let mut wire = valid_link_reply();
    wire.attestation = None;

    let err = link_reply_from_wire(wire).expect_err("absent attestation must be refused");
    assert_eq!(err, LinkWireError::MissingAttestation);
}

#[test]
fn empty_attestation_token_is_refused() {
    let mut wire = valid_link_reply();
    wire.attestation.as_mut().unwrap().id_token = String::new();

    let err = link_reply_from_wire(wire).expect_err("empty id_token must be refused");
    assert_eq!(err, LinkWireError::EmptyAttestationToken);
}

#[test]
fn invite_id_of_15_bytes_is_refused() {
    let mut wire = valid_link_reply();
    wire.invite_id = vec![1u8; 15];

    let err = link_reply_from_wire(wire).expect_err("15-byte invite_id must be refused");
    assert!(matches!(err, LinkWireError::InvalidInviteId(_)));
}

#[test]
fn identity_pub_of_64_bytes_is_refused() {
    let mut wire = valid_link_reply();
    wire.device.as_mut().unwrap().identity_pub = vec![3u8; 64];

    let err = link_reply_from_wire(wire).expect_err("64-byte identity_pub must be refused");
    assert!(matches!(err, LinkWireError::InvalidIdentityPub(_)));
}

#[test]
fn agreement_pub_of_64_bytes_is_refused() {
    let mut wire = valid_link_reply();
    wire.device.as_mut().unwrap().agreement_pub = vec![4u8; 64];

    let err = link_reply_from_wire(wire).expect_err("64-byte agreement_pub must be refused");
    assert!(matches!(err, LinkWireError::InvalidAgreementPub(_)));
}

#[test]
fn half_secret_of_15_bytes_is_refused() {
    let mut wire = valid_link_reply();
    wire.half_secret = vec![5u8; 15];

    let err = link_reply_from_wire(wire).expect_err("15-byte half_secret must be refused");
    assert!(matches!(err, LinkWireError::InvalidHalfSecret(_)));
}

#[test]
fn link_id_of_15_bytes_is_refused() {
    let mut wire = valid_link_approve();
    wire.link_id = vec![2u8; 15];

    let err = link_approve_from_wire(wire).expect_err("15-byte link_id must be refused");
    assert!(matches!(err, LinkWireError::InvalidLinkId(_)));
}

#[test]
fn approve_invite_id_of_17_bytes_is_refused() {
    let mut wire = valid_link_approve();
    wire.invite_id = vec![1u8; 17];

    let err = link_approve_from_wire(wire).expect_err("17-byte invite_id must be refused");
    assert!(matches!(err, LinkWireError::InvalidInviteId(_)));
}

#[test]
fn decline_invite_id_of_17_bytes_is_refused() {
    let mut wire = valid_link_decline();
    wire.invite_id = vec![1u8; 17];

    let err = link_decline_from_wire(wire).expect_err("17-byte invite_id must be refused");
    assert!(matches!(err, LinkWireError::InvalidInviteId(_)));
}

// ---- LinkDecline.reason decorates and decides nothing ----

#[test]
fn decline_reason_unspecified_converts_to_none() {
    let mut wire = valid_link_decline();
    wire.reason = 0;

    let decline = link_decline_from_wire(wire).expect("unspecified reason must not refuse");
    assert_eq!(decline.reason(), None);
}

#[test]
fn decline_reason_with_no_defined_variant_converts_to_none() {
    let mut wire = valid_link_decline();
    wire.reason = 99;

    let decline = link_decline_from_wire(wire).expect("undefined reason must not refuse");
    assert_eq!(decline.reason(), None);
}

#[test]
fn decline_reason_known_value_is_kept() {
    let wire = valid_link_decline();
    let decline = link_decline_from_wire(wire).expect("valid LinkDecline must convert");
    assert_eq!(decline.reason(), Some(LinkDeclineReason::UserDeclined));
}

// ---- issuer / issued_at are discarded ----

#[test]
fn issuer_and_issued_at_never_appear_in_link_reply() {
    let mut wire = valid_link_reply();
    wire.attestation.as_mut().unwrap().issuer = "not-the-real-issuer".to_string();
    wire.attestation.as_mut().unwrap().issued_at = 424_242;

    let reply = link_reply_from_wire(wire).expect("valid LinkReply must convert");
    assert_eq!(reply.attestation_token(), "token-abc");

    let debug = format!("{reply:?}");
    assert!(!debug.contains("not-the-real-issuer"));
    assert!(!debug.contains("424242"));
}

#[test]
fn to_wire_writes_issuer_and_issued_at_as_defaults() {
    let reply = link_reply_from_wire(valid_link_reply()).expect("valid LinkReply must convert");
    let back = link_reply_to_wire(&reply);

    assert_eq!(back.attestation.as_ref().unwrap().issuer, "");
    assert_eq!(back.attestation.as_ref().unwrap().issued_at, 0);
}

// ---- Error Display never carries the attestation token ----

#[test]
fn error_display_never_carries_the_attestation_token() {
    let secret_token = "eyJhbGciOiJSUzI1NiJ9.super-secret-payload.sig";
    let mut wire = valid_link_reply();
    wire.attestation.as_mut().unwrap().id_token = secret_token.to_string();
    wire.half_secret = vec![5u8; 15]; // Fails after the token has already been read into the message.

    let err = link_reply_from_wire(wire).expect_err("15-byte half_secret must be refused");
    assert!(!err.to_string().contains(secret_token));
}

// ---- Framed LinkReply / LinkApprove / LinkDecline encoding and decoding ----

#[test]
fn framed_link_reply_round_trips() {
    let reply = link_reply_from_wire(valid_link_reply()).expect("valid LinkReply must convert");
    let framed_bytes = encode_link_reply_frame(&reply, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");
    assert_eq!(frame.type_code(), MessageType::LinkReply.code());
    assert_eq!(MessageType::LinkReply.code(), 0x0c);

    let decoded = decode_link_reply_frame(&frame).expect("decoding LinkReply frame must succeed");
    assert_eq!(decoded.invite_id(), reply.invite_id());
    assert_eq!(decoded.identity_pub(), reply.identity_pub());
    assert_eq!(decoded.agreement_pub(), reply.agreement_pub());
    assert_eq!(decoded.attestation_token(), reply.attestation_token());
    assert_eq!(decoded.display_name(), reply.display_name());
}

#[test]
fn framed_link_approve_round_trips() {
    let approve =
        link_approve_from_wire(valid_link_approve()).expect("valid LinkApprove must convert");
    let framed_bytes = encode_link_approve_frame(&approve, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");
    assert_eq!(frame.type_code(), MessageType::LinkApprove.code());
    assert_eq!(MessageType::LinkApprove.code(), 0x0d);

    let decoded =
        decode_link_approve_frame(&frame).expect("decoding LinkApprove frame must succeed");
    assert_eq!(decoded.invite_id(), approve.invite_id());
    assert_eq!(decoded.link_id(), approve.link_id());
}

#[test]
fn framed_link_decline_round_trips() {
    let decline =
        link_decline_from_wire(valid_link_decline()).expect("valid LinkDecline must convert");
    let framed_bytes = encode_link_decline_frame(&decline, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");
    assert_eq!(frame.type_code(), MessageType::LinkDecline.code());
    assert_eq!(MessageType::LinkDecline.code(), 0x0e);

    let decoded =
        decode_link_decline_frame(&frame).expect("decoding LinkDecline frame must succeed");
    assert_eq!(decoded.invite_id(), decline.invite_id());
    assert_eq!(decoded.reason(), decline.reason());
}

// ---- decode_*_frame refuses another linking message's type byte ----

#[test]
fn decode_link_reply_frame_with_wrong_type_is_refused() {
    let approve =
        link_approve_from_wire(valid_link_approve()).expect("valid LinkApprove must convert");
    let framed_bytes = encode_link_approve_frame(&approve, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be complete");

    let err = decode_link_reply_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        LinkFrameError::WrongMessageType {
            expected: MessageType::LinkReply.code(),
            got: MessageType::LinkApprove.code(),
        }
    );
}

#[test]
fn decode_link_approve_frame_with_wrong_type_is_refused() {
    let decline =
        link_decline_from_wire(valid_link_decline()).expect("valid LinkDecline must convert");
    let framed_bytes = encode_link_decline_frame(&decline, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be complete");

    let err = decode_link_approve_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        LinkFrameError::WrongMessageType {
            expected: MessageType::LinkApprove.code(),
            got: MessageType::LinkDecline.code(),
        }
    );
}

#[test]
fn decode_link_decline_frame_with_wrong_type_is_refused() {
    let reply = link_reply_from_wire(valid_link_reply()).expect("valid LinkReply must convert");
    let framed_bytes = encode_link_reply_frame(&reply, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be complete");

    let err = decode_link_decline_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        LinkFrameError::WrongMessageType {
            expected: MessageType::LinkDecline.code(),
            got: MessageType::LinkReply.code(),
        }
    );
}

// ---- Corrupted / empty payload decoding ----

#[test]
fn decode_link_reply_frame_corrupted_protobuf_is_refused() {
    let corrupt_payload = vec![0xFF, 0xFF, 0xFF];
    let frame_bytes = encode_frame(MessageType::LinkReply.code(), &corrupt_payload, 65536)
        .expect("framing raw bytes must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be present");

    let err = decode_link_reply_frame(&frame).expect_err("corrupt protobuf must fail to decode");
    assert!(matches!(err, LinkFrameError::Decode(_)));
}

#[test]
fn decode_link_reply_frame_empty_payload_is_refused() {
    let empty_payload = Vec::new();
    let frame_bytes = encode_frame(MessageType::LinkReply.code(), &empty_payload, 65536)
        .expect("framing raw bytes must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be present");

    let err = decode_link_reply_frame(&frame)
        .expect_err("empty LinkReply wire payload must fail validation");
    assert!(matches!(
        err,
        LinkFrameError::Wire(LinkWireError::InvalidInviteId(_))
    ));
}

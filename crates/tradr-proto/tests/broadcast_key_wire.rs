//! Tests `tradr_proto::broadcast_key` conversions between wire
//! `BroadcastKeyOffer` and native `BroadcastKeyOffer` (docs/11-account-linking.md,
//! "The exchange, and why it needs no roles"). Round trips first, then one
//! hostile test per error variant.

use tradr_core::{
    AccountBroadcastKey, BroadcastKeyError, BroadcastKeyOffer, BroadcastKeyOfferError, UnixTime,
};
use tradr_proto::broadcast_key::{
    BroadcastKeyFrameError, BroadcastKeyWireError, broadcast_key_offer_from_wire,
    broadcast_key_offer_to_wire, decode_broadcast_key_offer_frame,
    encode_broadcast_key_offer_frame,
};
use tradr_proto::framing::{FrameDecoder, encode_frame};
use tradr_proto::message_type::MessageType;
use tradr_proto::v1;

// A valid wire offer where every field passes validation.
fn valid_broadcast_key_offer() -> v1::BroadcastKeyOffer {
    v1::BroadcastKeyOffer {
        key: vec![0x42; 32],
        generation: 3,
        created_at: 1_700_000_000,
    }
}

// ---- Round trips ----

#[test]
fn native_offer_round_trips_through_wire_conversions() {
    let key = AccountBroadcastKey::from_bytes(&[7u8; 32]).expect("valid 32-byte key");
    let native =
        BroadcastKeyOffer::new(key, 2, UnixTime::from_secs(1_700_000_000)).expect("valid offer");
    let wire = broadcast_key_offer_to_wire(&native);
    let back = broadcast_key_offer_from_wire(wire).expect("valid wire offer must convert");

    assert_eq!(back.key().as_bytes(), native.key().as_bytes());
    assert_eq!(back.generation(), native.generation());
    assert_eq!(back.created_at(), native.created_at());
}

#[test]
fn framed_offer_round_trips_through_encoder_and_decoder() {
    let key = AccountBroadcastKey::from_bytes(&[7u8; 32]).expect("valid 32-byte key");
    let native =
        BroadcastKeyOffer::new(key, 2, UnixTime::from_secs(1_700_000_000)).expect("valid offer");
    let framed_bytes =
        encode_broadcast_key_offer_frame(&native, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    assert_eq!(frame.type_code(), 0x10);
    assert_eq!(frame.type_code(), MessageType::BroadcastKeyOffer.code());

    let decoded = decode_broadcast_key_offer_frame(&frame)
        .expect("decoding BroadcastKeyOffer frame must succeed");
    assert_eq!(decoded.key().as_bytes(), native.key().as_bytes());
    assert_eq!(decoded.generation(), native.generation());
    assert_eq!(decoded.created_at(), native.created_at());
}

#[test]
fn encoded_frame_type_code_is_0x10() {
    let key = AccountBroadcastKey::from_bytes(&[7u8; 32]).expect("valid 32-byte key");
    let native = BroadcastKeyOffer::new(key, 1, UnixTime::from_secs(1_000)).expect("valid offer");
    let framed_bytes =
        encode_broadcast_key_offer_frame(&native, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    assert_eq!(frame.type_code(), 0x10);
    assert_eq!(frame.type_code(), MessageType::BroadcastKeyOffer.code());
}

// ---- Negative tests on wire fields ----

#[test]
fn key_of_31_bytes_is_refused() {
    let mut wire = valid_broadcast_key_offer();
    wire.key = vec![1u8; 31];
    let err = broadcast_key_offer_from_wire(wire).expect_err("31-byte key must be refused");
    assert_eq!(
        err,
        BroadcastKeyWireError::InvalidKey(BroadcastKeyError::WrongLength {
            expected: 32,
            actual: 31,
        })
    );
}

#[test]
fn key_of_33_bytes_is_refused() {
    let mut wire = valid_broadcast_key_offer();
    wire.key = vec![1u8; 33];
    let err = broadcast_key_offer_from_wire(wire).expect_err("33-byte key must be refused");
    assert_eq!(
        err,
        BroadcastKeyWireError::InvalidKey(BroadcastKeyError::WrongLength {
            expected: 32,
            actual: 33,
        })
    );
}

#[test]
fn empty_key_is_refused() {
    let mut wire = valid_broadcast_key_offer();
    wire.key = Vec::new();
    let err = broadcast_key_offer_from_wire(wire).expect_err("empty key must be refused");
    assert_eq!(
        err,
        BroadcastKeyWireError::InvalidKey(BroadcastKeyError::WrongLength {
            expected: 32,
            actual: 0,
        })
    );
}

#[test]
fn generation_zero_is_refused() {
    let mut wire = valid_broadcast_key_offer();
    wire.generation = 0;
    let err = broadcast_key_offer_from_wire(wire).expect_err("generation 0 must be refused");
    assert_eq!(
        err,
        BroadcastKeyWireError::InvalidOffer(BroadcastKeyOfferError::ZeroIsNotAGeneration)
    );
}

#[test]
fn created_at_zero_is_refused() {
    let mut wire = valid_broadcast_key_offer();
    wire.created_at = 0;
    let err = broadcast_key_offer_from_wire(wire).expect_err("created_at 0 must be refused");
    assert_eq!(
        err,
        BroadcastKeyWireError::InvalidOffer(BroadcastKeyOfferError::CreatedAtNotAfterEpoch {
            seconds: 0,
        })
    );
}

#[test]
fn created_at_negative_one_is_refused() {
    let mut wire = valid_broadcast_key_offer();
    wire.created_at = -1;
    let err = broadcast_key_offer_from_wire(wire).expect_err("created_at -1 must be refused");
    assert_eq!(
        err,
        BroadcastKeyWireError::InvalidOffer(BroadcastKeyOfferError::CreatedAtNotAfterEpoch {
            seconds: -1,
        })
    );
}

// ---- Positive boundary test ----

#[test]
fn boundary_created_at_one_and_generation_one_are_accepted() {
    let mut wire = valid_broadcast_key_offer();
    wire.generation = 1;
    wire.created_at = 1;
    let offer = broadcast_key_offer_from_wire(wire)
        .expect("created_at 1 and generation 1 must be accepted");
    assert_eq!(offer.generation(), 1);
    assert_eq!(offer.created_at(), UnixTime::from_secs(1));
}

// ---- Framing error tests ----

#[test]
fn decode_frame_with_wrong_type_code_is_refused() {
    let key = AccountBroadcastKey::from_bytes(&[7u8; 32]).expect("valid 32-byte key");
    let native = BroadcastKeyOffer::new(key, 1, UnixTime::from_secs(100)).expect("valid offer");
    let wire = broadcast_key_offer_to_wire(&native);
    let payload = prost::Message::encode_to_vec(&wire);
    let wrong_code = MessageType::Hello.code();
    let frame_bytes = encode_frame(wrong_code, &payload, 65536).expect("framing must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be complete");

    let err =
        decode_broadcast_key_offer_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        BroadcastKeyFrameError::WrongMessageType {
            expected: MessageType::BroadcastKeyOffer.code(),
            got: wrong_code,
        }
    );
}

#[test]
fn decode_frame_with_corrupt_protobuf_is_refused() {
    let corrupt_payload = vec![0xFF, 0xFF, 0xFF];
    let frame_bytes = encode_frame(
        MessageType::BroadcastKeyOffer.code(),
        &corrupt_payload,
        65536,
    )
    .expect("framing raw bytes must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be present");

    let err =
        decode_broadcast_key_offer_frame(&frame).expect_err("corrupt protobuf must fail to decode");
    assert!(matches!(err, BroadcastKeyFrameError::Decode(_)));
}

#[test]
fn decode_frame_with_invalid_wire_fields_returns_wire_error() {
    let wire = v1::BroadcastKeyOffer {
        key: Vec::new(),
        generation: 1,
        created_at: 100,
    };
    let payload = prost::Message::encode_to_vec(&wire);
    let frame_bytes = encode_frame(MessageType::BroadcastKeyOffer.code(), &payload, 65536)
        .expect("framing raw bytes must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be present");

    let err = decode_broadcast_key_offer_frame(&frame)
        .expect_err("empty key in frame must return wire error");
    assert!(matches!(
        err,
        BroadcastKeyFrameError::Wire(BroadcastKeyWireError::InvalidKey(_))
    ));
}

#[test]
fn encode_frame_with_small_max_frame_size_returns_framing_error() {
    let key = AccountBroadcastKey::from_bytes(&[7u8; 32]).expect("valid 32-byte key");
    let native = BroadcastKeyOffer::new(key, 1, UnixTime::from_secs(100)).expect("valid offer");
    let err = encode_broadcast_key_offer_frame(&native, 1)
        .expect_err("small max_frame_size must fail framing");
    assert!(matches!(err, BroadcastKeyFrameError::Framing(_)));
}

#[test]
fn error_display_and_source_are_implemented() {
    let key_err = BroadcastKeyWireError::InvalidKey(BroadcastKeyError::WrongLength {
        expected: 32,
        actual: 0,
    });
    assert!(!key_err.to_string().is_empty());
    assert!(std::error::Error::source(&key_err).is_some());

    let frame_err = BroadcastKeyFrameError::Wire(key_err);
    assert!(!frame_err.to_string().is_empty());
    assert!(std::error::Error::source(&frame_err).is_some());
}

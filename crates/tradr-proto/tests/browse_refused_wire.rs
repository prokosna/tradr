use prost::Message;
use tradr_core::{Ack, BrowseCodec, BrowseMessage, RefusalReason, Refused};
use tradr_proto::browse::{
    BrowseFrameError, ProtoBrowseCodec, decode_refused_frame, encode_ack_frame,
    encode_refused_frame,
};
use tradr_proto::framing::{FrameDecoder, encode_frame};
use tradr_proto::message_type::MessageType;
use tradr_proto::v1;

const ALL_REASONS: [RefusalReason; 6] = [
    RefusalReason::NoAccess,
    RefusalReason::NotFound,
    RefusalReason::AlreadyExists,
    RefusalReason::WrongKind,
    RefusalReason::NotAllowed,
    RefusalReason::Failed,
];

#[test]
fn every_reason_round_trips_through_encode_and_decode_refused_frame() {
    for reason in ALL_REASONS {
        let msg = Refused {
            request_id: format!("req-{reason:?}"),
            reason,
        };
        let encoded = encode_refused_frame(&msg, 65536).expect("encode must succeed");

        let mut decoder = FrameDecoder::new(65536);
        decoder.feed(&encoded);
        let frame = decoder
            .next_frame()
            .expect("next_frame must not error")
            .expect("frame must be complete");

        let decoded = decode_refused_frame(&frame).expect("decode must succeed");
        assert_eq!(decoded, msg);
    }
}

#[test]
fn every_reason_round_trips_through_proto_browse_codec() {
    let codec = ProtoBrowseCodec::new(65536);
    for reason in ALL_REASONS {
        let msg = BrowseMessage::Refused(Refused {
            request_id: format!("req-codec-{reason:?}"),
            reason,
        });
        let encoded = codec
            .encode_frame(&msg, 65536)
            .expect("codec encode must succeed");
        let (decoded, consumed) = codec
            .decode_frame(&encoded, 65536)
            .expect("codec decode must succeed")
            .expect("frame must be complete");
        assert_eq!(decoded, msg);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn encoded_refused_frame_type_byte_is_0x4d() {
    let msg = Refused {
        request_id: "req-type-byte-check".to_string(),
        reason: RefusalReason::NoAccess,
    };
    let encoded = encode_refused_frame(&msg, 65536).expect("encode must succeed");
    // Wire format is [len: u32 BE][type_code: u8][payload].
    assert_eq!(encoded[4], 0x4d);
    assert_eq!(encoded[4], MessageType::Refused.code());
}

#[test]
fn wire_reason_zero_and_unlisted_ninety_nine_decode_to_failed() {
    for wire_reason in [0, 99] {
        let wire = v1::Refused {
            request_id: format!("req-wire-{wire_reason}"),
            reason: wire_reason,
        };
        let framed = encode_frame(MessageType::Refused.code(), &wire.encode_to_vec(), 65536)
            .expect("encode_frame must succeed");

        let mut decoder = FrameDecoder::new(65536);
        decoder.feed(&framed);
        let frame = decoder
            .next_frame()
            .expect("next_frame must not error")
            .expect("frame must be complete");

        let decoded = decode_refused_frame(&frame).expect("decode must succeed");
        assert_eq!(decoded.request_id, format!("req-wire-{wire_reason}"));
        assert_eq!(decoded.reason, RefusalReason::Failed);

        let codec = ProtoBrowseCodec::new(65536);
        let (codec_decoded, consumed) = codec
            .decode_frame(&framed, 65536)
            .expect("codec decode must succeed")
            .expect("frame must be complete");
        assert_eq!(
            codec_decoded,
            BrowseMessage::Refused(Refused {
                request_id: format!("req-wire-{wire_reason}"),
                reason: RefusalReason::Failed,
            })
        );
        assert_eq!(consumed, framed.len());
    }
}

#[test]
fn decode_refused_frame_given_ack_frame_answers_wrong_message_type() {
    let ack = Ack {
        request_id: "req-ack-test".to_string(),
    };
    let encoded_ack = encode_ack_frame(&ack, 65536).expect("encode ack must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&encoded_ack);
    let ack_frame = decoder
        .next_frame()
        .expect("next_frame must not error")
        .expect("frame must be complete");

    let err = decode_refused_frame(&ack_frame).expect_err("wrong message type must error");
    assert_eq!(
        err,
        BrowseFrameError::WrongMessageType {
            expected: MessageType::Refused.code(),
            got: MessageType::Ack.code(),
        }
    );
}

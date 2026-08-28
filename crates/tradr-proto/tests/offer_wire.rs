//! Tests `tradr_proto::control`'s conversions between wire `control.proto` Offer
//! messages and `tradr_core`'s native Offer types (docs/04-protocol.md, DCR-058,
//! DCR-059). Round trips first, then hostile inputs, followed by dropped fields.

use std::str::FromStr;

use tradr_core::{
    ItemAcceptanceError, ItemId, OfferItemError, RelPath, TransferAcceptError, TransferId,
    TransferOfferError,
};
use tradr_proto::control::{
    OfferFrameError, OfferWireError, decode_transfer_accept_frame, decode_transfer_offer_frame,
    decode_transfer_reject_frame, encode_transfer_accept_frame, encode_transfer_offer_frame,
    encode_transfer_reject_frame, transfer_accept_from_wire, transfer_accept_to_wire,
    transfer_offer_from_wire, transfer_offer_to_wire, transfer_reject_from_wire,
    transfer_reject_to_wire,
};
use tradr_proto::framing::{FrameDecoder, FrameError, encode_frame};
use tradr_proto::message_type::MessageType;
use tradr_proto::v1;

fn valid_offer() -> v1::TransferOffer {
    v1::TransferOffer {
        transfer_id: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".to_string(),
        items: vec![v1::OfferItem {
            item_id: "item-1".to_string(),
            relative_path: "docs/report.pdf".to_string(),
            size: 1048576,
            content_hash: vec![0xaa; 32],
            mtime: 1_700_000_000,
            mime: "application/pdf".to_string(),
            chunk_size: 1048576,
        }],
        total_bytes: 1048576,
        sender_label: "kitchen-laptop".to_string(),
        origin: v1::OfferOrigin::DragDrop as i32,
    }
}

fn valid_accept() -> v1::TransferAccept {
    v1::TransferAccept {
        transfer_id: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".to_string(),
        items: vec![v1::ItemAcceptance {
            item_id: "item-1".to_string(),
            accepted: true,
            resume_chunk: 0,
            have_chunks: Vec::new(),
        }],
        destination_label: "Downloads".to_string(),
    }
}

fn valid_reject() -> v1::TransferReject {
    v1::TransferReject {
        transfer_id: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".to_string(),
        reason: v1::RejectReason::NoSpace as i32,
        note: "Disk full".to_string(),
    }
}

// ---- Round trips ----

#[test]
fn offer_round_trips() {
    let wire = valid_offer();
    let offer = transfer_offer_from_wire(wire.clone()).expect("valid offer must convert");
    let back = transfer_offer_to_wire(&offer);

    assert_eq!(back.transfer_id, wire.transfer_id);
    assert_eq!(back.total_bytes, wire.total_bytes);
    assert_eq!(back.sender_label, wire.sender_label);
    assert_eq!(back.origin, wire.origin);
    assert_eq!(back.items.len(), 1);
    assert_eq!(back.items[0].item_id, wire.items[0].item_id);
    assert_eq!(back.items[0].relative_path, wire.items[0].relative_path);
    assert_eq!(back.items[0].size, wire.items[0].size);
    assert_eq!(back.items[0].content_hash, wire.items[0].content_hash);
    assert_eq!(back.items[0].chunk_size, wire.items[0].chunk_size);

    let offer_back = transfer_offer_from_wire(back).expect("wire back must convert");
    assert_eq!(offer, offer_back);
}

#[test]
fn accept_round_trips() {
    let wire = valid_accept();
    let accept = transfer_accept_from_wire(wire.clone()).expect("valid accept must convert");
    let back = transfer_accept_to_wire(&accept);

    assert_eq!(back.transfer_id, wire.transfer_id);
    assert_eq!(back.destination_label, wire.destination_label);
    assert_eq!(back.items.len(), 1);
    assert_eq!(back.items[0].item_id, wire.items[0].item_id);
    assert_eq!(back.items[0].accepted, wire.items[0].accepted);
    assert_eq!(back.items[0].resume_chunk, wire.items[0].resume_chunk);
    assert_eq!(back.items[0].have_chunks, wire.items[0].have_chunks);

    let accept_back = transfer_accept_from_wire(back).expect("wire back must convert");
    assert_eq!(accept, accept_back);
}

#[test]
fn reject_round_trips() {
    let wire = valid_reject();
    let reject = transfer_reject_from_wire(wire.clone()).expect("valid reject must convert");
    let back = transfer_reject_to_wire(&reject);

    assert_eq!(back.transfer_id, wire.transfer_id);
    assert_eq!(back.reason, wire.reason);
    assert_eq!(back.note, wire.note);

    let reject_back = transfer_reject_from_wire(back).expect("wire back must convert");
    assert_eq!(reject, reject_back);
}

// ---- to_wire is infallible ----

#[test]
fn to_wire_directions_do_not_return_a_result() {
    let offer = transfer_offer_from_wire(valid_offer()).expect("valid offer must convert");
    let _: v1::TransferOffer = transfer_offer_to_wire(&offer);

    let accept = transfer_accept_from_wire(valid_accept()).expect("valid accept must convert");
    let _: v1::TransferAccept = transfer_accept_to_wire(&accept);

    let reject = transfer_reject_from_wire(valid_reject()).expect("valid reject must convert");
    let _: v1::TransferReject = transfer_reject_to_wire(&reject);
}

// ---- Frame round trips ----

#[test]
fn framed_offer_round_trips() {
    let offer = transfer_offer_from_wire(valid_offer()).expect("valid offer must convert");
    let framed_bytes =
        encode_transfer_offer_frame(&offer, 65536).expect("encoding offer frame must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    let decoded =
        decode_transfer_offer_frame(&frame).expect("decoding TransferOffer frame must succeed");
    assert_eq!(decoded, offer);
}

#[test]
fn framed_accept_round_trips() {
    let accept = transfer_accept_from_wire(valid_accept()).expect("valid accept must convert");
    let framed_bytes =
        encode_transfer_accept_frame(&accept, 65536).expect("encoding accept frame must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    let decoded =
        decode_transfer_accept_frame(&frame).expect("decoding TransferAccept frame must succeed");
    assert_eq!(decoded, accept);
}

#[test]
fn framed_reject_round_trips() {
    let reject = transfer_reject_from_wire(valid_reject()).expect("valid reject must convert");
    let framed_bytes =
        encode_transfer_reject_frame(&reject, 65536).expect("encoding reject frame must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    let decoded =
        decode_transfer_reject_frame(&frame).expect("decoding TransferReject frame must succeed");
    assert_eq!(decoded, reject);
}

// ---- Hostile inputs, one test per refusal ----

#[test]
fn transfer_id_not_uuidv7_is_refused() {
    let mut wire = valid_offer();
    wire.transfer_id = "not-a-uuid".to_string();

    let err = transfer_offer_from_wire(wire).expect_err("invalid transfer_id must be refused");
    assert!(matches!(err, OfferWireError::InvalidTransferId(_)));
}

#[test]
fn offer_with_empty_items_is_refused() {
    let mut wire = valid_offer();
    wire.items = vec![];
    wire.total_bytes = 0;

    let err = transfer_offer_from_wire(wire).expect_err("empty items must be refused");
    assert_eq!(
        err,
        OfferWireError::InvalidOffer(TransferOfferError::NoItems)
    );
}

#[test]
fn offer_with_duplicate_item_id_is_refused() {
    let mut wire = valid_offer();
    let item1 = wire.items[0].clone();
    let mut item2 = wire.items[0].clone();
    item2.relative_path = "docs/other.pdf".to_string();
    wire.items = vec![item1, item2];
    wire.total_bytes = 2 * 1048576;

    let err = transfer_offer_from_wire(wire).expect_err("duplicate item_id must be refused");
    assert_eq!(
        err,
        OfferWireError::InvalidOffer(TransferOfferError::DuplicateItemId(
            ItemId::new("item-1").expect("valid")
        ))
    );
}

#[test]
fn offer_with_total_bytes_mismatch_is_refused() {
    let mut wire = valid_offer();
    wire.total_bytes = 200;

    let err = transfer_offer_from_wire(wire).expect_err("total_bytes mismatch must be refused");
    assert_eq!(
        err,
        OfferWireError::InvalidOffer(TransferOfferError::TotalBytesMismatch {
            declared: 200,
            summed: 1048576,
        })
    );
}

#[test]
fn offer_with_zero_size_item_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].size = 0;
    wire.total_bytes = 0;

    let err = transfer_offer_from_wire(wire).expect_err("zero size item must be refused");
    assert_eq!(err, OfferWireError::InvalidItem(OfferItemError::EmptySize));
}

#[test]
fn offer_with_content_hash_of_31_bytes_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].content_hash = vec![0xaa; 31];

    let err = transfer_offer_from_wire(wire).expect_err("31-byte content_hash must be refused");
    assert_eq!(err, OfferWireError::InvalidContentHash { len: 31 });
}

#[test]
fn offer_with_content_hash_of_33_bytes_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].content_hash = vec![0xaa; 33];

    let err = transfer_offer_from_wire(wire).expect_err("33-byte content_hash must be refused");
    assert_eq!(err, OfferWireError::InvalidContentHash { len: 33 });
}

#[test]
fn offer_with_escaping_relative_path_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].relative_path = "../escape".to_string();

    let err = transfer_offer_from_wire(wire).expect_err("escaping relative_path must be refused");
    assert!(matches!(err, OfferWireError::InvalidRelPath(_)));
}

#[test]
fn offer_with_overlong_item_id_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].item_id = "a".repeat(65);

    let err = transfer_offer_from_wire(wire).expect_err("overlong item_id must be refused");
    assert!(matches!(err, OfferWireError::InvalidItemId(_)));
}

#[test]
fn offer_with_zero_chunk_size_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].chunk_size = 0;

    let err = transfer_offer_from_wire(wire).expect_err("zero chunk_size must be refused");
    assert_eq!(err, OfferWireError::InvalidChunkSize { got: 0 });
}

#[test]
fn offer_with_512k_chunk_size_is_refused() {
    let mut wire = valid_offer();
    wire.items[0].chunk_size = 524288;

    let err = transfer_offer_from_wire(wire).expect_err("512k chunk_size must be refused");
    assert_eq!(err, OfferWireError::InvalidChunkSize { got: 524288 });
}

#[test]
fn accept_with_duplicate_have_chunks_is_refused() {
    let mut wire = valid_accept();
    wire.items[0].have_chunks = vec![1, 3, 1];

    let err = transfer_accept_from_wire(wire).expect_err("duplicate have_chunk must be refused");
    assert_eq!(
        err,
        OfferWireError::InvalidItemAcceptance(ItemAcceptanceError::DuplicateHaveChunk(1))
    );
}

#[test]
fn accept_declined_item_with_nonzero_resume_chunk_is_refused() {
    let mut wire = valid_accept();
    wire.items[0].accepted = false;
    wire.items[0].resume_chunk = 5;

    let err = transfer_accept_from_wire(wire)
        .expect_err("declined item with resume_chunk must be refused");
    assert_eq!(
        err,
        OfferWireError::InvalidItemAcceptance(ItemAcceptanceError::DeclinedWithProgress)
    );
}

#[test]
fn accept_with_empty_items_is_refused() {
    let mut wire = valid_accept();
    wire.items = vec![];

    let err = transfer_accept_from_wire(wire).expect_err("empty accept items must be refused");
    assert_eq!(
        err,
        OfferWireError::InvalidAccept(TransferAcceptError::NoItems)
    );
}

#[test]
fn decode_offer_frame_with_wrong_type_is_refused() {
    let accept = transfer_accept_from_wire(valid_accept()).expect("valid accept");
    let framed_bytes = encode_transfer_accept_frame(&accept, 65536).expect("encoding");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    let err = decode_transfer_offer_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        OfferFrameError::WrongMessageType {
            expected: MessageType::TransferOffer.code(),
            got: MessageType::TransferAccept.code(),
        }
    );
}

#[test]
fn decode_accept_frame_with_wrong_type_is_refused() {
    let offer = transfer_offer_from_wire(valid_offer()).expect("valid offer");
    let framed_bytes = encode_transfer_offer_frame(&offer, 65536).expect("encoding");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    let err = decode_transfer_accept_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        OfferFrameError::WrongMessageType {
            expected: MessageType::TransferAccept.code(),
            got: MessageType::TransferOffer.code(),
        }
    );
}

#[test]
fn decode_reject_frame_with_wrong_type_is_refused() {
    let offer = transfer_offer_from_wire(valid_offer()).expect("valid offer");
    let framed_bytes = encode_transfer_offer_frame(&offer, 65536).expect("encoding");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&framed_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame header must succeed")
        .expect("frame must be complete");

    let err = decode_transfer_reject_frame(&frame).expect_err("wrong message type must be refused");
    assert_eq!(
        err,
        OfferFrameError::WrongMessageType {
            expected: MessageType::TransferReject.code(),
            got: MessageType::TransferOffer.code(),
        }
    );
}

// ---- Dropped decorations ----

#[test]
fn sender_label_of_300_bytes_is_dropped_not_refused() {
    let mut wire = valid_offer();
    wire.sender_label = "a".repeat(300);

    let offer = transfer_offer_from_wire(wire).expect("overlong sender_label must not refuse");
    assert_eq!(offer.sender_label(), None);
}

#[test]
fn sender_label_with_control_char_is_dropped_not_refused() {
    let mut wire = valid_offer();
    wire.sender_label = "Alice\nBob".to_string();

    let offer =
        transfer_offer_from_wire(wire).expect("sender_label with control char must not refuse");
    assert_eq!(offer.sender_label(), None);
}

#[test]
fn origin_of_zero_is_dropped_to_none() {
    let mut wire = valid_offer();
    wire.origin = 0;

    let offer = transfer_offer_from_wire(wire).expect("unspecified origin must not refuse");
    assert_eq!(offer.origin(), None);
}

#[test]
fn origin_of_99_is_dropped_to_none() {
    let mut wire = valid_offer();
    wire.origin = 99;

    let offer = transfer_offer_from_wire(wire).expect("unknown origin must not refuse");
    assert_eq!(offer.origin(), None);
}

#[test]
fn reason_of_zero_is_dropped_to_none() {
    let mut wire = valid_reject();
    wire.reason = 0;

    let reject = transfer_reject_from_wire(wire).expect("unspecified reason must not refuse");
    assert_eq!(reject.reason(), None);
}

#[test]
fn reason_of_99_is_dropped_to_none() {
    let mut wire = valid_reject();
    wire.reason = 99;

    let reject = transfer_reject_from_wire(wire).expect("unknown reason must not refuse");
    assert_eq!(reject.reason(), None);
}

#[test]
fn destination_label_overlong_is_dropped_not_refused() {
    let mut wire = valid_accept();
    wire.destination_label = "a".repeat(300);

    let accept =
        transfer_accept_from_wire(wire).expect("overlong destination_label must not refuse");
    assert_eq!(accept.destination_label(), None);
}

// ---- mime and mtime dropped ----

#[test]
fn mime_and_mtime_are_dropped_and_reset_on_wire_conversion() {
    let mut wire = valid_offer();
    wire.items[0].mime = "image/png".to_string();
    wire.items[0].mtime = 1_700_000_000;

    let offer = transfer_offer_from_wire(wire).expect("valid offer with mime/mtime must convert");
    let back = transfer_offer_to_wire(&offer);

    assert_eq!(back.items[0].mime, "");
    assert_eq!(back.items[0].mtime, 0);
}

// ---- Error display and framing error coverage ----

#[test]
fn offer_wire_error_display_covers_every_variant() {
    let variants = [
        OfferWireError::InvalidTransferId(
            TransferId::from_str("bad-id").expect_err("bad transfer id"),
        ),
        OfferWireError::InvalidChunkSize { got: 500 },
        OfferWireError::InvalidItemId(ItemId::new("").expect_err("empty item id")),
        OfferWireError::InvalidRelPath(RelPath::new("../bad").expect_err("escape path")),
        OfferWireError::InvalidContentHash { len: 20 },
        OfferWireError::InvalidItem(OfferItemError::EmptySize),
        OfferWireError::InvalidOffer(TransferOfferError::NoItems),
        OfferWireError::InvalidItemAcceptance(ItemAcceptanceError::DeclinedWithProgress),
        OfferWireError::InvalidAccept(TransferAcceptError::NoItems),
    ];
    for variant in variants {
        let text = variant.to_string();
        assert!(!text.is_empty());
    }
}

#[test]
fn offer_frame_error_display_covers_all_variants() {
    let variants = [
        OfferFrameError::WrongMessageType {
            expected: 0x03,
            got: 0x04,
        },
        OfferFrameError::Framing(FrameError::Empty),
        OfferFrameError::Wire(OfferWireError::InvalidItem(OfferItemError::EmptySize)),
    ];
    for variant in variants {
        let text = variant.to_string();
        assert!(!text.is_empty());
    }
}

#[test]
fn encode_offer_frame_oversized_is_refused() {
    let offer = transfer_offer_from_wire(valid_offer()).expect("valid offer must convert");
    let err = encode_transfer_offer_frame(&offer, 10).expect_err("oversized frame must fail");
    assert!(matches!(
        err,
        OfferFrameError::Framing(FrameError::Oversized { .. })
    ));
}

#[test]
fn encode_accept_frame_oversized_is_refused() {
    let accept = transfer_accept_from_wire(valid_accept()).expect("valid accept must convert");
    let err = encode_transfer_accept_frame(&accept, 10).expect_err("oversized frame must fail");
    assert!(matches!(
        err,
        OfferFrameError::Framing(FrameError::Oversized { .. })
    ));
}

#[test]
fn encode_reject_frame_oversized_is_refused() {
    let reject = transfer_reject_from_wire(valid_reject()).expect("valid reject must convert");
    let err = encode_transfer_reject_frame(&reject, 10).expect_err("oversized frame must fail");
    assert!(matches!(
        err,
        OfferFrameError::Framing(FrameError::Oversized { .. })
    ));
}

#[test]
fn decode_offer_frame_corrupted_protobuf_is_refused() {
    let corrupt_payload = vec![0xFF, 0xFF, 0xFF];
    let frame_bytes = encode_frame(MessageType::TransferOffer.code(), &corrupt_payload, 65536)
        .expect("framing raw bytes must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be present");

    let err = decode_transfer_offer_frame(&frame).expect_err("corrupt protobuf must fail");
    assert!(matches!(err, OfferFrameError::Decode(_)));
}

#[test]
fn decode_offer_frame_invalid_fields_is_refused() {
    let empty_payload = Vec::new();
    let frame_bytes = encode_frame(MessageType::TransferOffer.code(), &empty_payload, 65536)
        .expect("framing raw bytes must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder
        .next_frame()
        .expect("decoding frame must succeed")
        .expect("frame must be present");

    let err = decode_transfer_offer_frame(&frame).expect_err("empty wire payload must fail");
    assert!(matches!(
        err,
        OfferFrameError::Wire(OfferWireError::InvalidTransferId(_))
    ));
}

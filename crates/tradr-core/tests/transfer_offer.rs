//! Tests for Transfer Offer domain types in tradr-core (docs/04-protocol.md,
//! DCR-058): `OfferOrigin`, `RejectReason`, `OfferItem`, `TransferOffer`,
//! `ItemAcceptance`, `TransferAccept`, and `TransferReject`.

use tradr_core::{
    ContentHash, DisplayName, ItemAcceptance, ItemAcceptanceError, ItemId, OfferItem,
    OfferItemError, OfferOrigin, OfferOriginError, REFERENCE_CHUNK_SIZE_BYTES, RejectReason,
    RejectReasonError, RelPath, TransferAccept, TransferAcceptError, TransferId, TransferOffer,
    TransferOfferError, TransferReject,
};

const VALID_TRANSFER_ID_1: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
const VALID_TRANSFER_ID_2: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c073990";

fn sample_transfer_id() -> TransferId {
    VALID_TRANSFER_ID_1.parse().expect("valid transfer id")
}

fn sample_transfer_id_other() -> TransferId {
    VALID_TRANSFER_ID_2.parse().expect("valid transfer id")
}

fn sample_item_id(name: &str) -> ItemId {
    ItemId::new(name).expect("valid item id")
}

fn sample_rel_path(path: &str) -> RelPath {
    RelPath::new(path).expect("valid rel path")
}

fn sample_hash(byte: u8) -> ContentHash {
    ContentHash::from_bytes([byte; 32])
}

fn sample_display_name(name: &str) -> DisplayName {
    DisplayName::new(name).expect("valid display name")
}

// --- OfferOrigin & RejectReason ---

#[test]
fn offer_origin_variants_match() {
    let origins = [
        OfferOrigin::DragDrop,
        OfferOrigin::ShareSheet,
        OfferOrigin::ShareBrowse,
        OfferOrigin::Clipboard,
    ];
    for origin in origins {
        let copy = origin;
        assert_eq!(origin, copy);
    }
}

#[test]
fn offer_origin_wire_values_match_control_proto() {
    assert_eq!(i32::from(OfferOrigin::DragDrop), 1);
    assert_eq!(i32::from(OfferOrigin::ShareSheet), 2);
    assert_eq!(i32::from(OfferOrigin::ShareBrowse), 3);
    assert_eq!(i32::from(OfferOrigin::Clipboard), 4);
}

#[test]
fn offer_origin_try_from_round_trips_every_variant() {
    for origin in [
        OfferOrigin::DragDrop,
        OfferOrigin::ShareSheet,
        OfferOrigin::ShareBrowse,
        OfferOrigin::Clipboard,
    ] {
        let wire: i32 = origin.into();
        assert_eq!(OfferOrigin::try_from(wire), Ok(origin));
    }
}

#[test]
fn offer_origin_try_from_rejects_unspecified() {
    assert_eq!(OfferOrigin::try_from(0), Err(OfferOriginError::Unspecified));
}

#[test]
fn offer_origin_try_from_rejects_unknown() {
    assert_eq!(
        OfferOrigin::try_from(99),
        Err(OfferOriginError::Unknown(99))
    );
}

#[test]
fn reject_reason_variants_match() {
    let reasons = [
        RejectReason::UserDeclined,
        RejectReason::NoSpace,
        RejectReason::TooLarge,
        RejectReason::NotTrusted,
        RejectReason::Busy,
    ];
    for reason in reasons {
        let copy = reason;
        assert_eq!(reason, copy);
    }
}

#[test]
fn reject_reason_wire_values_match_control_proto() {
    assert_eq!(i32::from(RejectReason::UserDeclined), 1);
    assert_eq!(i32::from(RejectReason::NoSpace), 2);
    assert_eq!(i32::from(RejectReason::TooLarge), 3);
    assert_eq!(i32::from(RejectReason::NotTrusted), 4);
    assert_eq!(i32::from(RejectReason::Busy), 5);
}

#[test]
fn reject_reason_try_from_round_trips_every_variant() {
    for reason in [
        RejectReason::UserDeclined,
        RejectReason::NoSpace,
        RejectReason::TooLarge,
        RejectReason::NotTrusted,
        RejectReason::Busy,
    ] {
        let wire: i32 = reason.into();
        assert_eq!(RejectReason::try_from(wire), Ok(reason));
    }
}

#[test]
fn reject_reason_try_from_rejects_unspecified() {
    assert_eq!(
        RejectReason::try_from(0),
        Err(RejectReasonError::Unspecified)
    );
}

#[test]
fn reject_reason_try_from_rejects_unknown() {
    assert_eq!(
        RejectReason::try_from(99),
        Err(RejectReasonError::Unknown(99))
    );
}

// --- OfferItem ---

#[test]
fn offer_item_constructs_and_exposes_fields() {
    let item_id = sample_item_id("item_1");
    let rel_path = sample_rel_path("docs/report.pdf");
    let size = 2 * REFERENCE_CHUNK_SIZE_BYTES;
    let hash = sample_hash(0xaa);

    let item = OfferItem::new(item_id, rel_path.clone(), size, hash).expect("valid offer item");

    assert_eq!(item.item_id(), &item_id);
    assert_eq!(item.rel_path(), &rel_path);
    assert_eq!(item.size(), size);
    assert_eq!(item.content_hash(), &hash);
    assert_eq!(item.chunk_count(), 2);
}

#[test]
fn offer_item_chunk_count_rounds_up() {
    let item1 = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("a.bin"),
        1,
        sample_hash(1),
    )
    .expect("valid");
    assert_eq!(item1.chunk_count(), 1);

    let item_exact = OfferItem::new(
        sample_item_id("item_2"),
        sample_rel_path("b.bin"),
        REFERENCE_CHUNK_SIZE_BYTES,
        sample_hash(2),
    )
    .expect("valid");
    assert_eq!(item_exact.chunk_count(), 1);

    let item_over = OfferItem::new(
        sample_item_id("item_3"),
        sample_rel_path("c.bin"),
        REFERENCE_CHUNK_SIZE_BYTES + 1,
        sample_hash(3),
    )
    .expect("valid");
    assert_eq!(item_over.chunk_count(), 2);

    let item_5mb = OfferItem::new(
        sample_item_id("item_4"),
        sample_rel_path("d.bin"),
        5 * REFERENCE_CHUNK_SIZE_BYTES,
        sample_hash(4),
    )
    .expect("valid");
    assert_eq!(item_5mb.chunk_count(), 5);
}

#[test]
fn offer_item_refuses_zero_size() {
    let result = OfferItem::new(
        sample_item_id("item_zero"),
        sample_rel_path("empty.txt"),
        0,
        sample_hash(0),
    );
    assert_eq!(result, Err(OfferItemError::EmptySize));
}

// --- TransferOffer ---

#[test]
fn transfer_offer_constructs_and_exposes_fields() {
    let tid = sample_transfer_id();
    let item1 = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("photos/pic1.png"),
        1000,
        sample_hash(1),
    )
    .expect("valid");
    let item2 = OfferItem::new(
        sample_item_id("item_2"),
        sample_rel_path("photos/pic2.png"),
        2000,
        sample_hash(2),
    )
    .expect("valid");

    let sender = sample_display_name("Alice's Phone");
    let offer = TransferOffer::new(
        tid,
        vec![item1.clone(), item2.clone()],
        3000,
        Some(sender.clone()),
        Some(OfferOrigin::DragDrop),
    )
    .expect("valid offer");

    assert_eq!(offer.transfer_id(), tid);
    assert_eq!(offer.items(), &[item1, item2]);
    assert_eq!(offer.total_bytes(), 3000);
    assert_eq!(offer.sender_label(), Some(&sender));
    assert_eq!(offer.origin(), Some(OfferOrigin::DragDrop));
}

#[test]
fn transfer_offer_constructs_without_sender_label() {
    let tid = sample_transfer_id();
    let item = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file.txt"),
        500,
        sample_hash(1),
    )
    .expect("valid");

    let offer = TransferOffer::new(tid, vec![item], 500, None, Some(OfferOrigin::ShareSheet))
        .expect("valid offer");

    assert_eq!(offer.sender_label(), None);
    assert_eq!(offer.origin(), Some(OfferOrigin::ShareSheet));
}

#[test]
fn transfer_offer_constructs_without_origin() {
    let tid = sample_transfer_id();
    let item = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file.txt"),
        500,
        sample_hash(1),
    )
    .expect("valid");

    let offer = TransferOffer::new(tid, vec![item], 500, None, None).expect("valid offer");

    assert_eq!(offer.origin(), None);
}

#[test]
fn transfer_offer_refuses_empty_items() {
    let result = TransferOffer::new(
        sample_transfer_id(),
        vec![],
        0,
        None,
        Some(OfferOrigin::DragDrop),
    );
    assert_eq!(result, Err(TransferOfferError::NoItems));
}

#[test]
fn transfer_offer_refuses_duplicate_item_id() {
    let item1 = OfferItem::new(
        sample_item_id("dup_item"),
        sample_rel_path("a.txt"),
        100,
        sample_hash(1),
    )
    .expect("valid");
    let item2 = OfferItem::new(
        sample_item_id("dup_item"),
        sample_rel_path("b.txt"),
        200,
        sample_hash(2),
    )
    .expect("valid");

    let result = TransferOffer::new(
        sample_transfer_id(),
        vec![item1, item2],
        300,
        None,
        Some(OfferOrigin::DragDrop),
    );
    assert_eq!(
        result,
        Err(TransferOfferError::DuplicateItemId(sample_item_id(
            "dup_item"
        )))
    );
}

#[test]
fn transfer_offer_refuses_total_bytes_mismatch() {
    let item = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file.txt"),
        100,
        sample_hash(1),
    )
    .expect("valid");

    let result = TransferOffer::new(
        sample_transfer_id(),
        vec![item],
        200, // declared 200, but sum is 100
        None,
        Some(OfferOrigin::Clipboard),
    );
    assert_eq!(
        result,
        Err(TransferOfferError::TotalBytesMismatch {
            declared: 200,
            summed: 100,
        })
    );
}

#[test]
fn transfer_offer_refuses_total_bytes_overflow() {
    let item1 = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("large1.bin"),
        u64::MAX,
        sample_hash(1),
    )
    .expect("valid");
    let item2 = OfferItem::new(
        sample_item_id("item_2"),
        sample_rel_path("large2.bin"),
        1,
        sample_hash(2),
    )
    .expect("valid");

    let result = TransferOffer::new(
        sample_transfer_id(),
        vec![item1, item2],
        u64::MAX,
        None,
        Some(OfferOrigin::ShareBrowse),
    );
    assert!(matches!(
        result,
        Err(TransferOfferError::TotalBytesMismatch { .. })
    ));
}

// --- ItemAcceptance ---

#[test]
fn item_acceptance_constructs_and_exposes_fields() {
    let item_id = sample_item_id("item_1");
    let acc = ItemAcceptance::new(item_id, true, 3, vec![1, 2, 5]).expect("valid acceptance");

    assert_eq!(acc.item_id(), &item_id);
    assert!(acc.accepted());
    assert_eq!(acc.resume_chunk(), 3);
    assert_eq!(acc.have_chunks(), &[1, 2, 5]);
}

#[test]
fn item_acceptance_declined_constructs_with_zero_progress() {
    let item_id = sample_item_id("item_declined");
    let acc = ItemAcceptance::new(item_id, false, 0, vec![]).expect("valid declined item");

    assert_eq!(acc.item_id(), &item_id);
    assert!(!acc.accepted());
    assert_eq!(acc.resume_chunk(), 0);
    assert!(acc.have_chunks().is_empty());
}

#[test]
fn item_acceptance_refuses_declined_with_resume_chunk() {
    let result = ItemAcceptance::new(sample_item_id("item_1"), false, 1, vec![]);
    assert_eq!(result, Err(ItemAcceptanceError::DeclinedWithProgress));
}

#[test]
fn item_acceptance_refuses_declined_with_have_chunks() {
    let result = ItemAcceptance::new(sample_item_id("item_1"), false, 0, vec![2]);
    assert_eq!(result, Err(ItemAcceptanceError::DeclinedWithProgress));
}

#[test]
fn item_acceptance_refuses_duplicate_have_chunks() {
    let result = ItemAcceptance::new(sample_item_id("item_1"), true, 0, vec![1, 4, 1]);
    assert_eq!(result, Err(ItemAcceptanceError::DuplicateHaveChunk(1)));
}

// --- TransferAccept ---

#[test]
fn transfer_accept_constructs_and_exposes_fields() {
    let tid = sample_transfer_id();
    let acc1 = ItemAcceptance::new(sample_item_id("item_1"), true, 0, vec![]).expect("valid");
    let acc2 = ItemAcceptance::new(sample_item_id("item_2"), false, 0, vec![]).expect("valid");
    let label = sample_display_name("Downloads");

    let accept = TransferAccept::new(tid, vec![acc1.clone(), acc2.clone()], Some(label.clone()))
        .expect("valid transfer accept");

    assert_eq!(accept.transfer_id(), tid);
    assert_eq!(accept.items(), &[acc1, acc2]);
    assert_eq!(accept.destination_label(), Some(&label));
}

#[test]
fn transfer_accept_refuses_empty_items() {
    let result = TransferAccept::new(sample_transfer_id(), vec![], None);
    assert_eq!(result, Err(TransferAcceptError::NoItems));
}

#[test]
fn transfer_accept_refuses_duplicate_item_id() {
    let acc1 = ItemAcceptance::new(sample_item_id("dup_item"), true, 0, vec![]).expect("valid");
    let acc2 = ItemAcceptance::new(sample_item_id("dup_item"), false, 0, vec![]).expect("valid");

    let result = TransferAccept::new(sample_transfer_id(), vec![acc1, acc2], None);
    assert_eq!(
        result,
        Err(TransferAcceptError::DuplicateItemId(sample_item_id(
            "dup_item"
        )))
    );
}

// --- TransferAccept::for_offer ---

#[test]
fn transfer_accept_for_offer_validates_matching_offer() {
    let tid = sample_transfer_id();
    let item1 = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file1.dat"),
        3 * REFERENCE_CHUNK_SIZE_BYTES, // 3 chunks: indices 0, 1, 2
        sample_hash(1),
    )
    .expect("valid");
    let item2 = OfferItem::new(
        sample_item_id("item_2"),
        sample_rel_path("file2.dat"),
        REFERENCE_CHUNK_SIZE_BYTES, // 1 chunk: index 0
        sample_hash(2),
    )
    .expect("valid");

    let offer = TransferOffer::new(
        tid,
        vec![item1, item2],
        4 * REFERENCE_CHUNK_SIZE_BYTES,
        None,
        Some(OfferOrigin::DragDrop),
    )
    .expect("valid offer");

    let acc1 = ItemAcceptance::new(sample_item_id("item_1"), true, 1, vec![0, 2]).expect("valid");
    let acc2 = ItemAcceptance::new(sample_item_id("item_2"), false, 0, vec![]).expect("valid");

    let accept = TransferAccept::new(tid, vec![acc1, acc2], None).expect("valid accept");
    assert_eq!(accept.for_offer(&offer), Ok(()));
}

#[test]
fn transfer_accept_for_offer_refuses_transfer_id_mismatch() {
    let tid1 = sample_transfer_id();
    let tid2 = sample_transfer_id_other();

    let item = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file.txt"),
        100,
        sample_hash(1),
    )
    .expect("valid");
    let offer = TransferOffer::new(tid1, vec![item], 100, None, Some(OfferOrigin::DragDrop))
        .expect("valid offer");

    let acc = ItemAcceptance::new(sample_item_id("item_1"), true, 0, vec![]).expect("valid");
    let accept = TransferAccept::new(tid2, vec![acc], None).expect("valid accept");

    assert_eq!(
        accept.for_offer(&offer),
        Err(TransferAcceptError::TransferIdMismatch)
    );
}

#[test]
fn transfer_accept_for_offer_refuses_unknown_item_id() {
    let tid = sample_transfer_id();
    let item = OfferItem::new(
        sample_item_id("known_item"),
        sample_rel_path("file.txt"),
        100,
        sample_hash(1),
    )
    .expect("valid");
    let offer = TransferOffer::new(tid, vec![item], 100, None, Some(OfferOrigin::DragDrop))
        .expect("valid offer");

    let acc = ItemAcceptance::new(sample_item_id("unknown_item"), true, 0, vec![]).expect("valid");
    let accept = TransferAccept::new(tid, vec![acc], None).expect("valid accept");

    assert_eq!(
        accept.for_offer(&offer),
        Err(TransferAcceptError::UnknownItemId(sample_item_id(
            "unknown_item"
        )))
    );
}

#[test]
fn transfer_accept_for_offer_refuses_resume_chunk_out_of_range() {
    let tid = sample_transfer_id();
    let item = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file.txt"),
        2 * REFERENCE_CHUNK_SIZE_BYTES, // chunk count: 2 (valid indices: 0, 1)
        sample_hash(1),
    )
    .expect("valid");
    let offer = TransferOffer::new(
        tid,
        vec![item],
        2 * REFERENCE_CHUNK_SIZE_BYTES,
        None,
        Some(OfferOrigin::DragDrop),
    )
    .expect("valid offer");

    // resume_chunk = 2 is >= chunk_count (2)
    let acc = ItemAcceptance::new(sample_item_id("item_1"), true, 2, vec![]).expect("valid");
    let accept = TransferAccept::new(tid, vec![acc], None).expect("valid accept");

    assert_eq!(
        accept.for_offer(&offer),
        Err(TransferAcceptError::ResumeChunkOutOfRange {
            item_id: sample_item_id("item_1"),
            resume_chunk: 2,
            chunk_count: 2,
        })
    );
}

#[test]
fn transfer_accept_for_offer_refuses_have_chunk_out_of_range() {
    let tid = sample_transfer_id();
    let item = OfferItem::new(
        sample_item_id("item_1"),
        sample_rel_path("file.txt"),
        REFERENCE_CHUNK_SIZE_BYTES, // chunk count: 1 (valid index: 0)
        sample_hash(1),
    )
    .expect("valid");
    let offer = TransferOffer::new(
        tid,
        vec![item],
        REFERENCE_CHUNK_SIZE_BYTES,
        None,
        Some(OfferOrigin::DragDrop),
    )
    .expect("valid offer");

    // have_chunks contains 1, which is >= chunk_count (1)
    let acc = ItemAcceptance::new(sample_item_id("item_1"), true, 0, vec![1]).expect("valid");
    let accept = TransferAccept::new(tid, vec![acc], None).expect("valid accept");

    assert_eq!(
        accept.for_offer(&offer),
        Err(TransferAcceptError::HaveChunkOutOfRange {
            item_id: sample_item_id("item_1"),
            chunk: 1,
            chunk_count: 1,
        })
    );
}

// --- TransferReject ---

#[test]
fn transfer_reject_constructs_and_exposes_fields() {
    let tid = sample_transfer_id();
    let note = sample_display_name("Device out of storage");
    let reject = TransferReject::new(tid, Some(RejectReason::NoSpace), Some(note.clone()));

    assert_eq!(reject.transfer_id(), tid);
    assert_eq!(reject.reason(), Some(RejectReason::NoSpace));
    assert_eq!(reject.note(), Some(&note));

    let reject_no_note = TransferReject::new(tid, Some(RejectReason::UserDeclined), None);
    assert_eq!(reject_no_note.transfer_id(), tid);
    assert_eq!(reject_no_note.reason(), Some(RejectReason::UserDeclined));
    assert_eq!(reject_no_note.note(), None);
}

#[test]
fn transfer_reject_constructs_without_reason() {
    let tid = sample_transfer_id();
    let reject = TransferReject::new(tid, None, None);
    assert_eq!(reject.transfer_id(), tid);
    assert_eq!(reject.reason(), None);
    assert_eq!(reject.note(), None);
}

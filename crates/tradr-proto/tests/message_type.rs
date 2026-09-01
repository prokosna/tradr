//! docs/04-protocol.md's "The type byte" section, in full, including its
//! three subsections: a code is assigned once and never reused, a code
//! names a plane and the wrong plane is refused rather than ignored, and
//! what "unknown message types are ignored" actually covers.

use std::collections::HashSet;

use tradr_proto::message_type::{Classification, MessageType, Plane, Refusal, classify};

// Mirrors docs/04's table directly, written independently of
// `message_type.rs`'s own logic, so the exhaustive test below cannot pass
// merely because the implementation agrees with itself.
fn expected_classification(code: u8, arriving_on: Plane) -> Classification {
    if code == 0x00 {
        return Classification::Refused(Refusal::Zero);
    }
    let range_owner = match code {
        0x01..=0x1f => Plane::Control,
        0x20..=0x3f => Plane::Data,
        0x40..=0x5f => Plane::Browse,
        _ => return Classification::Refused(Refusal::OutsideEveryPlane),
    };
    if range_owner != arriving_on {
        return Classification::Refused(Refusal::WrongPlane { range_owner });
    }
    let assigned = match (arriving_on, code) {
        (Plane::Control, 0x01) => Some(MessageType::Hello),
        (Plane::Control, 0x02) => Some(MessageType::HelloAck),
        (Plane::Control, 0x03) => Some(MessageType::TransferOffer),
        (Plane::Control, 0x04) => Some(MessageType::TransferAccept),
        (Plane::Control, 0x05) => Some(MessageType::TransferReject),
        (Plane::Control, 0x06) => Some(MessageType::TransferComplete),
        (Plane::Control, 0x07) => Some(MessageType::TransferAbort),
        (Plane::Control, 0x08) => Some(MessageType::PathChanged),
        (Plane::Control, 0x09) => Some(MessageType::KeepAlive),
        (Plane::Control, 0x0a) => Some(MessageType::ItemComplete),
        (Plane::Control, 0x0b) => Some(MessageType::TransferProgress),
        (Plane::Control, 0x0c) => Some(MessageType::LinkReply),
        (Plane::Control, 0x0d) => Some(MessageType::LinkApprove),
        (Plane::Control, 0x0e) => Some(MessageType::LinkDecline),
        (Plane::Data, 0x20) => Some(MessageType::ChunkRequest),
        (Plane::Data, 0x21) => Some(MessageType::ChunkRerequest),
        (Plane::Data, 0x22) => Some(MessageType::ChunkData),
        (Plane::Data, 0x23) => Some(MessageType::FlowControl),
        (Plane::Browse, 0x40) => Some(MessageType::ListDir),
        (Plane::Browse, 0x41) => Some(MessageType::DirListing),
        (Plane::Browse, 0x42) => Some(MessageType::Stat),
        (Plane::Browse, 0x43) => Some(MessageType::StatResult),
        (Plane::Browse, 0x44) => Some(MessageType::ReadFile),
        (Plane::Browse, 0x45) => Some(MessageType::ReadFileBegin),
        (Plane::Browse, 0x46) => Some(MessageType::WriteFile),
        (Plane::Browse, 0x47) => Some(MessageType::Mkdir),
        (Plane::Browse, 0x48) => Some(MessageType::Delete),
        (Plane::Browse, 0x49) => Some(MessageType::Rename),
        (Plane::Browse, 0x4a) => Some(MessageType::Ack),
        (Plane::Browse, 0x4b) => Some(MessageType::Watch),
        (Plane::Browse, 0x4c) => Some(MessageType::FsEvent),
        _ => None,
    };
    match assigned {
        Some(message_type) => Classification::Known(message_type),
        None => Classification::Ignorable,
    }
}

#[test]
fn classify_matches_the_docs_table_for_every_code_on_every_plane() {
    // 256 codes times 3 planes: every case docs/04's table (and the ranges
    // it defines) can produce.
    for &plane in Plane::ALL {
        for code in 0u8..=255 {
            assert_eq!(
                classify(code, plane),
                expected_classification(code, plane),
                "code 0x{code:02x} arriving on {plane}"
            );
        }
    }
}

#[test]
fn all_has_no_duplicate_code() {
    // DCR-050's failure mode exactly: a reused code decodes as the older
    // message an outdated peer still knows, silently.
    let mut codes = HashSet::new();
    for message_type in MessageType::ALL {
        assert!(
            codes.insert(message_type.code()),
            "code 0x{:02x} is assigned to more than one variant",
            message_type.code()
        );
    }
}

#[test]
fn all_has_no_duplicate_variant_and_every_code_sits_in_its_own_planes_range() {
    let mut seen = HashSet::new();
    for message_type in MessageType::ALL {
        assert!(
            seen.insert(*message_type),
            "{message_type} appears more than once in MessageType::ALL"
        );
        let (low, high) = match message_type.plane() {
            Plane::Control => (0x01u8, 0x1f),
            Plane::Data => (0x20, 0x3f),
            Plane::Browse => (0x40, 0x5f),
        };
        assert!(
            (low..=high).contains(&message_type.code()),
            "{message_type}'s code 0x{:02x} falls outside {}'s own range",
            message_type.code(),
            message_type.plane()
        );
    }
}

#[test]
fn code_round_trips_through_classify() {
    for message_type in MessageType::ALL {
        assert_eq!(
            classify(message_type.code(), message_type.plane()),
            Classification::Known(*message_type)
        );
    }
}

#[test]
fn zero_is_refused_on_every_plane() {
    for &plane in Plane::ALL {
        assert_eq!(
            classify(0x00, plane),
            Classification::Refused(Refusal::Zero)
        );
    }
}

#[test]
fn a_known_code_is_refused_as_wrong_plane_everywhere_else() {
    // Browse's 0x40 ListDir.
    assert_eq!(
        classify(0x40, Plane::Browse),
        Classification::Known(MessageType::ListDir)
    );
    assert_eq!(
        classify(0x40, Plane::Control),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Browse
        })
    );
    assert_eq!(
        classify(0x40, Plane::Data),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Browse
        })
    );

    // Control's 0x01 Hello.
    assert_eq!(
        classify(0x01, Plane::Control),
        Classification::Known(MessageType::Hello)
    );
    assert_eq!(
        classify(0x01, Plane::Data),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Control
        })
    );
    assert_eq!(
        classify(0x01, Plane::Browse),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Control
        })
    );

    // Data's 0x20 ChunkRequest.
    assert_eq!(
        classify(0x20, Plane::Data),
        Classification::Known(MessageType::ChunkRequest)
    );
    assert_eq!(
        classify(0x20, Plane::Control),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Data
        })
    );
    assert_eq!(
        classify(0x20, Plane::Browse),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Data
        })
    );
}

#[test]
fn unassigned_code_inside_a_range_is_ignorable_on_its_own_plane_and_refused_elsewhere() {
    // 0x0f sits in Control's 0x01-0x1f range and is unassigned: the case
    // that separates a plane's range from what it has assigned inside it.
    assert_eq!(classify(0x0f, Plane::Control), Classification::Ignorable);
    assert_eq!(
        classify(0x0f, Plane::Browse),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Control
        })
    );
    assert_eq!(
        classify(0x0f, Plane::Data),
        Classification::Refused(Refusal::WrongPlane {
            range_owner: Plane::Control
        })
    );
}

#[test]
fn codes_outside_every_planes_range_are_refused_everywhere() {
    for &plane in Plane::ALL {
        assert_eq!(
            classify(0x60, plane),
            Classification::Refused(Refusal::OutsideEveryPlane)
        );
        assert_eq!(
            classify(0xff, plane),
            Classification::Refused(Refusal::OutsideEveryPlane)
        );
    }
}

// Expands one identifier list into both an exhaustive match over
// MessageType and a Vec built from the same list, so the two can never
// drift apart. Chosen over std::mem::discriminant because nothing in core
// enumerates an enum's variants from its discriminants alone.
macro_rules! ground_truth_message_types {
    ($($variant:ident),+ $(,)?) => {{
        // No wildcard arm: MessageType gaining a variant not named below
        // fails to compile, standing in for "a test that fails if a
        // variant is added without being added to ALL". Never called: its
        // only job is the compile-time exhaustiveness check above.
        #[allow(dead_code)]
        fn assert_every_variant_named(message_type: MessageType) {
            match message_type {
                $(MessageType::$variant => {})+
            }
        }
        vec![$(MessageType::$variant),+]
    }};
}

#[test]
fn all_matches_an_independently_enumerated_list_of_every_variant() {
    let ground_truth: Vec<MessageType> = ground_truth_message_types![
        Hello,
        HelloAck,
        TransferOffer,
        TransferAccept,
        TransferReject,
        TransferComplete,
        TransferAbort,
        PathChanged,
        KeepAlive,
        ItemComplete,
        TransferProgress,
        LinkReply,
        LinkApprove,
        LinkDecline,
        ChunkRequest,
        ChunkRerequest,
        ChunkData,
        FlowControl,
        ListDir,
        DirListing,
        Stat,
        StatResult,
        ReadFile,
        ReadFileBegin,
        WriteFile,
        Mkdir,
        Delete,
        Rename,
        Ack,
        Watch,
        FsEvent,
    ];

    let ground_truth_set: HashSet<MessageType> = ground_truth.into_iter().collect();
    let all_set: HashSet<MessageType> = MessageType::ALL.iter().copied().collect();
    assert_eq!(
        ground_truth_set, all_set,
        "MessageType::ALL disagrees with the independently enumerated variant list"
    );
    assert_eq!(
        ground_truth_set.len(),
        MessageType::ALL.len(),
        "MessageType::ALL contains a duplicate, masking a missing variant"
    );
    assert_eq!(
        ground_truth_set.len(),
        31,
        "14 Control + 4 Data + 13 Browse"
    );
}

//! Round-trips one message from each of the five `proto/tradr/v1/` files, and
//! checks that a corrupted buffer is rejected rather than silently decoded.

use prost::Message;
use tradr_core::REFERENCE_CHUNK_SIZE_BYTES;
use tradr_proto::v1::{
    BrokrRegister, ChunkData, ChunkRequest, DeviceInfo, Hello, ListDir, Platform,
};

#[test]
fn device_info_round_trips() {
    let original = DeviceInfo {
        device_id: vec![1, 2, 3, 4],
        identity_pub: vec![7; 65],
        agreement_pub: vec![8; 65],
        display_name: "kitchen-laptop".to_string(),
        platform: Platform::Linux as i32,
        capabilities: 0b0101,
    };

    let encoded = original.encode_to_vec();
    let decoded = DeviceInfo::decode(encoded.as_slice()).expect("valid encoding must decode");

    assert_eq!(original, decoded);
}

#[test]
fn list_dir_round_trips() {
    let original = ListDir {
        share_id: "share-42".to_string(),
        path: "photos/2026".to_string(),
        cursor: "cursor-abc".to_string(),
        limit: 500,
        with_hash: true,
    };

    let encoded = original.encode_to_vec();
    let decoded = ListDir::decode(encoded.as_slice()).expect("valid encoding must decode");

    assert_eq!(original, decoded);
}

#[test]
fn hello_round_trips() {
    let original = Hello {
        min_version: 1,
        max_version: 3,
        device: Some(DeviceInfo {
            device_id: vec![9, 9],
            identity_pub: vec![1; 65],
            agreement_pub: vec![2; 65],
            display_name: "phone".to_string(),
            platform: Platform::Android as i32,
            capabilities: 1,
        }),
        attestation: None,
        key_binding: None,
        nonce: vec![0xAB; 16],
    };

    let encoded = original.encode_to_vec();
    let decoded = Hello::decode(encoded.as_slice()).expect("valid encoding must decode");

    assert_eq!(original, decoded);
}

#[test]
fn chunk_request_round_trips() {
    let original = ChunkRequest {
        transfer_id: "transfer-1".to_string(),
        item_id: "item-7".to_string(),
        from_chunk: 12,
        count: 64,
    };

    let encoded = original.encode_to_vec();
    let decoded = ChunkRequest::decode(encoded.as_slice()).expect("valid encoding must decode");

    assert_eq!(original, decoded);
}

#[test]
fn brokr_register_round_trips() {
    let original = BrokrRegister {
        device_id: vec![1, 2, 3],
        identity_pub: vec![4; 65],
        join_token: "join-token-value".to_string(),
        challenge_signature: vec![5; 64],
        display_name: "desktop".to_string(),
        platform: Platform::Macos as i32,
        account_tag: vec![6; 32],
        link_tags: vec![vec![7; 32], vec![8; 32]],
        fcm_token: "fcm-token-value".to_string(),
    };

    let encoded = original.encode_to_vec();
    let decoded = BrokrRegister::decode(encoded.as_slice()).expect("valid encoding must decode");

    assert_eq!(original, decoded);
}

#[test]
fn chunk_data_round_trips_with_offset_in_chunk() {
    let original = ChunkData {
        transfer_id: "transfer-1".to_string(),
        item_id: "item-7".to_string(),
        chunk_index: 3,
        payload_len: 262_144,
        last: false,
        offset_in_chunk: 786_432,
    };

    let encoded = original.encode_to_vec();
    let decoded = ChunkData::decode(encoded.as_slice()).expect("valid encoding must decode");

    assert_eq!(original, decoded);
}

// docs/04-protocol.md rests on offset_in_chunk being free when a transport does
// not subdivide: protobuf omits a zero-valued scalar entirely. This must hold
// on a genuinely non-zero comparison, not just an equal-to-itself one, or the
// test could pass without measuring anything.
#[test]
fn chunk_data_zero_offset_in_chunk_costs_nothing_on_the_wire() {
    let base = ChunkData {
        transfer_id: "transfer-1".to_string(),
        item_id: "item-7".to_string(),
        chunk_index: 3,
        payload_len: 262_144,
        last: false,
        offset_in_chunk: 0,
    };

    let default_offset = base.clone();
    let mut explicit_zero_offset = base.clone();
    explicit_zero_offset.offset_in_chunk = 0;
    let mut non_zero_offset = base;
    non_zero_offset.offset_in_chunk = 262_144;

    let default_encoded = default_offset.encode_to_vec();
    let explicit_zero_encoded = explicit_zero_offset.encode_to_vec();
    let non_zero_encoded = non_zero_offset.encode_to_vec();

    assert_eq!(
        default_encoded, explicit_zero_encoded,
        "a default offset_in_chunk and an explicitly-set-to-zero one must encode identically"
    );
    assert!(
        non_zero_encoded.len() > default_encoded.len(),
        "a non-zero offset_in_chunk must lengthen the encoding, or the zero-cost \
         comparison above proves nothing (default={}, non_zero={})",
        default_encoded.len(),
        non_zero_encoded.len()
    );
}

// DCR-015: the four 256 KiB pieces of one reference chunk must be
// distinguishable from the header alone. payload_len is a length field, not
// the payload itself, so the raw bytes never need allocating for this.
#[test]
fn chunk_data_subdivided_pieces_of_one_reference_chunk_are_distinguishable() {
    const PIECE_SIZE: u32 = 256 * 1024;
    let chunk_index: u64 = 1;

    let pieces: Vec<ChunkData> = (0..4)
        .map(|piece_num| ChunkData {
            transfer_id: "transfer-1".to_string(),
            item_id: "item-7".to_string(),
            chunk_index,
            payload_len: PIECE_SIZE,
            last: piece_num == 3,
            offset_in_chunk: piece_num * PIECE_SIZE,
        })
        .collect();

    let absolute_positions: Vec<u64> = pieces
        .iter()
        .map(|piece| {
            let encoded = piece.encode_to_vec();
            let decoded =
                ChunkData::decode(encoded.as_slice()).expect("valid encoding must decode");
            chunk_index * REFERENCE_CHUNK_SIZE_BYTES + decoded.offset_in_chunk as u64
        })
        .collect();

    let expected: Vec<u64> = (0..4)
        .map(|piece_num: u64| {
            chunk_index * REFERENCE_CHUNK_SIZE_BYTES + piece_num * PIECE_SIZE as u64
        })
        .collect();

    assert_eq!(absolute_positions, expected);

    let unique: std::collections::HashSet<u64> = absolute_positions.iter().copied().collect();
    assert_eq!(
        unique.len(),
        4,
        "the four subdivided pieces must decode to four distinct absolute positions"
    );
}

// Truncating a valid encoding mid-field must produce a decode error, not a
// value. This is the negative case: a corrupted buffer must never decode.
#[test]
fn corrupted_buffer_fails_to_decode() {
    let original = DeviceInfo {
        device_id: vec![1, 2, 3, 4],
        identity_pub: vec![7; 65],
        agreement_pub: vec![8; 65],
        display_name: "truncate-me-please".to_string(),
        platform: Platform::Windows as i32,
        capabilities: 3,
    };

    let mut encoded = original.encode_to_vec();
    assert!(
        encoded.len() > 8,
        "the fixture must be long enough to truncate meaningfully"
    );
    encoded.truncate(encoded.len() - 8);

    let result = DeviceInfo::decode(encoded.as_slice());

    assert!(
        result.is_err(),
        "a buffer truncated mid-field must not decode into a value"
    );
}

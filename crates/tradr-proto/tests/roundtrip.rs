//! Round-trips one message from each of the five `proto/tradr/v1/` files, and
//! checks that a corrupted buffer is rejected rather than silently decoded.

use prost::Message;
use tradr_proto::v1::{BrokrRegister, ChunkRequest, DeviceInfo, Hello, ListDir, Platform};

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

//! Tests for mDNS TXT record construction and local platform detection (WI-M8-014).
//! Verifies the pure network helpers in `tradr_app::network` (Change Drill D10, DCR-126).

mod common;

use tradr_app::network::{device_txt_record, local_platform};
use tradr_core::Capabilities;
use tradr_discovery::{AGREEMENT_KEY_TAG_LEN, Platform};

#[test]
fn local_platform_returns_a_token_accepted_by_platform_new() {
    let token = local_platform();
    let platform = Platform::new(token);
    assert!(
        platform.is_ok(),
        "Platform::new must accept local_platform() token {token:?}"
    );
}

#[test]
fn device_txt_record_publishes_agreement_key_tag_as_first_bytes_of_blake3_over_agreement_pub() {
    let identity = common::identity(42);
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC)
        .expect("record construction must succeed");

    let expected_hash = blake3::hash(identity.agreement_pub().as_bytes());
    let mut expected_tag = [0u8; AGREEMENT_KEY_TAG_LEN];
    expected_tag.copy_from_slice(&expected_hash.as_bytes()[..AGREEMENT_KEY_TAG_LEN]);

    assert_eq!(record.agreement_key_tag(), expected_tag);
}

#[test]
fn device_txt_record_publishes_device_id_of_identity() {
    let identity = common::identity(7);
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC)
        .expect("record construction must succeed");

    assert_eq!(record.device_id(), identity.device_id());
}

#[test]
fn device_txt_record_publishes_exact_capabilities_with_multiple_bits() {
    let identity = common::identity(13);
    let caps =
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | Capabilities::BLE_GATT.bits());
    assert!(caps.bits().count_ones() > 1);

    let record = device_txt_record(&identity, caps).expect("record construction must succeed");

    assert_eq!(record.capabilities(), caps);
}

#[test]
fn device_txt_record_publishes_local_platform_and_no_display_name() {
    let identity = common::identity(99);
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC)
        .expect("record construction must succeed");

    assert_eq!(record.platform().as_str(), local_platform());
    assert!(record.display_name().is_none());
    assert!(
        !record.to_pairs().iter().any(|(k, _)| k == "n"),
        "to_pairs() must carry no 'n' key when display name is none"
    );
}

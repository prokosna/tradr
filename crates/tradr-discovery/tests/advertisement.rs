//! Tests for the BLE advertisement codec (docs/03, ADR-0019).

use tradr_core::Capabilities;
use tradr_discovery::{
    AD_STRUCTURE_OVERHEAD, ADVERTISEMENT_MAX_LEN, ADVERTISEMENT_VERSION, Advertisement,
    AdvertisementError, Eid, FLAGS_AD_LEN, PlatformCode, SERVICE_DATA_LEN, TRADR_SERVICE_UUID,
    TRADR_SERVICE_UUID_LE,
};

fn test_eid(byte: u8) -> Eid {
    Eid::from_bytes(&[byte; 8]).expect("8 bytes must construct")
}

#[test]
fn an_advertisement_round_trips_through_service_data_and_from_service_data_unchanged() {
    let original = Advertisement::new(
        test_eid(0x42),
        PlatformCode::LINUX,
        Capabilities::DIRECT_QUIC,
    );
    let bytes = original.service_data();
    let parsed = Advertisement::from_service_data(&bytes).expect("valid service data must parse");

    assert_eq!(original, parsed);
    assert_eq!(parsed.eid(), test_eid(0x42));
    assert_eq!(parsed.platform(), PlatformCode::LINUX);
    assert_eq!(parsed.capabilities(), Capabilities::DIRECT_QUIC);
}

#[test]
fn service_data_produces_exact_bytes_for_known_eid_platform_and_capabilities() {
    let eid = Eid::from_bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        .expect("8 bytes must construct");
    let ad = Advertisement::new(eid, PlatformCode::LINUX, Capabilities::DIRECT_QUIC);

    let expected = [0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11];
    assert_eq!(ad.service_data(), expected);
}

#[test]
fn version_byte_is_first_byte_and_is_one() {
    let ad = Advertisement::new(test_eid(0x00), PlatformCode::UNKNOWN, Capabilities::empty());
    let bytes = ad.service_data();

    assert_eq!(bytes[0], ADVERTISEMENT_VERSION);
    assert_eq!(bytes[0], 0x01);
}

#[test]
fn from_service_data_refuses_version_byte_two() {
    let mut bytes = [0u8; SERVICE_DATA_LEN];
    bytes[0] = 0x02;

    assert_eq!(
        Advertisement::from_service_data(&bytes),
        Err(AdvertisementError::UnknownVersion(2))
    );
}

#[test]
fn from_service_data_refuses_nine_bytes_and_eleven_bytes() {
    let nine = [0u8; 9];
    assert_eq!(
        Advertisement::from_service_data(&nine),
        Err(AdvertisementError::WrongLength {
            expected: SERVICE_DATA_LEN,
            actual: 9,
        })
    );

    let eleven = [0u8; 11];
    assert_eq!(
        Advertisement::from_service_data(&eleven),
        Err(AdvertisementError::WrongLength {
            expected: SERVICE_DATA_LEN,
            actual: 11,
        })
    );
}

#[test]
fn unassigned_platform_code_round_trips_without_flattening_to_unknown() {
    let unassigned = PlatformCode::from_code(9).expect("code 9 must construct");
    let ad = Advertisement::new(test_eid(0x55), unassigned, Capabilities::BLE_GATT);
    let bytes = ad.service_data();
    let parsed = Advertisement::from_service_data(&bytes).expect("valid service data must parse");

    assert_eq!(parsed.platform().code(), 9);
    assert_eq!(parsed.platform(), unassigned);
    assert_ne!(parsed.platform(), PlatformCode::UNKNOWN);
}

#[test]
fn platform_code_from_code_refuses_values_above_fifteen() {
    assert_eq!(
        PlatformCode::from_code(16),
        Err(AdvertisementError::InvalidPlatformCode(16))
    );
    assert_eq!(
        PlatformCode::from_code(255),
        Err(AdvertisementError::InvalidPlatformCode(255))
    );
}

#[test]
fn advertisement_new_masks_capabilities_to_low_four_bits_and_flags_byte_low_nibble_is_f() {
    let ad = Advertisement::new(
        test_eid(0x77),
        PlatformCode::WINDOWS,
        Capabilities::from_bits(0xFFFF),
    );

    assert_eq!(ad.capabilities(), Capabilities::from_bits(0x0F));
    let bytes = ad.service_data();
    assert_eq!(bytes[9] & 0x0F, 0x0F);
}

#[test]
fn capability_bits_above_bit_three_do_not_reach_the_wire() {
    let with_browsing = Advertisement::new(
        test_eid(0x88),
        PlatformCode::MAC,
        Capabilities::from_bits(
            Capabilities::DIRECT_QUIC.bits() | Capabilities::ACCEPTS_BROWSING.bits(),
        ),
    );
    let without_browsing =
        Advertisement::new(test_eid(0x88), PlatformCode::MAC, Capabilities::DIRECT_QUIC);

    assert_eq!(
        with_browsing.service_data(),
        without_browsing.service_data()
    );
    assert_eq!(
        with_browsing.capabilities(),
        without_browsing.capabilities()
    );
}

#[test]
fn tradr_service_uuid_le_is_tradr_service_uuid_reversed() {
    let mut reversed = TRADR_SERVICE_UUID;
    reversed.reverse();

    assert_eq!(TRADR_SERVICE_UUID_LE, reversed);
}

#[test]
fn ad_structure_budget_sums_to_maximum_advertisement_length() {
    assert_eq!(
        FLAGS_AD_LEN + AD_STRUCTURE_OVERHEAD + SERVICE_DATA_LEN,
        ADVERTISEMENT_MAX_LEN
    );
}

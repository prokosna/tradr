#![cfg(target_os = "linux")]

use std::collections::HashMap;

use tradr_discovery::{BleError, TRADR_SERVICE_UUID, ble_error, tradr_scan_report};

#[test]
fn not_supported_maps_to_unsupported_and_transient_errors_do_not() {
    assert_eq!(
        ble_error(&bluer::ErrorKind::NotSupported),
        BleError::Unsupported
    );
    assert_ne!(
        ble_error(&bluer::ErrorKind::NotReady),
        BleError::Unsupported
    );
    assert_ne!(ble_error(&bluer::ErrorKind::Failed), BleError::Unsupported);
    assert_ne!(
        ble_error(&bluer::ErrorKind::InProgress),
        BleError::Unsupported
    );
    assert_ne!(
        ble_error(&bluer::ErrorKind::NotAvailable),
        BleError::Unsupported
    );
}

#[test]
fn permission_denied_mappings() {
    assert_eq!(
        ble_error(&bluer::ErrorKind::NotAuthorized),
        BleError::PermissionDenied
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::NotPermitted),
        BleError::PermissionDenied
    );
}

#[test]
fn adapter_unavailable_mappings() {
    assert_eq!(
        ble_error(&bluer::ErrorKind::NotReady),
        BleError::AdapterUnavailable
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::NotAvailable),
        BleError::AdapterUnavailable
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::DoesNotExist),
        BleError::AdapterUnavailable
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::NotFound),
        BleError::AdapterUnavailable
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::InvalidName("hci0".to_string())),
        BleError::AdapterUnavailable
    );
}

#[test]
fn unlisted_kind_maps_to_io_other() {
    assert_eq!(
        ble_error(&bluer::ErrorKind::Failed),
        BleError::Io(std::io::ErrorKind::Other)
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::InProgress),
        BleError::Io(std::io::ErrorKind::Other)
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::AlreadyExists),
        BleError::Io(std::io::ErrorKind::Other)
    );
    assert_eq!(
        ble_error(&bluer::ErrorKind::InvalidArguments),
        BleError::Io(std::io::ErrorKind::Other)
    );
}

#[test]
fn tradr_scan_report_none_input_returns_none() {
    assert_eq!(tradr_scan_report("AA:BB:CC:DD:EE:FF", None), None);
}

#[test]
fn tradr_scan_report_other_uuid_returns_none() {
    let other_uuid = match "12345678-1234-5678-1234-567812345678".parse::<bluer::Uuid>() {
        Ok(uuid) => uuid,
        Err(err) => panic!("static uuid parse failed: {err}"),
    };
    let mut map = HashMap::new();
    map.insert(other_uuid, vec![0x01; 10]);
    assert_eq!(tradr_scan_report("AA:BB:CC:DD:EE:FF", Some(&map)), None);
}

#[test]
fn tradr_scan_report_valid_ten_bytes_returns_report() {
    let tradr_uuid = bluer::Uuid::from_bytes(TRADR_SERVICE_UUID);
    let payload = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut map = HashMap::new();
    map.insert(tradr_uuid, payload.to_vec());
    let report = match tradr_scan_report("AA:BB:CC:DD:EE:FF", Some(&map)) {
        Some(report) => report,
        None => panic!("expected scan report for valid payload"),
    };
    assert_eq!(report.handle(), "AA:BB:CC:DD:EE:FF");
    assert_eq!(report.service_data(), &payload);
}

#[test]
fn tradr_scan_report_wrong_payload_lengths_return_none() {
    let tradr_uuid = bluer::Uuid::from_bytes(TRADR_SERVICE_UUID);
    let mut map_9 = HashMap::new();
    map_9.insert(tradr_uuid, vec![0x01; 9]);
    assert_eq!(tradr_scan_report("AA:BB:CC:DD:EE:FF", Some(&map_9)), None);

    let mut map_11 = HashMap::new();
    map_11.insert(tradr_uuid, vec![0x01; 11]);
    assert_eq!(tradr_scan_report("AA:BB:CC:DD:EE:FF", Some(&map_11)), None);
}

#[test]
fn tradr_scan_report_ignores_unrelated_service_data_beside_tradr_uuid() {
    let tradr_uuid = bluer::Uuid::from_bytes(TRADR_SERVICE_UUID);
    let other_uuid = match "12345678-1234-5678-1234-567812345678".parse::<bluer::Uuid>() {
        Ok(uuid) => uuid,
        Err(err) => panic!("static uuid parse failed: {err}"),
    };
    let payload = [0x42u8; 10];
    let mut map = HashMap::new();
    map.insert(other_uuid, vec![0x99; 4]);
    map.insert(tradr_uuid, payload.to_vec());
    let report = match tradr_scan_report("11:22:33:44:55:66", Some(&map)) {
        Some(report) => report,
        None => panic!("expected scan report when other uuid is present"),
    };
    assert_eq!(report.handle(), "11:22:33:44:55:66");
    assert_eq!(report.service_data(), &payload);
}

#[test]
fn service_uuid_matches_advertiser_and_expected_uuid_string() {
    let expected_uuid_str = "00000001-6eed-40d6-85d3-3794eaa7b21c";
    let expected_uuid: bluer::Uuid = match expected_uuid_str.parse() {
        Ok(uuid) => uuid,
        Err(err) => panic!("static uuid parse failed: {err}"),
    };
    let service_uuid = bluer::Uuid::from_bytes(TRADR_SERVICE_UUID);
    assert_eq!(service_uuid.to_string(), expected_uuid_str);
    assert_eq!(service_uuid, expected_uuid);

    let payload = [0x55u8; 10];
    let mut map = HashMap::new();
    map.insert(expected_uuid, payload.to_vec());
    let report = match tradr_scan_report("AA:BB:CC:DD:EE:FF", Some(&map)) {
        Some(report) => report,
        None => panic!("tradr_scan_report must match the expected 128-bit uuid"),
    };
    assert_eq!(report.service_data(), &payload);
}

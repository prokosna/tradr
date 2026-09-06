//! Unit and integration tests for Android BLE glue (docs/03, DCR-086).
//! Carries no cfg so host cargo test validates mappings and queue invariants.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tauri_plugin_tradr::ble_android::{
    BleOutcome, SCAN_QUEUE_CAPACITY, SELF_TEST_HANDLE, SELF_TEST_SERVICE_DATA, ScanPush, ScanQueue,
    advertise_error, outcome_error, scan_error, scan_push_entry,
};
use tradr_discovery::{BleError, SERVICE_DATA_LEN, ScanReport};

#[test]
fn advertise_error_isolates_unsupported_to_code_5() {
    assert_eq!(advertise_error(5), BleError::Unsupported);
    assert_eq!(
        advertise_error(1),
        BleError::Io(std::io::ErrorKind::InvalidData)
    );
    assert_eq!(advertise_error(2), BleError::Io(std::io::ErrorKind::Other));
    assert_eq!(advertise_error(3), BleError::Io(std::io::ErrorKind::Other));
    assert_eq!(advertise_error(4), BleError::Io(std::io::ErrorKind::Other));

    assert_ne!(advertise_error(1), BleError::Unsupported);
    assert_ne!(advertise_error(2), BleError::Unsupported);
    assert_ne!(advertise_error(3), BleError::Unsupported);
    assert_ne!(advertise_error(4), BleError::Unsupported);
}

#[test]
fn scan_error_isolates_unsupported_to_code_4() {
    assert_eq!(scan_error(4), BleError::Unsupported);
    assert_ne!(scan_error(1), BleError::Unsupported);
    assert_ne!(scan_error(2), BleError::Unsupported);
    assert_ne!(scan_error(3), BleError::Unsupported);
    assert_ne!(scan_error(5), BleError::Unsupported);
    assert_ne!(scan_error(6), BleError::Unsupported);
}

#[test]
fn unrecognised_codes_map_to_io_and_never_unsupported() {
    for code in [0, 99, -1] {
        assert_eq!(
            advertise_error(code),
            BleError::Io(std::io::ErrorKind::Other)
        );
        assert_ne!(advertise_error(code), BleError::Unsupported);
        assert_eq!(scan_error(code), BleError::Io(std::io::ErrorKind::Other));
        assert_ne!(scan_error(code), BleError::Unsupported);
    }
}

#[test]
fn ble_outcome_deserializes_all_five_variants() {
    let ok: BleOutcome = serde_json::from_str(r#"{"outcome":"ok"}"#).expect("deserialize ok");
    assert_eq!(ok, BleOutcome::Ok);

    let unsupported: BleOutcome =
        serde_json::from_str(r#"{"outcome":"unsupported"}"#).expect("deserialize unsupported");
    assert_eq!(unsupported, BleOutcome::Unsupported);

    let permission_denied: BleOutcome = serde_json::from_str(r#"{"outcome":"permissionDenied"}"#)
        .expect("deserialize permissionDenied");
    assert_eq!(permission_denied, BleOutcome::PermissionDenied);

    let adapter_unavailable: BleOutcome =
        serde_json::from_str(r#"{"outcome":"adapterUnavailable"}"#)
            .expect("deserialize adapterUnavailable");
    assert_eq!(adapter_unavailable, BleOutcome::AdapterUnavailable);

    let advertise_failed: BleOutcome =
        serde_json::from_str(r#"{"outcome":"advertiseFailed","code":5}"#)
            .expect("deserialize advertiseFailed");
    assert_eq!(advertise_failed, BleOutcome::AdvertiseFailed { code: 5 });
}

#[test]
fn scan_push_deserializes_kotlin_json_wire_shape() {
    let report_json =
        r#"{"push":"report","handle":"00:11:22:33:44:55","serviceData":"AQIDBAUGBwgJCg=="}"#;
    let push: ScanPush = serde_json::from_str(report_json).expect("deserialize scan report push");
    let entry = scan_push_entry(&push).expect("expected Some for valid report");
    let report = entry.expect("expected Ok for valid report");
    assert_eq!(report.handle(), "00:11:22:33:44:55");
    assert_eq!(report.service_data(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    let failed_json = r#"{"push":"failed","code":4}"#;
    let failed_push: ScanPush =
        serde_json::from_str(failed_json).expect("deserialize scan failed push");
    assert_eq!(failed_push, ScanPush::Failed { code: 4 });
    assert_eq!(
        scan_push_entry(&failed_push),
        Some(Err(BleError::Unsupported))
    );
}

#[test]
fn outcome_error_maps_outcomes_correctly() {
    assert_eq!(outcome_error(&BleOutcome::Ok), None);
    assert_eq!(
        outcome_error(&BleOutcome::Unsupported),
        Some(BleError::Unsupported)
    );
    assert_eq!(
        outcome_error(&BleOutcome::PermissionDenied),
        Some(BleError::PermissionDenied)
    );
    assert_eq!(
        outcome_error(&BleOutcome::AdapterUnavailable),
        Some(BleError::AdapterUnavailable)
    );
    assert_eq!(
        outcome_error(&BleOutcome::AdvertiseFailed { code: 5 }),
        Some(BleError::Unsupported)
    );
    assert_eq!(
        outcome_error(&BleOutcome::AdvertiseFailed { code: 1 }),
        Some(BleError::Io(std::io::ErrorKind::InvalidData))
    );
    assert_eq!(
        outcome_error(&BleOutcome::AdvertiseFailed { code: 4 }),
        Some(BleError::Io(std::io::ErrorKind::Other))
    );
}

#[test]
fn scan_push_entry_filters_and_converts_reports() {
    let valid_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let valid_push = ScanPush::Report {
        handle: "00:11:22:33:44:55".to_string(),
        service_data: STANDARD.encode(valid_payload),
    };
    let entry = scan_push_entry(&valid_push).expect("expected Some for valid report");
    let report = entry.expect("expected Ok for valid report");
    assert_eq!(report.handle(), "00:11:22:33:44:55");
    assert_eq!(report.service_data(), &valid_payload);

    let short_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    let short_push = ScanPush::Report {
        handle: "00:11:22:33:44:55".to_string(),
        service_data: STANDARD.encode(short_payload),
    };
    assert!(scan_push_entry(&short_push).is_none());

    let long_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let long_push = ScanPush::Report {
        handle: "00:11:22:33:44:55".to_string(),
        service_data: STANDARD.encode(long_payload),
    };
    assert!(scan_push_entry(&long_push).is_none());

    let invalid_b64_push = ScanPush::Report {
        handle: "00:11:22:33:44:55".to_string(),
        service_data: "not-base64!@#$%^".to_string(),
    };
    assert!(scan_push_entry(&invalid_b64_push).is_none());

    let invalid_handle_push = ScanPush::Report {
        handle: "bad\nhandle".to_string(),
        service_data: STANDARD.encode(valid_payload),
    };
    assert!(scan_push_entry(&invalid_handle_push).is_none());

    let empty_handle_push = ScanPush::Report {
        handle: "".to_string(),
        service_data: STANDARD.encode(valid_payload),
    };
    assert!(scan_push_entry(&empty_handle_push).is_none());

    let failed_unsupported = ScanPush::Failed { code: 4 };
    assert_eq!(
        scan_push_entry(&failed_unsupported),
        Some(Err(BleError::Unsupported))
    );

    let failed_io = ScanPush::Failed { code: 1 };
    assert_eq!(
        scan_push_entry(&failed_io),
        Some(Err(BleError::Io(std::io::ErrorKind::Other)))
    );
}

#[test]
fn standard_base64_alphabet_is_pinned() {
    // Standard base64 renders indices 62 and 63 as '+' and '/', whereas URL-safe renders '-' and '_'.
    let bytes: [u8; 10] = [251, 240, 0, 0, 0, 0, 0, 0, 0, 0];
    let encoded = STANDARD.encode(bytes);
    assert!(
        encoded.contains('+'),
        "premise: standard base64 must contain '+'"
    );
    assert!(
        encoded.contains('/'),
        "premise: standard base64 must contain '/'"
    );

    let push = ScanPush::Report {
        handle: "00:11:22:33:44:55".to_string(),
        service_data: encoded,
    };
    let entry = scan_push_entry(&push).expect("must parse standard base64");
    let report = entry.expect("must be valid ScanReport");
    assert_eq!(report.service_data(), &bytes);
}

#[tokio::test]
async fn scan_queue_preserves_order_and_drops_oldest_when_full() {
    let queue = ScanQueue::new();

    // Verify in-order FIFO delivery.
    for i in 0..3 {
        let rep = ScanReport::new(&format!("handle-{i}"), &[i as u8; 10]).expect("valid report");
        queue.push(Ok(rep));
    }
    for i in 0..3 {
        let popped = queue.pop().await.expect("pop must succeed");
        assert_eq!(popped.handle(), &format!("handle-{i}"));
    }

    // Capacity eviction drops oldest item when exceeding SCAN_QUEUE_CAPACITY.
    for i in 0..=SCAN_QUEUE_CAPACITY {
        let rep = ScanReport::new(&format!("handle-{i}"), &[0u8; 10]).expect("valid report");
        queue.push(Ok(rep));
    }

    // Oldest item handle-0 must have been dropped; first pop yields handle-1.
    let first = queue.pop().await.expect("pop must succeed");
    assert_eq!(first.handle(), "handle-1");

    for i in 2..=SCAN_QUEUE_CAPACITY {
        let next = queue.pop().await.expect("pop must succeed");
        assert_eq!(next.handle(), &format!("handle-{i}"));
    }
}

#[tokio::test]
async fn scan_queue_awaiting_pop_completes_when_push_arrives() {
    let queue = Arc::new(ScanQueue::new());
    let queue_clone = Arc::clone(&queue);

    let pop_task = tokio::spawn(async move { queue_clone.pop().await });

    // Yield so pop_task awaits the queue before push arrives (rule E3: no sleep).
    tokio::task::yield_now().await;

    let rep = ScanReport::new("delayed-handle", &[7u8; 10]).expect("valid report");
    queue.push(Ok(rep.clone()));

    let result = tokio::time::timeout(Duration::from_secs(5), pop_task)
        .await
        .expect("pop awaiting empty queue must not time out")
        .expect("spawned task must not panic")
        .expect("popped result must be Ok");

    assert_eq!(result, rep);
}

#[test]
fn selftest_push_literal_deserializes_and_yields_expected_report() {
    let raw = r#"{"push":"report","handle":"self-test","serviceData":"AVNFTEZURVNUAA=="}"#;
    let push: ScanPush = serde_json::from_str(raw).expect("must parse ScanPush");
    let entry = scan_push_entry(&push).expect("expected Some for self-test report");
    let report = entry.expect("expected Ok for self-test report");
    assert_eq!(report.handle(), SELF_TEST_HANDLE);
    assert_eq!(report.service_data(), &SELF_TEST_SERVICE_DATA);
}

#[test]
fn selftest_service_data_matches_expected_ten_bytes() {
    assert_eq!(SELF_TEST_SERVICE_DATA.len(), SERVICE_DATA_LEN);
    let expected = [0x01, b'S', b'E', b'L', b'F', b'T', b'E', b'S', b'T', 0x00];
    assert_eq!(SELF_TEST_SERVICE_DATA, expected);
}

use std::time::Duration;

use tradr_core::{Candidate, TransportId};
use tradr_transport::selection::{BLE_GATT_MAX_TRANSFER_BYTES, class_weight, prefilter, score};

#[test]
fn named_transports_match_class_weights() {
    assert_eq!(class_weight(TransportId::new("direct-quic")), 1000);
    assert_eq!(class_weight(TransportId::new("wifi-direct")), 800);
    assert_eq!(class_weight(TransportId::new("holepunch-quic")), 700);
    assert_eq!(class_weight(TransportId::new("relay")), 300);
    assert_eq!(class_weight(TransportId::new("ble-gatt")), 50);
}

#[test]
fn unrecognised_transport_weighs_zero() {
    assert_eq!(class_weight(TransportId::new("unknown-carrier")), 0);
}

#[test]
fn score_subtracts_one_point_per_ten_milliseconds() {
    assert_eq!(
        score(TransportId::new("ble-gatt"), Duration::from_millis(200)),
        30
    );
}

#[test]
fn score_with_duration_max_saturates_below_every_finite_case() {
    let max_score = score(TransportId::new("direct-quic"), Duration::MAX);
    let finite_low = score(TransportId::new("ble-gatt"), Duration::from_secs(3600));
    assert!(max_score < finite_low);
}

#[test]
fn prefilter_boundary_at_ble_gatt_max_transfer_bytes() {
    assert_eq!(BLE_GATT_MAX_TRANSFER_BYTES, 524_288);
    let candidate =
        Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid candidate");
    let candidates = [candidate.clone()];

    let at_limit = prefilter(&candidates, BLE_GATT_MAX_TRANSFER_BYTES);
    assert_eq!(at_limit, vec![candidate]);

    let past_limit = prefilter(&candidates, BLE_GATT_MAX_TRANSFER_BYTES + 1);
    assert!(past_limit.is_empty());
}

#[test]
fn prefilter_keeps_direct_quic_when_ble_gatt_dropped() {
    let direct =
        Candidate::new(TransportId::new("direct-quic"), "192.168.1.42:51820").expect("valid");
    let ble = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");
    let candidates = [direct.clone(), ble];

    let kept = prefilter(&candidates, BLE_GATT_MAX_TRANSFER_BYTES + 1);
    assert_eq!(kept, vec![direct]);
}

#[test]
fn prefilter_preserves_order_of_survivors() {
    let c1 = Candidate::new(TransportId::new("direct-quic"), "192.168.1.42:51820").expect("valid");
    let c2 = Candidate::new(TransportId::new("wifi-direct"), "192.168.49.1:51820").expect("valid");
    let c3 = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");
    let c4 = Candidate::new(TransportId::new("relay"), "relay://brokr.example/x").expect("valid");
    let candidates = [c1.clone(), c2.clone(), c3, c4.clone()];

    let kept = prefilter(&candidates, BLE_GATT_MAX_TRANSFER_BYTES + 1);
    assert_eq!(kept, vec![c1, c2, c4]);
}

use std::time::Duration;

use tradr_core::TransportId;
use tradr_transport::selection::{class_weight, score};

#[test]
fn class_weights_order_the_known_transports() {
    assert_eq!(class_weight(TransportId::new("direct-quic")), 1000);
    assert_eq!(class_weight(TransportId::new("wifi-direct")), 800);
    assert_eq!(class_weight(TransportId::new("holepunch-quic")), 700);
    assert_eq!(class_weight(TransportId::new("relay")), 300);
}

#[test]
fn an_unrecognised_transport_weighs_nothing() {
    assert_eq!(class_weight(TransportId::new("ble-gatt")), 0);
    assert_eq!(class_weight(TransportId::new("carrier-pigeon")), 0);
}

#[test]
fn score_subtracts_one_point_per_ten_milliseconds() {
    assert_eq!(
        score(TransportId::new("direct-quic"), Duration::from_millis(200)),
        980
    );
    assert_eq!(
        score(TransportId::new("relay"), Duration::from_millis(5)),
        300
    );
}

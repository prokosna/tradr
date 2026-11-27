//! Pure path-selection policy: transport scoring (docs/03).

use std::time::Duration;

use tradr_core::TransportId;

/// Returns the base comparison weight for a transport class.
pub fn class_weight(transport: TransportId) -> i32 {
    match transport.as_str() {
        "direct-quic" => 1000,
        "wifi-direct" => 800,
        "holepunch-quic" => 700,
        "relay" => 300,
        _ => 0,
    }
}

/// Computes path adoption score from class weight penalised by round-trip latency.
pub fn score(transport: TransportId, rtt: Duration) -> i32 {
    let penalty = (rtt.as_millis() / 10) as i128;
    let weight = class_weight(transport) as i128;
    let raw = weight - penalty;
    if raw < i32::MIN as i128 {
        i32::MIN
    } else if raw > i32::MAX as i128 {
        i32::MAX
    } else {
        raw as i32
    }
}

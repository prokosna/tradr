use std::io::{self, ErrorKind};

use tradr_core::{TransportError, tradr_uuid};
use tradr_transport::ble::{
    BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID, BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID,
    BLE_GATT_SERVICE_UUID, delivery, operations,
};

#[test]
fn ble_gatt_uuids_match_their_slots_and_are_pairwise_distinct() {
    assert_eq!(BLE_GATT_SERVICE_UUID, tradr_uuid(0x0002));
    assert_eq!(BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID, tradr_uuid(0x0003));
    assert_eq!(BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID, tradr_uuid(0x0004));

    assert_ne!(BLE_GATT_SERVICE_UUID, BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID);
    assert_ne!(BLE_GATT_SERVICE_UUID, BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID);
    assert_ne!(
        BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID,
        BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID
    );
}

#[test]
fn operations_shorter_than_mtu_yields_one_piece_equal_to_input() {
    let input = b"short payload";
    let pieces = operations(input, 20).expect("operations succeeds for valid mtu");
    assert_eq!(pieces, vec![input.as_slice()]);
}

#[test]
fn operations_exactly_mtu_long_yields_one_piece() {
    let input = [42u8; 20];
    let pieces = operations(&input, 20).expect("operations succeeds for valid mtu");
    assert_eq!(pieces, vec![input.as_slice()]);
}

#[test]
fn operations_one_byte_longer_than_mtu_yields_two_pieces() {
    let input = [42u8; 21];
    let pieces = operations(&input, 20).expect("operations succeeds for valid mtu");
    assert_eq!(pieces.len(), 2);
    assert_eq!(pieces[0], &input[..20]);
    assert_eq!(pieces[1], &input[20..]);
    assert_eq!(pieces[1].len(), 1);
}

#[test]
fn operations_530_bytes_at_mtu_20_yields_27_pieces_and_round_trips() {
    let input: Vec<u8> = (0..530).map(|i| (i % 256) as u8).collect();
    let pieces = operations(&input, 20).expect("operations succeeds for valid mtu");
    assert_eq!(pieces.len(), 27);
    assert_eq!(pieces.last().copied(), Some(&input[520..]));
    assert_eq!(pieces.last().map(|p| p.len()), Some(10));

    let concatenated: Vec<u8> = pieces.into_iter().flatten().copied().collect();
    assert_eq!(concatenated, input);
}

#[test]
fn operations_on_empty_input_yields_no_pieces() {
    let pieces = operations(&[], 20).expect("operations succeeds for empty input");
    assert!(pieces.is_empty());
}

#[test]
fn operations_at_mtu_zero_returns_invalid_input_error() {
    let result = operations(b"data", 0);
    assert_eq!(result, Err(TransportError::Io(ErrorKind::InvalidInput)));
}

#[test]
fn delivery_ok_empty_vec_yields_ok_none() {
    let outcome = delivery(Ok(Vec::new())).expect("delivery succeeds for empty input");
    assert_eq!(outcome, None);
}

#[test]
fn delivery_ok_non_empty_yields_ok_some() {
    let outcome = delivery(Ok(b"abc".to_vec())).expect("delivery succeeds for non-empty input");
    assert_eq!(outcome, Some(b"abc".to_vec()));
}

#[test]
fn delivery_err_preserves_underlying_io_error_kind() {
    let outcome = delivery(Err(io::Error::from(ErrorKind::BrokenPipe)));
    assert_eq!(outcome, Err(TransportError::Io(ErrorKind::BrokenPipe)));
}

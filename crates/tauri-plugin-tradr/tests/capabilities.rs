use tauri_plugin_tradr::capabilities::LocalCapabilities;
use tradr_core::Capabilities;

#[test]
fn set_built_from_direct_quic_declares_bit_0_and_not_bit_2() {
    let caps = LocalCapabilities::new(Capabilities::DIRECT_QUIC);
    assert_eq!(caps.get().bits(), 1);
    assert!(!caps.get().contains(Capabilities::BLE_GATT));
}

#[test]
fn declare_ble_gatt_sets_bit_2_and_leaves_bit_0_as_it_was() {
    let caps = LocalCapabilities::new(Capabilities::DIRECT_QUIC);
    caps.declare(Capabilities::BLE_GATT);
    assert_eq!(caps.get().bits(), 0b101);
}

#[test]
fn withdraw_ble_gatt_clears_bit_2_and_leaves_bit_0_as_it_was() {
    let caps = LocalCapabilities::new(Capabilities::DIRECT_QUIC);
    caps.declare(Capabilities::BLE_GATT);
    assert_eq!(caps.get().bits(), 0b101);

    caps.withdraw(Capabilities::BLE_GATT);
    assert_eq!(caps.get().bits(), 0b001);

    caps.withdraw(Capabilities::BLE_GATT);
    assert_eq!(caps.get().bits(), 0b001);
}

#[test]
fn declare_and_withdraw_touch_no_bit_they_were_not_given() {
    let caps = LocalCapabilities::new(Capabilities::from_bits(0b1010));
    assert_eq!(caps.get().bits(), 0b1010);

    caps.declare(Capabilities::BLE_GATT);
    assert_eq!(caps.get().bits(), 0b1110);

    caps.withdraw(Capabilities::BLE_GATT);
    assert_eq!(caps.get().bits(), 0b1010);
}

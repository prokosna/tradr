use tradr_app::capabilities::LocalCapabilities;
use tradr_core::Capabilities;

#[test]
fn set_built_from_direct_quic_declares_bit_0_and_not_bit_4() {
    let caps = LocalCapabilities::new(Capabilities::DIRECT_QUIC);
    assert_eq!(caps.get().bits(), 1);
    assert!(!caps.get().contains(Capabilities::ACCEPTS_BROWSING));
}

#[test]
fn declare_browsing_sets_bit_4_and_leaves_bit_0_as_it_was() {
    let caps = LocalCapabilities::new(Capabilities::DIRECT_QUIC);
    caps.declare(Capabilities::ACCEPTS_BROWSING);
    assert_eq!(caps.get().bits(), 0b10001);
}

#[test]
fn withdraw_browsing_clears_bit_4_and_leaves_bit_0_as_it_was() {
    let caps = LocalCapabilities::new(Capabilities::DIRECT_QUIC);
    caps.declare(Capabilities::ACCEPTS_BROWSING);
    assert_eq!(caps.get().bits(), 0b10001);

    caps.withdraw(Capabilities::ACCEPTS_BROWSING);
    assert_eq!(caps.get().bits(), 0b001);

    caps.withdraw(Capabilities::ACCEPTS_BROWSING);
    assert_eq!(caps.get().bits(), 0b001);
}

#[test]
fn declare_and_withdraw_touch_no_bit_they_were_not_given() {
    let caps = LocalCapabilities::new(Capabilities::from_bits(0b1010));
    assert_eq!(caps.get().bits(), 0b1010);

    caps.declare(Capabilities::ACCEPTS_BROWSING);
    assert_eq!(caps.get().bits(), 0b11010);

    caps.withdraw(Capabilities::ACCEPTS_BROWSING);
    assert_eq!(caps.get().bits(), 0b1010);
}

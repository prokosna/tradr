//! Tests for mDNS TXT record construction and local platform detection (WI-M8-014),
//! and QUIC bind address resolution and fallback binding (WI-M8-018).
//! Verifies the network helpers in `tradr_app::network`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use tradr_app::network::{
    bind_with_fallback, device_txt_record, local_platform, quic_bind_addresses,
};
use tradr_core::Capabilities;
use tradr_discovery::{AGREEMENT_KEY_TAG_LEN, Platform, STATIC_PEER_DEFAULT_PORT};
use tradr_transport::quic::QuicTransport;

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

fn free_ports() -> (SocketAddr, SocketAddr) {
    let s1 = std::net::UdpSocket::bind("0.0.0.0:0").expect("ephemeral udp bind");
    let s2 = std::net::UdpSocket::bind("0.0.0.0:0").expect("ephemeral udp bind");
    (
        s1.local_addr().expect("local addr"),
        s2.local_addr().expect("local addr"),
    )
}

#[test]
fn quic_bind_addresses_answers_the_default_port_then_an_ephemeral_fallback() {
    let (default_addr, fallback_addr) =
        quic_bind_addresses().expect("quic bind addresses must parse");

    assert_eq!(default_addr.port(), STATIC_PEER_DEFAULT_PORT);
    assert_eq!(fallback_addr.port(), 0);
    assert_eq!(
        default_addr.ip(),
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    );
    assert_eq!(
        fallback_addr.ip(),
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    );
}

#[tokio::test]
async fn bind_with_fallback_binds_the_default_address_when_it_is_free() {
    let (default_addr, fallback_addr) = free_ports();
    assert_ne!(default_addr.port(), fallback_addr.port());

    let key_store = Arc::new(common::device_store(1));
    let transport = bind_with_fallback(key_store, default_addr, fallback_addr)
        .expect("bind must succeed on free default address");

    assert_eq!(
        transport.local_addr().expect("local addr").port(),
        default_addr.port()
    );
}

#[tokio::test]
async fn bind_with_fallback_binds_the_fallback_address_when_the_default_is_taken() {
    let primary_store = Arc::new(common::device_store(2));
    let (default_addr, fallback_addr) = free_ports();
    assert_ne!(default_addr.port(), fallback_addr.port());

    let primary_transport =
        QuicTransport::new(primary_store, default_addr).expect("primary quic transport must bind");
    let taken_addr = primary_transport
        .local_addr()
        .expect("bound primary transport reports address");

    let fallback_store = Arc::new(common::device_store(3));
    let transport = bind_with_fallback(fallback_store, taken_addr, fallback_addr)
        .expect("bind must succeed on fallback address");

    assert_eq!(
        transport.local_addr().expect("local addr").port(),
        fallback_addr.port()
    );
}

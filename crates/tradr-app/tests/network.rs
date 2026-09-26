//! Tests for mDNS TXT record construction and local platform detection (WI-M8-014),
//! and QUIC bind address resolution and fallback binding (WI-M8-018).
//! Verifies the network helpers in `tradr_app::network`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use tradr_app::network::{
    bind_with_fallback, device_txt_record, display_name_from_device_name,
    display_name_from_hostname, local_display_name, local_platform, quic_bind_addresses,
    quic_dial_bind_address,
};
use tradr_core::{Capabilities, DISPLAY_NAME_MAX_LEN, DisplayName};
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
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC, None)
        .expect("record construction must succeed");

    let expected_hash = blake3::hash(identity.agreement_pub().as_bytes());
    let mut expected_tag = [0u8; AGREEMENT_KEY_TAG_LEN];
    expected_tag.copy_from_slice(&expected_hash.as_bytes()[..AGREEMENT_KEY_TAG_LEN]);

    assert_eq!(record.agreement_key_tag(), expected_tag);
}

#[test]
fn device_txt_record_publishes_device_id_of_identity() {
    let identity = common::identity(7);
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC, None)
        .expect("record construction must succeed");

    assert_eq!(record.device_id(), identity.device_id());
}

#[test]
fn device_txt_record_publishes_exact_capabilities_with_multiple_bits() {
    let identity = common::identity(13);
    let caps =
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | Capabilities::BLE_GATT.bits());
    assert!(caps.bits().count_ones() > 1);

    let record =
        device_txt_record(&identity, caps, None).expect("record construction must succeed");

    assert_eq!(record.capabilities(), caps);
}

#[test]
fn device_txt_record_publishes_local_platform_and_no_display_name() {
    let identity = common::identity(99);
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC, None)
        .expect("record construction must succeed");

    assert_eq!(record.platform().as_str(), local_platform());
    assert!(record.display_name().is_none());
    assert!(
        !record.to_pairs().iter().any(|(k, _)| k == "n"),
        "to_pairs() must carry no 'n' key when display name is none"
    );
}

#[test]
fn display_name_from_hostname_without_dot_keeps_entire_string() {
    let name = display_name_from_hostname("desk");
    assert_eq!(name.as_ref().map(DisplayName::as_str), Some("desk"));
}

#[test]
fn display_name_from_hostname_takes_first_label_from_multilabel_name() {
    let from_internal = display_name_from_hostname("desk.example.internal");
    assert_eq!(
        from_internal.as_ref().map(DisplayName::as_str),
        Some("desk")
    );

    let from_local = display_name_from_hostname("desk.local");
    assert_eq!(from_local.as_ref().map(DisplayName::as_str), Some("desk"));
}

#[test]
fn display_name_from_hostname_truncates_ascii_label_to_max_len_bytes() {
    let long_label = "a".repeat(DISPLAY_NAME_MAX_LEN + 10);
    let hostname = format!("{long_label}.example.com");
    let name = display_name_from_hostname(&hostname);

    let expected = "a".repeat(DISPLAY_NAME_MAX_LEN);
    assert_eq!(
        name.as_ref().map(DisplayName::as_str),
        Some(expected.as_str())
    );
    assert_eq!(
        name.as_ref().map(|n| n.as_str().len()),
        Some(DISPLAY_NAME_MAX_LEN)
    );
}

#[test]
fn display_name_from_hostname_truncates_multibyte_label_on_character_boundary() {
    let input_label = "あ".repeat(12);
    let hostname = format!("{input_label}.local");
    let name = display_name_from_hostname(&hostname);

    assert!(
        name.is_some(),
        "display name must be accepted by DisplayName"
    );
    let display_str = name
        .as_ref()
        .map(DisplayName::as_str)
        .expect("display name present");
    assert!(
        display_str.len() <= DISPLAY_NAME_MAX_LEN,
        "truncated length must be at most {DISPLAY_NAME_MAX_LEN} bytes"
    );
    assert!(
        input_label.starts_with(display_str),
        "truncated string must be a prefix of the input label"
    );
}

#[test]
fn display_name_from_hostname_refuses_empty_string() {
    assert!(display_name_from_hostname("").is_none());
}

#[test]
fn display_name_from_hostname_refuses_empty_first_label() {
    assert!(display_name_from_hostname(".").is_none());
    assert!(display_name_from_hostname(".desk").is_none());
}

#[test]
fn display_name_from_hostname_refuses_control_character_in_first_label() {
    assert!(display_name_from_hostname("a\u{7}b.local").is_none());
}

#[test]
fn display_name_from_hostname_refuses_localhost() {
    assert!(display_name_from_hostname("localhost").is_none());
    assert!(display_name_from_hostname("LocalHost").is_none());
    assert!(display_name_from_hostname("localhost.localdomain").is_none());
}

#[test]
fn display_name_from_device_name_preserves_dots_and_accepts_valid_names() {
    let galaxy = display_name_from_device_name("Galaxy S24 Ultra");
    assert_eq!(
        galaxy.as_ref().map(DisplayName::as_str),
        Some("Galaxy S24 Ultra")
    );

    let pixel = display_name_from_device_name("Minori's Pixel 8.1");
    assert_eq!(
        pixel.as_ref().map(DisplayName::as_str),
        Some("Minori's Pixel 8.1")
    );
}

#[test]
fn display_name_from_device_name_truncates_on_character_boundary() {
    let long_ascii = "a".repeat(40);
    let name_ascii = display_name_from_device_name(&long_ascii);
    let expected_ascii = "a".repeat(32);
    assert_eq!(
        name_ascii.as_ref().map(DisplayName::as_str),
        Some(expected_ascii.as_str())
    );
    assert_eq!(name_ascii.as_ref().map(|n| n.as_str().len()), Some(32));

    let long_multibyte = "あ".repeat(11);
    let name_multibyte = display_name_from_device_name(&long_multibyte);
    let expected_multibyte = "あ".repeat(10);
    assert_eq!(
        name_multibyte.as_ref().map(DisplayName::as_str),
        Some(expected_multibyte.as_str())
    );
    assert_eq!(name_multibyte.as_ref().map(|n| n.as_str().len()), Some(30));
}

#[test]
fn display_name_from_device_name_refuses_empty_and_localhost() {
    assert!(display_name_from_device_name("").is_none());
    assert!(display_name_from_device_name("localhost").is_none());
    assert!(display_name_from_device_name("LocalHost").is_none());
}

#[test]
fn local_display_name_matches_display_name_from_os_hostname() {
    let os_hostname = hostname::get().expect("operating system hostname available");
    let utf8_hostname = os_hostname.to_str().expect("hostname is valid utf-8");
    let expected = display_name_from_hostname(utf8_hostname);

    assert!(
        expected.is_some(),
        "os hostname must produce a valid display name"
    );
    assert_eq!(local_display_name(), expected);
}

#[test]
fn device_txt_record_carries_provided_display_name() {
    let identity = common::identity(42);
    let name = DisplayName::new("desk-machine").expect("valid display name");
    let record = device_txt_record(&identity, Capabilities::DIRECT_QUIC, Some(name.clone()))
        .expect("record construction must succeed");

    assert_eq!(record.display_name(), Some(&name));
    let pairs = record.to_pairs();
    let n_pair = pairs.iter().find(|(k, _)| k == "n");
    assert_eq!(
        n_pair.map(|(_, v)| v.as_str()),
        Some("desk-machine"),
        "to_pairs() must include the 'n' key with the display name value"
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

#[test]
fn quic_dial_bind_address_answers_the_ephemeral_port_on_unspecified_ipv6() {
    let addr = quic_dial_bind_address().expect("quic dial bind address must parse");

    assert_eq!(addr.port(), 0);
    assert_eq!(
        addr.ip(),
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

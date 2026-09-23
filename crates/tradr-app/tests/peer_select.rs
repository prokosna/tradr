//! Tests for peer selector matching by key and display name (WI-M8-039).

use std::time::Duration;

use mdns_sd::{ResolvedService, ServiceEvent, ServiceInfo};
use tradr_app::peers::select_peer_key;
use tradr_app::send_session::PeerDiscovery;
use tradr_core::{
    Capabilities, DeviceId, DiscoveryEvent, DisplayName, ObservationId, ObservationKey, PeerList,
    PeerObservation, SourceId,
};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, MdnsSource, Platform, SERVICE_TYPE, StaticPeerRegistry, TxtRecord,
};
use tradr_transport::selection::TransferSize;
use tradr_transport::set::TransportSet;

fn test_device_id(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; 16]).expect("16 bytes is a valid DeviceId")
}

fn resolved_service(
    instance_name: &str,
    device_id: DeviceId,
    display_name: &str,
    ip: &str,
    port: u16,
) -> ResolvedService {
    let record = TxtRecord::new(
        device_id,
        [0x55; AGREEMENT_KEY_TAG_LEN],
        Some(DisplayName::new(display_name).expect("valid display name")),
        Capabilities::DIRECT_QUIC,
        Platform::new("linux").expect("valid platform"),
    );
    ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        "test-host.local.",
        ip,
        port,
        &*record.to_pairs(),
    )
    .expect("valid service info")
    .as_resolved_service()
}

#[test]
fn key_selects_its_peer() {
    let device_id = test_device_id(0x10);
    let source = SourceId::new("mdns");
    let obs = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.a").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id)
    .with_display_name(DisplayName::new("Alice Phone").unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    let key = device_id.to_string();
    assert_eq!(select_peer_key(&key, &list), Ok(Some(key)));
}

#[test]
fn unique_name_selects_that_peers_key() {
    let device_id = test_device_id(0x10);
    let source = SourceId::new("mdns");
    let obs = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.a").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id)
    .with_display_name(DisplayName::new("Alice Phone").unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    assert_eq!(
        select_peer_key("Alice Phone", &list),
        Ok(Some(device_id.to_string()))
    );
}

#[test]
fn name_differing_only_in_case_selects_nothing() {
    let device_id = test_device_id(0x10);
    let source = SourceId::new("mdns");
    let obs = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.a").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id)
    .with_display_name(DisplayName::new("Alice Phone").unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    assert_eq!(select_peer_key("alice phone", &list), Ok(None));
    assert_eq!(select_peer_key("ALICE PHONE", &list), Ok(None));
}

#[test]
fn prefix_of_name_selects_nothing() {
    let device_id = test_device_id(0x10);
    let source = SourceId::new("mdns");
    let obs = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.a").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id)
    .with_display_name(DisplayName::new("Alice Phone").unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    assert_eq!(select_peer_key("Alice", &list), Ok(None));
    assert_eq!(select_peer_key("Alice Pho", &list), Ok(None));
}

#[test]
fn two_peers_of_one_name_returns_exact_error_text_with_keys() {
    let device_id1 = test_device_id(0x10);
    let device_id2 = test_device_id(0x20);
    let source = SourceId::new("mdns");

    let obs1 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.1").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id1)
    .with_display_name(DisplayName::new("Shared Name").unwrap());

    let obs2 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.2").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id2)
    .with_display_name(DisplayName::new("Shared Name").unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs1)).unwrap();
    list.apply(source, DiscoveryEvent::Observed(obs2)).unwrap();

    let expected_keys = format!("{device_id1}, {device_id2}");
    let expected_err = format!("2 peers are named Shared Name; name one by key: {expected_keys}");
    assert_eq!(select_peer_key("Shared Name", &list), Err(expected_err));
}

#[test]
fn when_one_peers_key_equals_another_peers_name_the_selector_picks_the_keys_peer() {
    let device_id1 = test_device_id(0x10);
    let key1 = device_id1.to_string();
    let device_id2 = test_device_id(0x20);
    let source = SourceId::new("mdns");

    let obs1 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.1").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id1)
    .with_display_name(DisplayName::new("Peer One").unwrap());

    let obs2 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.2").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id2)
    .with_display_name(DisplayName::new(&key1).unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs1)).unwrap();
    list.apply(source, DiscoveryEvent::Observed(obs2)).unwrap();

    assert_eq!(select_peer_key(&key1, &list), Ok(Some(key1)));
}

#[test]
fn empty_list_selects_nothing() {
    let list = PeerList::new();
    assert_eq!(select_peer_key("Alice Phone", &list), Ok(None));
    assert_eq!(
        select_peer_key("10101010101010101010101010101010", &list),
        Ok(None)
    );
}

#[tokio::test]
async fn await_peer_given_ambiguous_name_returns_error_before_window_elapses() {
    let (tx, rx) = flume::unbounded();
    let mdns = MdnsSource::new(rx);

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let static_path = temp_dir.path().join("static-peers.json");
    let (registry, static_source) =
        StaticPeerRegistry::load(&static_path).expect("load empty registry");

    let self_id = test_device_id(0x01);
    let mut discovery = PeerDiscovery::from_sources(mdns, static_source, registry, self_id);

    let id1 = test_device_id(0x10);
    let id2 = test_device_id(0x20);

    let s1 = resolved_service("dev1", id1, "Ambiguous Name", "192.168.1.10", 21820);
    let s2 = resolved_service("dev2", id2, "Ambiguous Name", "192.168.1.20", 21820);

    tx.send(ServiceEvent::ServiceResolved(Box::new(s1)))
        .expect("send s1");
    tx.send(ServiceEvent::ServiceResolved(Box::new(s2)))
        .expect("send s2");

    let transports = TransportSet::new(vec![]);
    let start = std::time::Instant::now();
    let result = discovery
        .await_peer(
            "Ambiguous Name",
            &transports,
            TransferSize::Bytes(0),
            Duration::from_secs(2),
        )
        .await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "must return well before 2-second deadline, took {elapsed:?}"
    );

    let err = result.expect_err("ambiguous peer name must fail immediately");
    let expected_keys = format!("{id1}, {id2}");
    let expected_err =
        format!("2 peers are named Ambiguous Name; name one by key: {expected_keys}");
    assert_eq!(err, expected_err);
}

//! Tests for peer discovery drain filtering out this device's own DeviceId (WI-M8-033).

use mdns_sd::{ResolvedService, ServiceEvent, ServiceInfo};
use tradr_app::peers::drain_peer_sources;
use tradr_core::{Capabilities, DeviceId, DisplayName, PeerList};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, MdnsSource, Platform, SERVICE_TYPE, StaticPeerRegistry, TxtRecord,
};
use tradr_identity::OsRng;

fn test_device_id(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; 16]).expect("16 bytes is a valid DeviceId")
}

fn resolved_service(
    instance_name: &str,
    device_id: DeviceId,
    ip: &str,
    port: u16,
) -> ResolvedService {
    let record = TxtRecord::new(
        device_id,
        [0x55; AGREEMENT_KEY_TAG_LEN],
        Some(DisplayName::new("Test Peer").expect("valid display name")),
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

#[tokio::test]
async fn drain_discards_observation_carrying_own_device_id() {
    let self_id = test_device_id(0x11);
    let (tx, rx) = flume::unbounded();
    let mut mdns = MdnsSource::new(rx);

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let static_path = temp_dir.path().join("static-peers.json");
    let (_registry, mut static_source) =
        StaticPeerRegistry::load(&static_path).expect("load empty registry");

    let resolved = resolved_service("own-device", self_id, "192.168.1.10", 21820);
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved)))
        .expect("send resolved event");

    let mut list = PeerList::new();
    drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id)
        .await
        .expect("drain must succeed");

    assert!(list.peers().is_empty(), "self must not enter peer list");
}

#[tokio::test]
async fn drain_retains_observation_carrying_different_device_id() {
    let self_id = test_device_id(0x11);
    let other_id = test_device_id(0x22);
    let (tx, rx) = flume::unbounded();
    let mut mdns = MdnsSource::new(rx);

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let static_path = temp_dir.path().join("static-peers.json");
    let (_registry, mut static_source) =
        StaticPeerRegistry::load(&static_path).expect("load empty registry");

    let resolved = resolved_service("other-device", other_id, "192.168.1.20", 21820);
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved)))
        .expect("send resolved event");

    let mut list = PeerList::new();
    drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id)
        .await
        .expect("drain must succeed");

    assert_eq!(list.peers().len(), 1);
    assert_eq!(list.peers()[0].device_id(), Some(other_id));
}

#[tokio::test]
async fn drain_retains_observation_with_no_device_id() {
    let self_id = test_device_id(0x11);
    let (_tx, rx) = flume::unbounded();
    let mut mdns = MdnsSource::new(rx);

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let static_path = temp_dir.path().join("static-peers.json");
    let (mut registry, mut static_source) =
        StaticPeerRegistry::load(&static_path).expect("load empty registry");

    let _static_id = registry
        .add(
            Some("unpinned-peer"),
            &["192.168.1.30:21820".to_string()],
            &OsRng,
        )
        .expect("add unpinned static peer");

    let mut list = PeerList::new();
    drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id)
        .await
        .expect("drain must succeed");

    assert_eq!(list.peers().len(), 1);
    assert_eq!(list.peers()[0].device_id(), None);
}

#[tokio::test]
async fn drain_applies_lost_event_for_filtered_observation_without_error() {
    let self_id = test_device_id(0x11);
    let (tx, rx) = flume::unbounded();
    let mut mdns = MdnsSource::new(rx);

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let static_path = temp_dir.path().join("static-peers.json");
    let (_registry, mut static_source) =
        StaticPeerRegistry::load(&static_path).expect("load empty registry");

    let resolved = resolved_service("own-device", self_id, "192.168.1.10", 21820);
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved)))
        .expect("send resolved event");

    let mut list = PeerList::new();
    drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id)
        .await
        .expect("drain must succeed");
    assert!(list.peers().is_empty());

    let fullname = format!("own-device.{SERVICE_TYPE}");
    tx.send(ServiceEvent::ServiceRemoved(
        SERVICE_TYPE.to_string(),
        fullname,
    ))
    .expect("send removed event");

    drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id)
        .await
        .expect("lost event for filtered observation must not error");
    assert!(list.peers().is_empty());
}

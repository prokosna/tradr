use tradr_app::peers::peer_info;
use tradr_core::{
    Candidate, Capabilities, DeviceId, DiscoveryEvent, DisplayName, ObservationId, ObservationKey,
    PeerList, PeerObservation, SourceId, TransportId,
};

#[test]
fn identified_peer_key_is_device_id_hex_without_slash() {
    let device_id = DeviceId::from_bytes(&[0x42; 16]).unwrap();
    let source = SourceId::new("mdns");
    let key = ObservationKey::new("printer._tradr._udp.local.").unwrap();
    let obs_id = ObservationId::new(source, key);
    let obs = PeerObservation::new(obs_id.clone(), Vec::new()).with_device_id(device_id);

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let info = peer_info(&peers[0]);

    assert_eq!(info.device_id, device_id.to_string());
    assert_eq!(info.key, device_id.to_string());
    assert_ne!(info.key, obs_id.to_string());
    assert!(
        !info.key.contains('/'),
        "identified peer key must contain no '/'"
    );
}

#[test]
fn unidentified_peer_key_is_first_observation_id_and_device_id_is_empty() {
    let source = SourceId::new("ble");
    let key = ObservationKey::new("handle:0x0042").unwrap();
    let obs_id = ObservationId::new(source, key);
    let obs = PeerObservation::new(obs_id.clone(), Vec::new());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let info = peer_info(&peers[0]);

    assert_eq!(info.key, obs_id.to_string());
    assert_eq!(info.device_id, "");
}

#[test]
fn capabilities_is_first_observation_advertised_bits() {
    let source = SourceId::new("mdns");
    let key = ObservationKey::new("peer-1").unwrap();
    let obs_id = ObservationId::new(source, key);
    let bits = Capabilities::DIRECT_QUIC.bits() | Capabilities::ACCEPTS_BROWSING.bits();
    let fixture_caps = Capabilities::from_bits(bits);
    assert_ne!(fixture_caps.bits(), 0);
    assert_ne!(fixture_caps, Capabilities::default());

    let obs = PeerObservation::new(obs_id, Vec::new()).with_capabilities(fixture_caps);

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let info = peer_info(&peers[0]);

    assert_eq!(info.capabilities, fixture_caps.bits());
}

#[test]
fn display_name_is_first_observation_with_name_or_none() {
    let device_id = DeviceId::from_bytes(&[0x10; 16]).unwrap();
    let source = SourceId::new("mdns");

    let obs1 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.a").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id);

    let obs2 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.b").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id)
    .with_display_name(DisplayName::new("Alice Phone").unwrap());

    let obs3 = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer.c").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id)
    .with_display_name(DisplayName::new("Bob Laptop").unwrap());

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs1)).unwrap();
    list.apply(source, DiscoveryEvent::Observed(obs2)).unwrap();
    list.apply(source, DiscoveryEvent::Observed(obs3)).unwrap();

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let info = peer_info(&peers[0]);
    assert_eq!(info.display_name, Some("Alice Phone".to_string()));

    let unnamed_source = SourceId::new("ble");
    let obs_unnamed = PeerObservation::new(
        ObservationId::new(unnamed_source, ObservationKey::new("handle:1").unwrap()),
        Vec::new(),
    );
    let mut list_unnamed = PeerList::new();
    list_unnamed
        .apply(unnamed_source, DiscoveryEvent::Observed(obs_unnamed))
        .unwrap();

    let unnamed_peers = list_unnamed.peers();
    assert_eq!(unnamed_peers.len(), 1);
    let unnamed_info = peer_info(&unnamed_peers[0]);
    assert_eq!(unnamed_info.display_name, None);
}

#[test]
fn addresses_lists_every_candidate_address() {
    let source = SourceId::new("mdns");
    let c1 = Candidate::new(TransportId::new("direct-quic"), "192.168.1.50:4433").unwrap();
    let c2 = Candidate::new(TransportId::new("wifi-direct"), "192.168.49.1:8000").unwrap();
    let obs = PeerObservation::new(
        ObservationId::new(source, ObservationKey::new("peer-addrs").unwrap()),
        vec![c1.clone(), c2.clone()],
    );

    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(obs)).unwrap();

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let info = peer_info(&peers[0]);

    assert_eq!(
        info.addresses,
        vec![c1.address().to_string(), c2.address().to_string()]
    );
}

#[test]
fn sources_names_each_distinct_discovery_source_once() {
    let device_id = DeviceId::from_bytes(&[0x07; 16]).unwrap();
    let s1 = SourceId::new("mdns");
    let s2 = SourceId::new("ble");

    let obs1 = PeerObservation::new(
        ObservationId::new(s1, ObservationKey::new("key-1").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id);

    let obs2 = PeerObservation::new(
        ObservationId::new(s2, ObservationKey::new("key-2").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id);

    let obs3 = PeerObservation::new(
        ObservationId::new(s1, ObservationKey::new("key-3").unwrap()),
        Vec::new(),
    )
    .with_device_id(device_id);

    let mut list = PeerList::new();
    list.apply(s1, DiscoveryEvent::Observed(obs1)).unwrap();
    list.apply(s2, DiscoveryEvent::Observed(obs2)).unwrap();
    list.apply(s1, DiscoveryEvent::Observed(obs3)).unwrap();

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let info = peer_info(&peers[0]);

    assert_eq!(info.sources, vec!["ble".to_string(), "mdns".to_string()]);
}

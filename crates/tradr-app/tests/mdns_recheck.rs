//! Tests for mDNS observation rechecking (WI-M8-081a, docs/03).

use std::cell::RefCell;

use tradr_app::peers::{mdns_observation_keys, recheck_mdns_peers};
use tradr_core::{
    DeviceId, DiscoveryEvent, ObservationId, ObservationKey, PeerList, PeerObservation,
};
use tradr_discovery::{MDNS_SOURCE_ID, STATIC_PEER_SOURCE_ID};

fn test_device_id(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; 16]).expect("16 bytes is a valid DeviceId")
}

#[test]
fn none_over_list_yields_all_mdns_keys_and_omits_static_peers() {
    let mut list = PeerList::new();
    let dev1 = test_device_id(0x01);
    let dev2 = test_device_id(0x02);
    let dev3 = test_device_id(0x03);

    let key1 = ObservationKey::new("mdns.peer.1").expect("valid key");
    let key2 = ObservationKey::new("mdns.peer.2").expect("valid key");
    let static_key = ObservationKey::new("static.peer.3").expect("valid key");

    let obs1 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key1.clone()), Vec::new())
        .with_device_id(dev1);

    let obs2 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key2.clone()), Vec::new())
        .with_device_id(dev2);

    let obs3 = PeerObservation::new(
        ObservationId::new(STATIC_PEER_SOURCE_ID, static_key.clone()),
        Vec::new(),
    )
    .with_device_id(dev3);

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs1))
        .expect("apply obs1");
    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs2))
        .expect("apply obs2");
    list.apply(STATIC_PEER_SOURCE_ID, DiscoveryEvent::Observed(obs3))
        .expect("apply obs3");

    let keys = mdns_observation_keys(&list, None);
    assert_eq!(keys, vec![key1, key2]);
    assert!(!keys.contains(&static_key));
}

#[test]
fn peer_seen_by_mdns_and_static_peer_under_one_device_id_yields_only_its_mdns_key() {
    let mut list = PeerList::new();
    let dev = test_device_id(0x10);

    let mdns_key = ObservationKey::new("mdns.shared.peer").expect("valid key");
    let static_key = ObservationKey::new("static.shared.peer").expect("valid key");

    let mdns_obs = PeerObservation::new(
        ObservationId::new(MDNS_SOURCE_ID, mdns_key.clone()),
        Vec::new(),
    )
    .with_device_id(dev);

    let static_obs = PeerObservation::new(
        ObservationId::new(STATIC_PEER_SOURCE_ID, static_key.clone()),
        Vec::new(),
    )
    .with_device_id(dev);

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(mdns_obs))
        .expect("apply mdns_obs");
    list.apply(STATIC_PEER_SOURCE_ID, DiscoveryEvent::Observed(static_obs))
        .expect("apply static_obs");

    let keys = mdns_observation_keys(&list, Some(&dev.to_string()));
    assert_eq!(keys, vec![mdns_key]);
    assert!(!keys.contains(&static_key));
}

#[test]
fn some_naming_different_peer_yields_nothing_of_first_peer() {
    let mut list = PeerList::new();
    let dev1 = test_device_id(0x10);
    let dev2 = test_device_id(0x20);

    let key1 = ObservationKey::new("mdns.peer.1").expect("valid key");
    let key2 = ObservationKey::new("mdns.peer.2").expect("valid key");

    let obs1 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key1.clone()), Vec::new())
        .with_device_id(dev1);

    let obs2 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key2.clone()), Vec::new())
        .with_device_id(dev2);

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs1))
        .expect("apply obs1");
    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs2))
        .expect("apply obs2");

    let keys = mdns_observation_keys(&list, Some(&dev2.to_string()));
    assert_eq!(keys, vec![key2]);
    assert!(!keys.contains(&key1));
}

#[test]
fn some_naming_no_peer_yields_empty_vector() {
    let mut list = PeerList::new();
    let dev1 = test_device_id(0x10);
    let key1 = ObservationKey::new("mdns.peer.1").expect("valid key");
    let obs1 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key1), Vec::new())
        .with_device_id(dev1);

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs1))
        .expect("apply obs1");

    let keys = mdns_observation_keys(&list, Some("nonexistent-device-id"));
    assert!(keys.is_empty());

    let empty_list = PeerList::new();
    let keys_empty = mdns_observation_keys(&empty_list, Some("any-id"));
    assert!(keys_empty.is_empty());
}

#[test]
fn unidentified_peer_is_matched_by_its_observation_id_string() {
    let mut list = PeerList::new();
    let key = ObservationKey::new("unidentified.mdns").expect("valid key");
    let obs = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key.clone()), Vec::new());
    let obs_id_str = obs.id().to_string();

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs))
        .expect("apply obs");

    let keys = mdns_observation_keys(&list, Some(&obs_id_str));
    assert_eq!(keys, vec![key]);
}

#[test]
fn recheck_mdns_peers_returns_count_and_invokes_recheck_for_each_key() {
    let mut list = PeerList::new();
    let dev1 = test_device_id(0x01);
    let dev2 = test_device_id(0x02);

    let key1 = ObservationKey::new("mdns.peer.1").expect("valid key");
    let key2 = ObservationKey::new("mdns.peer.2").expect("valid key");

    let obs1 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key1.clone()), Vec::new())
        .with_device_id(dev1);
    let obs2 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key2.clone()), Vec::new())
        .with_device_id(dev2);

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs1))
        .expect("apply obs1");
    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs2))
        .expect("apply obs2");

    let recorded = RefCell::new(Vec::new());
    let count = recheck_mdns_peers(&list, None, &|key| {
        recorded.borrow_mut().push(key.clone());
        Ok(())
    })
    .expect("recheck succeeded");

    assert_eq!(count, 2);
    assert_eq!(recorded.into_inner(), vec![key1, key2]);
}

#[test]
fn recheck_mdns_peers_stops_at_first_error_and_returns_it() {
    let mut list = PeerList::new();
    let dev1 = test_device_id(0x01);
    let dev2 = test_device_id(0x02);
    let dev3 = test_device_id(0x03);

    let key1 = ObservationKey::new("mdns.peer.1").expect("valid key");
    let key2 = ObservationKey::new("mdns.peer.2").expect("valid key");
    let key3 = ObservationKey::new("mdns.peer.3").expect("valid key");

    let obs1 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key1.clone()), Vec::new())
        .with_device_id(dev1);
    let obs2 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key2.clone()), Vec::new())
        .with_device_id(dev2);
    let obs3 = PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key3.clone()), Vec::new())
        .with_device_id(dev3);

    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs1))
        .expect("apply obs1");
    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs2))
        .expect("apply obs2");
    list.apply(MDNS_SOURCE_ID, DiscoveryEvent::Observed(obs3))
        .expect("apply obs3");

    let recorded = RefCell::new(Vec::new());
    let err = recheck_mdns_peers(&list, None, &|key| {
        recorded.borrow_mut().push(key.clone());
        if key == &key2 {
            Err("verify failed for key2".to_string())
        } else {
            Ok(())
        }
    })
    .expect_err("must return first error");

    assert_eq!(err, "verify failed for key2");
    assert_eq!(recorded.into_inner(), vec![key1, key2]);
}

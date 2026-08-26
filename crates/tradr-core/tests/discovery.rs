//! Tests for `ObservationKey`, `DisplayName`, `PeerObservation`, the peer
//! list's merge rules, and `DiscoverySource`'s dyn compatibility (docs/03,
//! "What a Discovery Source reports" and "The peer list"). See
//! tests/transport.rs, the direct model for the manual-poll double below.

use std::future::Future;
use std::task::{Context, Poll, Waker};

use tradr_core::{
    Candidate, Capabilities, DEVICE_ID_LEN, DeviceId, DiscoveryError, DiscoveryEvent,
    DiscoverySource, DisplayName, DisplayNameError, OBSERVATION_KEY_MAX_LEN, ObservationId,
    ObservationKey, ObservationKeyError, PeerList, PeerListError, PeerObservation, SourceId,
    TransportId,
};

fn device(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; DEVICE_ID_LEN]).expect("16 bytes must construct")
}

fn observation_id(source: SourceId, key: &str) -> ObservationId {
    ObservationId::new(source, ObservationKey::new(key).expect("valid key"))
}

fn candidate(transport: &'static str, address: &str) -> Candidate {
    Candidate::new(TransportId::new(transport), address).expect("valid address")
}

// --- ObservationKey ---

#[test]
fn observation_key_new_accepts_a_realistic_value() {
    assert!(ObservationKey::new("aa:bb:cc:dd:ee:ff").is_ok());
}

#[test]
fn observation_key_new_rejects_empty() {
    assert_eq!(ObservationKey::new(""), Err(ObservationKeyError::Empty));
}

#[test]
fn observation_key_new_rejects_too_long() {
    let s = "a".repeat(OBSERVATION_KEY_MAX_LEN + 1);
    assert_eq!(
        ObservationKey::new(&s),
        Err(ObservationKeyError::TooLong(OBSERVATION_KEY_MAX_LEN + 1))
    );
}

#[test]
fn observation_key_new_rejects_control_character() {
    assert_eq!(
        ObservationKey::new("host\u{0007}key"),
        Err(ObservationKeyError::ControlCharacter('\u{0007}'))
    );
}

// --- DisplayName ---

#[test]
fn display_name_new_accepts_a_realistic_value() {
    assert!(DisplayName::new("Alice's Laptop").is_ok());
}

#[test]
fn display_name_new_rejects_empty() {
    assert_eq!(DisplayName::new(""), Err(DisplayNameError::Empty));
}

#[test]
fn display_name_new_rejects_too_long() {
    let s = "a".repeat(tradr_core::DISPLAY_NAME_MAX_LEN + 1);
    assert_eq!(
        DisplayName::new(&s),
        Err(DisplayNameError::TooLong(
            tradr_core::DISPLAY_NAME_MAX_LEN + 1
        ))
    );
}

#[test]
fn display_name_new_rejects_control_character() {
    assert_eq!(
        DisplayName::new("Alice\u{0007}Laptop"),
        Err(DisplayNameError::ControlCharacter('\u{0007}'))
    );
}

#[test]
fn display_name_new_rejects_33_bytes_and_accepts_32_bytes_measured_in_bytes_not_chars() {
    // "\u{00e9}" (e-acute) is 2 bytes in UTF-8, so 16 copies is exactly
    // 32 bytes, and 16 copies plus one ASCII byte is exactly 33 bytes.
    let accepted = "\u{00e9}".repeat(16);
    assert_eq!(accepted.len(), 32);
    assert!(DisplayName::new(&accepted).is_ok());

    let rejected = format!("{accepted}a");
    assert_eq!(rejected.len(), 33);
    assert_eq!(
        DisplayName::new(&rejected),
        Err(DisplayNameError::TooLong(33))
    );
}

// --- PeerObservation canonicalisation ---

#[test]
fn peer_observation_new_sorts_and_deduplicates_candidates() {
    let source = SourceId::new("mdns");
    let id = observation_id(source, "a");

    let a = candidate("direct-quic", "192.168.1.1:1");
    let b = candidate("direct-quic", "192.168.1.2:1");
    let c = candidate("relay", "relay://x");

    let one = PeerObservation::new(id.clone(), vec![c.clone(), a.clone(), b.clone(), a.clone()]);
    let two = PeerObservation::new(id, vec![b, a, c]);

    assert_eq!(one, two);
    assert_eq!(one.candidates().len(), 3);
}

#[test]
fn peer_observation_new_accepts_an_empty_candidate_list() {
    let source = SourceId::new("ble");
    let id = observation_id(source, "eid-1");

    let observation = PeerObservation::new(id, Vec::new());

    assert!(observation.candidates().is_empty());
}

// --- ObservationId ordering ---

#[test]
fn observation_id_orders_by_source_then_key_and_peer_observations_follow_it() {
    let mdns = SourceId::new("mdns");
    let static_peer = SourceId::new("static");

    // `(source, key)` says mdns/z < static/a, since "mdns" < "static"; the
    // reverse field order, `(key, source)`, would instead say static/a <
    // mdns/z, since "a" < "z". The pair disagrees between the two
    // orderings, so only the declared field order passes.
    let mdns_z = observation_id(mdns, "z");
    let static_a = observation_id(static_peer, "a");

    assert!(mdns_z < static_a);

    let mut list = PeerList::new();
    list.apply(
        static_peer,
        DiscoveryEvent::Observed(
            PeerObservation::new(static_a, Vec::new()).with_device_id(device(4)),
        ),
    )
    .expect("valid event");
    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(mdns_z, Vec::new()).with_device_id(device(4)),
        ),
    )
    .expect("valid event");

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let observations = peers[0].observations();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].id().source(), mdns);
    assert_eq!(observations[1].id().source(), static_peer);
}

// --- PeerList::apply, SourceMismatch ---

#[test]
fn apply_refuses_observed_naming_another_source_and_leaves_the_list_unchanged() {
    let mdns = SourceId::new("mdns");
    let ble = SourceId::new("ble");
    let mut list = PeerList::new();

    let id = observation_id(mdns, "key-1");
    let observation = PeerObservation::new(id, Vec::new());
    let result = list.apply(ble, DiscoveryEvent::Observed(observation));

    assert_eq!(
        result,
        Err(PeerListError::SourceMismatch {
            claimed: mdns,
            actual: ble,
        })
    );
    assert_eq!(list.observation_count(), 0);
}

#[test]
fn apply_refuses_lost_naming_another_source_and_leaves_the_list_unchanged() {
    let mdns = SourceId::new("mdns");
    let ble = SourceId::new("ble");
    let mut list = PeerList::new();

    let id = observation_id(mdns, "key-1");
    list.apply(
        mdns,
        DiscoveryEvent::Observed(PeerObservation::new(id.clone(), Vec::new())),
    )
    .expect("matching source must be accepted");

    let result = list.apply(ble, DiscoveryEvent::Lost(id));

    assert_eq!(
        result,
        Err(PeerListError::SourceMismatch {
            claimed: mdns,
            actual: ble,
        })
    );
    assert_eq!(list.observation_count(), 1);
}

// --- Merging ---

#[test]
fn two_sources_observing_the_same_device_id_produce_one_peer_with_unioned_candidates() {
    let mdns = SourceId::new("mdns");
    let brokr = SourceId::new("brokr");
    let mut list = PeerList::new();

    let shared = candidate("direct-quic", "192.168.1.42:51820");
    let mdns_only = candidate("direct-quic", "192.168.1.42:9999");
    let brokr_only = candidate("relay", "relay://brokr.example/x");

    let mdns_observation =
        PeerObservation::new(observation_id(mdns, "abc"), vec![shared.clone(), mdns_only])
            .with_device_id(device(1));
    let brokr_observation = PeerObservation::new(
        observation_id(brokr, "def"),
        vec![shared.clone(), brokr_only],
    )
    .with_device_id(device(1));

    list.apply(mdns, DiscoveryEvent::Observed(mdns_observation))
        .expect("valid event");
    list.apply(brokr, DiscoveryEvent::Observed(brokr_observation))
        .expect("valid event");

    let peers = list.peers();
    assert_eq!(peers.len(), 1);
    let peer = &peers[0];
    assert_eq!(peer.device_id(), Some(device(1)));
    assert_eq!(peer.candidates().len(), 3);
    assert!(peer.candidates().contains(&shared));
    assert_eq!(peer.observations().len(), 2);
}

#[test]
fn an_observation_with_no_device_id_is_its_own_peer() {
    let mdns = SourceId::new("mdns");
    let mut list = PeerList::new();

    let identified =
        PeerObservation::new(observation_id(mdns, "a"), Vec::new()).with_device_id(device(7));
    let unidentified = PeerObservation::new(observation_id(mdns, "b"), Vec::new());

    list.apply(mdns, DiscoveryEvent::Observed(identified))
        .expect("valid event");
    list.apply(mdns, DiscoveryEvent::Observed(unidentified))
        .expect("valid event");

    let peers = list.peers();
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].device_id(), Some(device(7)));
    assert_eq!(peers[1].device_id(), None);
    assert_eq!(peers[1].observations().len(), 1);
}

#[test]
fn peers_orders_identified_peers_ascending_by_device_id_with_unidentified_last() {
    let mdns = SourceId::new("mdns");
    let mut list = PeerList::new();

    // Applied high device id before low: insertion order disagrees with
    // the required ascending order, so only a real sort passes.
    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(observation_id(mdns, "high"), Vec::new())
                .with_device_id(device(9)),
        ),
    )
    .expect("valid event");
    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(observation_id(mdns, "low"), Vec::new()).with_device_id(device(1)),
        ),
    )
    .expect("valid event");
    list.apply(
        mdns,
        DiscoveryEvent::Observed(PeerObservation::new(
            observation_id(mdns, "unid"),
            Vec::new(),
        )),
    )
    .expect("valid event");

    let peers = list.peers();
    assert_eq!(peers.len(), 3);
    assert_eq!(peers[0].device_id(), Some(device(1)));
    assert_eq!(peers[1].device_id(), Some(device(9)));
    assert_eq!(peers[2].device_id(), None);
}

#[test]
fn reapplying_observed_with_the_same_id_replaces_rather_than_adds() {
    let mdns = SourceId::new("mdns");
    let mut list = PeerList::new();
    let id = observation_id(mdns, "a");

    list.apply(
        mdns,
        DiscoveryEvent::Observed(PeerObservation::new(id.clone(), Vec::new())),
    )
    .expect("valid event");
    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(id, vec![candidate("direct-quic", "10.0.0.1:1")])
                .with_device_id(device(3)),
        ),
    )
    .expect("valid event");

    assert_eq!(list.observation_count(), 1);
    assert_eq!(list.peers().len(), 1);
    assert_eq!(list.peers()[0].device_id(), Some(device(3)));
}

#[test]
fn trust_on_first_use_merges_a_late_device_id_into_the_peer_already_holding_it() {
    let mdns = SourceId::new("mdns");
    let static_peer = SourceId::new("static");
    let mut list = PeerList::new();

    // mDNS already knows the device.
    let mdns_id = observation_id(mdns, "abc");
    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(
                mdns_id,
                vec![candidate("direct-quic", "192.168.1.42:51820")],
            )
            .with_device_id(device(9)),
        ),
    )
    .expect("valid event");

    // A Static Peer entry has no device id until its first connection.
    let static_id = observation_id(static_peer, "home-desktop");
    list.apply(
        static_peer,
        DiscoveryEvent::Observed(PeerObservation::new(
            static_id.clone(),
            vec![candidate("direct-quic", "desktop.tailnet.ts.net:51820")],
        )),
    )
    .expect("valid event");

    // Before the first connection, the Static Peer entry is unidentified,
    // so there are two peers.
    assert_eq!(list.peers().len(), 2);

    // The first connection fills in expect_device_id, and the source
    // re-reports the same ObservationId with the Device ID now present.
    list.apply(
        static_peer,
        DiscoveryEvent::Observed(
            PeerObservation::new(
                static_id,
                vec![candidate("direct-quic", "desktop.tailnet.ts.net:51820")],
            )
            .with_device_id(device(9)),
        ),
    )
    .expect("valid event");

    let peers = list.peers();
    assert_eq!(
        peers.len(),
        1,
        "the two observations must merge into one peer"
    );
    assert_eq!(peers[0].device_id(), Some(device(9)));
    assert_eq!(peers[0].observations().len(), 2);
}

#[test]
fn lost_for_an_id_never_applied_is_ok_and_changes_nothing() {
    let mdns = SourceId::new("mdns");
    let mut list = PeerList::new();

    let result = list.apply(
        mdns,
        DiscoveryEvent::Lost(observation_id(mdns, "never-seen")),
    );

    assert_eq!(result, Ok(()));
    assert_eq!(list.observation_count(), 0);
}

#[test]
fn lost_removes_the_observation_and_the_peer_disappears() {
    let mdns = SourceId::new("mdns");
    let mut list = PeerList::new();
    let id = observation_id(mdns, "a");

    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(id.clone(), Vec::new()).with_device_id(device(2)),
        ),
    )
    .expect("valid event");
    assert_eq!(list.peers().len(), 1);

    list.apply(mdns, DiscoveryEvent::Lost(id))
        .expect("valid event");

    assert_eq!(list.observation_count(), 0);
    assert!(list.peers().is_empty());
}

#[test]
fn applying_the_same_events_in_different_orders_produces_identical_peers() {
    let mdns = SourceId::new("mdns");
    let brokr = SourceId::new("brokr");

    let event_a = (
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(
                observation_id(mdns, "a"),
                vec![candidate("direct-quic", "192.168.1.1:1")],
            )
            .with_device_id(device(1)),
        ),
    );
    let event_b = (
        brokr,
        DiscoveryEvent::Observed(
            PeerObservation::new(
                observation_id(brokr, "b"),
                vec![candidate("relay", "relay://x")],
            )
            .with_device_id(device(1)),
        ),
    );
    let event_c = (
        mdns,
        DiscoveryEvent::Observed(PeerObservation::new(observation_id(mdns, "c"), Vec::new())),
    );

    let mut forward = PeerList::new();
    forward
        .apply(event_a.0, event_a.1.clone())
        .expect("valid event");
    forward
        .apply(event_b.0, event_b.1.clone())
        .expect("valid event");
    forward
        .apply(event_c.0, event_c.1.clone())
        .expect("valid event");

    let mut backward = PeerList::new();
    backward.apply(event_c.0, event_c.1).expect("valid event");
    backward.apply(event_b.0, event_b.1).expect("valid event");
    backward.apply(event_a.0, event_a.1).expect("valid event");

    assert_eq!(forward.peers(), backward.peers());
}

#[test]
fn peer_returns_the_identified_peer_and_none_for_an_unobserved_device() {
    let mdns = SourceId::new("mdns");
    let mut list = PeerList::new();

    list.apply(
        mdns,
        DiscoveryEvent::Observed(
            PeerObservation::new(observation_id(mdns, "a"), Vec::new()).with_device_id(device(5)),
        ),
    )
    .expect("valid event");

    assert_eq!(
        list.peer(device(5)).map(|p| p.device_id()),
        Some(Some(device(5)))
    );
    assert_eq!(list.peer(device(6)), None);
}

// --- Capabilities ---

#[test]
fn capabilities_contains_reflects_set_and_unset_bits() {
    let caps =
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | Capabilities::RELAY.bits());

    assert!(caps.contains(Capabilities::DIRECT_QUIC));
    assert!(caps.contains(Capabilities::RELAY));
    assert!(!caps.contains(Capabilities::BLE_GATT));
}

#[test]
fn capabilities_default_contains_no_named_bit() {
    let caps = Capabilities::default();

    assert!(!caps.contains(Capabilities::DIRECT_QUIC));
    assert!(!caps.contains(Capabilities::WIFI_DIRECT));
    assert!(!caps.contains(Capabilities::BLE_GATT));
    assert!(!caps.contains(Capabilities::RELAY));
    assert!(!caps.contains(Capabilities::ACCEPTS_BROWSING));
    assert!(!caps.contains(Capabilities::WRITABLE_SHARE));
    assert!(!caps.contains(Capabilities::METERED));
}

#[test]
fn capabilities_contains_requires_every_bit_not_any() {
    let caps =
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | Capabilities::RELAY.bits());

    let both =
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | Capabilities::RELAY.bits());
    let only_one_shared =
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | Capabilities::BLE_GATT.bits());

    assert!(caps.contains(both));
    assert!(
        !caps.contains(only_one_shared),
        "caps holds only one of the two bits `only_one_shared` asks for"
    );
}

// --- Dyn compatibility ---

/// A `DiscoverySource` double that reports one fixed event and then
/// closes, standing in for a source whose stream of changes has ended.
struct FakeSource {
    id: SourceId,
    pending: Option<DiscoveryEvent>,
}

impl DiscoverySource for FakeSource {
    fn id(&self) -> SourceId {
        self.id
    }

    fn next_event(&mut self) -> tradr_core::BoxFuture<'_, Result<DiscoveryEvent, DiscoveryError>> {
        let event = self.pending.take();
        Box::pin(async move { event.ok_or(DiscoveryError::Closed) })
    }
}

// Compiles only if the future `F` produces is `Send`, the bound a
// multi-threaded executor needs (ADR-0013).
fn assert_send<F: Future + Send>(_: F) {}

#[test]
fn discovery_source_is_dyn_compatible_and_next_event_runs_without_a_runtime() {
    let mdns = SourceId::new("mdns");
    let observation = PeerObservation::new(observation_id(mdns, "a"), Vec::new());
    let mut sources: Vec<Box<dyn DiscoverySource>> = vec![
        Box::new(FakeSource {
            id: mdns,
            pending: Some(DiscoveryEvent::Observed(observation)),
        }),
        Box::new(FakeSource {
            id: SourceId::new("ble"),
            pending: None,
        }),
    ];

    // A separate instance, since `next_event` already consumes `pending`
    // the moment it is called, before it is ever polled.
    let mut send_check = FakeSource {
        id: mdns,
        pending: None,
    };
    assert_send(send_check.next_event());

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let mut first = sources[0].next_event();
    match first.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(DiscoveryEvent::Observed(_))) => {}
        other => panic!("unexpected result: {other:?}"),
    }
    drop(first);

    let mut second = sources[1].next_event();
    match second.as_mut().poll(&mut cx) {
        Poll::Ready(Err(DiscoveryError::Closed)) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

//! WI-M7-009, Critical Module: what a dial is told about the peer it is
//! reaching for, and which transport is handed the candidate (docs/03,
//! "What a transport is told about the peer it is dialling", DCR-108).
//! Handing back `Unpinned` for a pinned entry is the failure "The pin"
//! exists to prevent, so a second source answering it is tested beside it.

use std::sync::{Arc, Mutex};

use tauri_plugin_tradr::commands::{ResolvedPeer, connect_and_pin, resolve_peer};
use tradr_core::{
    BoxFuture, Candidate, DeviceId, DiscoveryEvent, Incoming, ObservationId, ObservationKey,
    PeerExpectation, PeerList, PeerObservation, SecureChannel, SourceId, Transport, TransportError,
    TransportId,
};
use tradr_discovery::{BLE_SOURCE_ID, MDNS_SOURCE_ID, StaticPeerRegistry};
use tradr_transport::set::TransportSet;

const DIRECT_QUIC: TransportId = TransportId::new("direct-quic");
const BLE_GATT: TransportId = TransportId::new("ble-gatt");
const BLE_HANDLE: &str = "AA:BB:CC:DD:EE:FF";
const QUIC_ADDRESS: &str = "192.168.1.42:21820";

type DialLog = Arc<Mutex<Vec<(TransportId, String)>>>;

// Records which transport was asked to dial what and refuses every dial:
// these tests decide where a candidate is sent, never what happens once
// it arrives.
struct StubTransport {
    id: TransportId,
    dials: DialLog,
}

impl Transport for StubTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn connect<'a>(
        &'a self,
        candidate: &'a Candidate,
        _expect: &'a PeerExpectation,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            self.dials
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((self.id, candidate.address().to_string()));
            Err(TransportError::Unreachable)
        })
    }

    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }
}

fn set_of(ids: &[TransportId]) -> (TransportSet, DialLog) {
    let dials: DialLog = Arc::new(Mutex::new(Vec::new()));
    let transports = ids
        .iter()
        .map(|id| {
            Arc::new(StubTransport {
                id: *id,
                dials: Arc::clone(&dials),
            }) as Arc<dyn Transport>
        })
        .collect();
    (TransportSet::new(transports), dials)
}

fn empty_registry(dir: &tempfile::TempDir) -> StaticPeerRegistry {
    let (registry, _source) = StaticPeerRegistry::load(&dir.path().join("static-peers.json"))
        .expect("load empty registry");
    registry
}

fn list_with(source: SourceId, observation: PeerObservation) -> PeerList {
    let mut list = PeerList::new();
    list.apply(source, DiscoveryEvent::Observed(observation))
        .expect("apply observation");
    list
}

// What a BLE scanner produces: a handle, no Device ID, one `ble-gatt`
// candidate.
fn ble_observation(candidates: Vec<Candidate>) -> PeerObservation {
    let key = ObservationKey::new(BLE_HANDLE).expect("valid observation key");
    PeerObservation::new(ObservationId::new(BLE_SOURCE_ID, key), candidates)
}

// Phase 1 collects a peer's candidates from every source that reported
// it, so one peer's set spans transport classes. This stands in for that
// union, which no single source emits on its own.
fn identified_observation(device: DeviceId, candidates: Vec<Candidate>) -> PeerObservation {
    let key = ObservationKey::new("tradr-peer._tradr._udp.local.").expect("valid observation key");
    PeerObservation::new(ObservationId::new(MDNS_SOURCE_ID, key), candidates).with_device_id(device)
}

fn ble_candidate() -> Candidate {
    Candidate::new(BLE_GATT, BLE_HANDLE).expect("valid ble candidate")
}

fn quic_candidate() -> Candidate {
    Candidate::new(DIRECT_QUIC, QUIC_ADDRESS).expect("valid quic candidate")
}

fn observation_id_of(list: &PeerList) -> String {
    list.peers()
        .first()
        .expect("one peer")
        .observations()
        .first()
        .expect("one observation")
        .id()
        .to_string()
}

// docs/03: every `ble-gatt` dial is `Unpinned`, and a BLE handle has no
// Static Peer entry, so there is nothing for the connection to write back.
#[test]
fn a_ble_observation_resolves_to_unpinned_with_nothing_to_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = empty_registry(&dir);
    let list = list_with(BLE_SOURCE_ID, ble_observation(vec![ble_candidate()]));
    let (transports, _dials) = set_of(&[DIRECT_QUIC, BLE_GATT]);

    let resolved = resolve_peer(&observation_id_of(&list), &list, &registry, &transports)
        .expect("resolve the ble peer");

    assert_eq!(resolved.expectation, PeerExpectation::Unpinned);
    assert_eq!(resolved.pin_target, None);
    assert_eq!(resolved.candidate.transport(), BLE_GATT);
    assert_eq!(resolved.candidate.address(), BLE_HANDLE);
}

// A device with no `ble-gatt` half cannot reach a peer that offers only
// one, and the refusal says so rather than naming the peer as absent.
#[test]
fn a_ble_observation_is_refused_when_this_device_holds_no_ble_transport() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = empty_registry(&dir);
    let list = list_with(BLE_SOURCE_ID, ble_observation(vec![ble_candidate()]));
    let (transports, _dials) = set_of(&[DIRECT_QUIC]);

    let err = resolve_peer(&observation_id_of(&list), &list, &registry, &transports)
        .expect_err("a ble candidate with no ble transport cannot be dialled");

    assert!(err.contains("this device can dial"), "{err}");
}

// The two refusals are different facts -- one about the peer, one about
// this device -- and one message for both hides an absent radio.
#[test]
fn no_candidate_at_all_is_a_different_refusal_from_none_this_device_can_dial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = empty_registry(&dir);
    let (transports, _dials) = set_of(&[DIRECT_QUIC]);

    let empty = list_with(BLE_SOURCE_ID, ble_observation(vec![]));
    let no_candidate = resolve_peer(&observation_id_of(&empty), &empty, &registry, &transports)
        .expect_err("a peer with no candidate cannot be dialled");

    let undialable = list_with(BLE_SOURCE_ID, ble_observation(vec![ble_candidate()]));
    let cannot_dial = resolve_peer(
        &observation_id_of(&undialable),
        &undialable,
        &registry,
        &transports,
    )
    .expect_err("a ble candidate with no ble transport cannot be dialled");

    assert_ne!(no_candidate, cannot_dial);
    assert!(
        no_candidate.contains("no candidate address found"),
        "{no_candidate}"
    );
    assert!(
        cannot_dial.contains("this device can dial"),
        "{cannot_dial}"
    );
}

// A source this branch has not been written for gets no default: dialling
// it under `Unpinned` would decide a fourth source's policy in advance.
#[test]
fn an_observation_from_another_source_is_still_refused_as_unidentified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = empty_registry(&dir);
    let source = SourceId::new("brokr");
    let key = ObservationKey::new("some-brokr-key").expect("valid observation key");
    let observation = PeerObservation::new(ObservationId::new(source, key), vec![quic_candidate()]);
    let list = list_with(source, observation);
    let (transports, _dials) = set_of(&[DIRECT_QUIC, BLE_GATT]);

    let err = resolve_peer(&observation_id_of(&list), &list, &registry, &transports)
        .expect_err("an unidentified observation from an unknown source is refused");

    assert!(err.contains("has not yet been identified"), "{err}");
}

// `class_weight` orders the pick, and the peer list sorts `ble-gatt`
// ahead of `direct-quic`, so taking the first candidate would take the
// wrong one.
#[test]
fn an_identified_peer_is_dialled_on_direct_quic_when_both_are_available() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = empty_registry(&dir);
    let device = DeviceId::from_bytes(&[3u8; 16]).expect("valid device id");
    let observation = identified_observation(device, vec![ble_candidate(), quic_candidate()]);
    let list = list_with(MDNS_SOURCE_ID, observation);
    let (transports, _dials) = set_of(&[DIRECT_QUIC, BLE_GATT]);

    let resolved = resolve_peer(&device.to_string(), &list, &registry, &transports)
        .expect("resolve the identified peer");

    assert_eq!(resolved.expectation, PeerExpectation::Device(device));
    assert_eq!(resolved.candidate.transport(), DIRECT_QUIC);
}

// The same peer, on a device holding no QUIC transport, is reached over
// the lower-weighted path rather than not at all.
#[test]
fn an_identified_peer_falls_to_ble_gatt_when_it_is_the_only_dialable_candidate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = empty_registry(&dir);
    let device = DeviceId::from_bytes(&[4u8; 16]).expect("valid device id");
    let observation = identified_observation(device, vec![ble_candidate(), quic_candidate()]);
    let list = list_with(MDNS_SOURCE_ID, observation);
    let (transports, _dials) = set_of(&[BLE_GATT]);

    let resolved = resolve_peer(&device.to_string(), &list, &registry, &transports)
        .expect("resolve the identified peer");

    assert_eq!(resolved.candidate.transport(), BLE_GATT);
}

// The dispatch itself: the candidate reaches the transport that produced
// it and no other transport is asked.
#[tokio::test]
async fn connect_and_pin_dials_the_transport_the_candidate_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = tokio::sync::Mutex::new(empty_registry(&dir));
    let (transports, dials) = set_of(&[DIRECT_QUIC, BLE_GATT]);
    let resolved = ResolvedPeer {
        candidate: ble_candidate(),
        expectation: PeerExpectation::Unpinned,
        pin_target: None,
    };

    // `expect_err` needs `T: Debug` and `dyn SecureChannel` has none.
    let err = match connect_and_pin(&transports, &registry, resolved).await {
        Ok(_) => panic!("the stub transport refuses every dial"),
        Err(e) => e,
    };

    assert!(err.contains(BLE_HANDLE), "{err}");
    let dialled = dials
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(dialled, vec![(BLE_GATT, BLE_HANDLE.to_string())]);
}

// A candidate whose transport the set does not hold is refused before a
// dial, not handed to whichever transport happens to be first.
#[tokio::test]
async fn connect_and_pin_refuses_a_candidate_no_transport_can_dial() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = tokio::sync::Mutex::new(empty_registry(&dir));
    let (transports, dials) = set_of(&[DIRECT_QUIC]);
    let resolved = ResolvedPeer {
        candidate: ble_candidate(),
        expectation: PeerExpectation::Unpinned,
        pin_target: None,
    };

    let err = match connect_and_pin(&transports, &registry, resolved).await {
        Ok(_) => panic!("no transport in the set can dial a ble-gatt candidate"),
        Err(e) => e,
    };

    assert!(err.contains("ble-gatt"), "{err}");
    assert!(
        dials
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty(),
        "nothing may be dialled when no transport matches"
    );
}

//! Tests for `MdnsSource` and the advertiser (docs/03, "1. mDNS / DNS-SD").
//! No daemon runs and no test sleeps (decision 22). `ResolvedService` has
//! no public constructor, so fixtures go through
//! `ServiceInfo::new(...).as_resolved_service()`, which cannot express a
//! scoped IPv6 address; that case is a unit test in `src/mdns.rs` instead.

use std::net::SocketAddr;
use std::task::{Context, Poll, Waker};

use mdns_sd::{ResolvedService, ServiceEvent, ServiceInfo};
use tradr_core::{
    Capabilities, DEVICE_ID_LEN, DeviceId, DiscoveryError, DiscoveryEvent, DiscoverySource,
    DisplayName, ObservationId, ObservationKey, Rng, RngError, TransportId,
};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, MDNS_SOURCE_ID, MdnsSource, Platform, SERVICE_TYPE, TxtRecord,
    advertisement, instance_name,
};

fn device(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; DEVICE_ID_LEN]).expect("16 bytes must construct")
}

fn tag(byte: u8) -> [u8; AGREEMENT_KEY_TAG_LEN] {
    [byte; AGREEMENT_KEY_TAG_LEN]
}

fn valid_record() -> TxtRecord {
    TxtRecord::new(
        device(0x11),
        tag(0x22),
        Some(DisplayName::new("Alice's laptop").expect("valid display name")),
        Capabilities::DIRECT_QUIC,
        Platform::new("linux").expect("valid platform"),
    )
}

fn resolved_with_pairs(
    instance_name: &str,
    port: u16,
    ip: &str,
    pairs: &[(String, String)],
) -> ResolvedService {
    ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        "test-host.local.",
        ip,
        port,
        pairs,
    )
    .expect("valid service info")
    .as_resolved_service()
}

fn resolved(instance_name: &str, port: u16, ip: &str, record: &TxtRecord) -> ResolvedService {
    resolved_with_pairs(instance_name, port, ip, &record.to_pairs())
}

fn fullname(instance_name: &str) -> String {
    format!("{instance_name}.{SERVICE_TYPE}")
}

// Drives `source.next_event()` to completion with a no-op waker, exactly
// tradr-core/tests/discovery.rs's style: every event a test needs must
// already be queued in the channel before this is called, since nothing
// here ever wakes a pending future.
fn poll_ready(source: &mut MdnsSource) -> Result<DiscoveryEvent, DiscoveryError> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = source.next_event();
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => {
            panic!("next_event did not resolve; queue every event before polling")
        }
    }
}

// --- ServiceResolved -> Observed ---

#[test]
fn a_resolved_service_yields_observed_with_the_records_fields_and_the_fullname_as_key() {
    let (tx, rx) = flume::unbounded();
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-a",
        51820,
        "192.168.1.42",
        &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("a valid resolution must be observed");

    let DiscoveryEvent::Observed(observation) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(observation.device_id(), Some(device(0x11)));
    assert_eq!(
        observation.display_name().map(DisplayName::as_str),
        Some("Alice's laptop")
    );
    assert_eq!(observation.capabilities(), Capabilities::DIRECT_QUIC);
    assert_eq!(
        observation.id(),
        &ObservationId::new(
            MDNS_SOURCE_ID,
            ObservationKey::new(&fullname("device-a")).expect("valid key")
        )
    );
}

// --- ServiceRemoved -> Lost ---

#[test]
fn a_removed_service_yields_lost_keyed_by_the_same_fullname_as_a_resolution() {
    let (tx, rx) = flume::unbounded();
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-b",
        51820,
        "192.168.1.43",
        &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);
    let observed = poll_ready(&mut source).expect("a valid resolution must be observed");
    let DiscoveryEvent::Observed(observation) = observed else {
        panic!("expected Observed");
    };
    let observed_id = observation.id().clone();

    let (tx2, rx2) = flume::unbounded();
    tx2.send(ServiceEvent::ServiceRemoved(
        SERVICE_TYPE.to_string(),
        fullname("device-b"),
    ))
    .expect("channel accepts a send before receive");
    let mut removed_source = MdnsSource::new(rx2);
    let removed = poll_ready(&mut removed_source).expect("a removal must be reported");

    let DiscoveryEvent::Lost(lost_id) = removed else {
        panic!("expected Lost, got {removed:?}");
    };
    // The point of this test: removal and resolution must agree on the
    // same `ObservationId`, not merely on equal-looking parts of it.
    assert_eq!(lost_id, observed_id);
}

// --- Events with no DiscoveryEvent counterpart are skipped ---

#[test]
fn search_started_and_service_found_are_skipped_before_a_resolution_is_returned() {
    let (tx, rx) = flume::unbounded();
    tx.send(ServiceEvent::SearchStarted(SERVICE_TYPE.to_string()))
        .expect("channel accepts a send before receive");
    tx.send(ServiceEvent::ServiceFound(
        SERVICE_TYPE.to_string(),
        fullname("device-c"),
    ))
    .expect("channel accepts a send before receive");
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-c",
        51820,
        "192.168.1.44",
        &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("the resolution must still be reached");

    assert!(matches!(event, DiscoveryEvent::Observed(_)));
}

// --- A malformed TXT record is skipped, not fatal ---

#[test]
fn a_malformed_txt_record_is_skipped_and_the_next_valid_resolution_is_returned() {
    let (tx, rx) = flume::unbounded();
    // Missing "id" and "pk": `TxtRecord::parse` must refuse this.
    let malformed_pairs = vec![
        ("v".to_string(), "1".to_string()),
        ("p".to_string(), "linux".to_string()),
        ("c".to_string(), "0".to_string()),
    ];
    tx.send(ServiceEvent::ServiceResolved(Box::new(
        resolved_with_pairs("device-d", 51820, "192.168.1.45", &malformed_pairs),
    )))
    .expect("channel accepts a send before receive");
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-e",
        51820,
        "192.168.1.46",
        &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("the valid resolution must still be reached");

    let DiscoveryEvent::Observed(observation) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(
        observation.id(),
        &ObservationId::new(
            MDNS_SOURCE_ID,
            ObservationKey::new(&fullname("device-e")).expect("valid key")
        )
    );
}

// --- A disconnected sender is a real error ---

#[test]
fn a_disconnected_sender_yields_closed() {
    let (tx, rx) = flume::unbounded::<ServiceEvent>();
    drop(tx);
    let mut source = MdnsSource::new(rx);

    let result = poll_ready(&mut source);

    assert_eq!(result, Err(DiscoveryError::Closed));
}

// --- Address formatting (docs/03, DCR-048) ---

#[test]
fn an_ipv4_address_formats_with_no_brackets() {
    let (tx, rx) = flume::unbounded();
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-f", 51820, "1.2.3.4", &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("a valid resolution must be observed");

    let DiscoveryEvent::Observed(observation) = event else {
        panic!("expected Observed");
    };
    let candidates = observation.candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].address(), "1.2.3.4:51820");
    assert_eq!(candidates[0].transport(), TransportId::new("direct-quic"));
}

#[test]
fn a_global_ipv6_address_has_no_scope_and_parses_as_a_socket_addr() {
    let (tx, rx) = flume::unbounded();
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-g",
        51820,
        "2001:db8::1",
        &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("a valid resolution must be observed");

    let DiscoveryEvent::Observed(observation) = event else {
        panic!("expected Observed");
    };
    let candidates = observation.candidates();
    assert_eq!(candidates.len(), 1);
    let address = candidates[0].address();
    assert_eq!(address, "[2001:db8::1]:51820");
    assert!(address.parse::<SocketAddr>().is_ok());
}

// --- No usable address is still an observation ---

#[test]
fn a_resolution_with_no_addresses_still_yields_observed_with_an_empty_candidate_list() {
    let (tx, rx) = flume::unbounded();
    let record = valid_record();
    tx.send(ServiceEvent::ServiceResolved(Box::new(resolved(
        "device-h", 51820, "", &record,
    ))))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("an observation with no addresses is still valid");

    let DiscoveryEvent::Observed(observation) = event else {
        panic!("expected Observed");
    };
    assert!(observation.candidates().is_empty());
}

// --- An unrecognised v does not hide the peer ---

#[test]
fn an_unrecognised_protocol_version_still_yields_observed() {
    let (tx, rx) = flume::unbounded();
    let record = valid_record();
    let mut pairs = record.to_pairs();
    let v = pairs
        .iter_mut()
        .find(|(k, _)| k == "v")
        .expect("to_pairs always emits v");
    v.1 = "99".to_string();
    tx.send(ServiceEvent::ServiceResolved(Box::new(
        resolved_with_pairs("device-i", 51820, "192.168.1.47", &pairs),
    )))
    .expect("channel accepts a send before receive");
    let mut source = MdnsSource::new(rx);

    let event = poll_ready(&mut source).expect("an unrecognised v must not hide the peer");

    assert!(matches!(event, DiscoveryEvent::Observed(_)));
}

// --- instance_name ---

struct FixedRng {
    bytes: [u8; 4],
}

impl Rng for FixedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.copy_from_slice(&self.bytes);
        Ok(())
    }
}

#[test]
fn instance_name_renders_four_bytes_as_eight_lowercase_hex_characters() {
    let rng = FixedRng {
        bytes: [0xde, 0xad, 0xbe, 0xef],
    };

    let name = instance_name(&rng).expect("fixed rng never fails");

    assert_eq!(name, "deadbeef");
}

// --- advertisement ---

#[test]
fn advertisement_txt_properties_round_trip_through_txt_record_parse() {
    let record = valid_record();

    let info = advertisement("abc123ef", 51820, &record).expect("valid service info");

    let pairs: Vec<(String, String)> = info
        .get_properties()
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect();
    let parsed = TxtRecord::parse(&pairs).expect("advertised properties must round-trip");
    assert_eq!(parsed, record);
}

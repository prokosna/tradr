//! Critical Module tests for the Static Peer registry (CLAUDE.md section
//! 6, docs/03's "The pin"). Written by the Supervisor before the
//! implementation exists: a registry handing back `Unpinned` for a pinned
//! entry authenticates a hijacked address to whatever key answers, and
//! every signature that impostor makes is valid, so nothing notices.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use tradr_core::{
    DeviceId, DiscoveryEvent, DiscoverySource, ObservationId, ObservationKey, PeerExpectation, Rng,
    RngError, SourceId, TransportId,
};
use tradr_discovery::{
    STATIC_PEER_DEFAULT_PORT, STATIC_PEER_SOURCE_ID, StaticPeerError, StaticPeerId,
    StaticPeerRegistry, StaticPeerSource,
};

// Each test gets a path of its own so nothing depends on execution order
// (rule E2). The counter distinguishes tests inside one binary; the
// process id distinguishes concurrent runs of that binary.
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "tradr-static-peers-{}-{n}.json",
        std::process::id()
    ));
    let _remove = std::fs::remove_file(&path);
    path
}

// Fills every byte with a fixed value, so an entry's generated id is
// exactly predictable and a test can name it.
struct FixedRng(u8);

impl Rng for FixedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(self.0);
        Ok(())
    }
}

fn device(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; 16]).expect("16 bytes is a Device ID")
}

fn drain(source: &mut StaticPeerSource) -> Vec<DiscoveryEvent> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime builds");
    let mut events = Vec::new();
    // Every event this source produces is already queued by the call that
    // produced it, so a zero-length poll drains without waiting on a clock
    // (rule E3).
    runtime.block_on(async {
        while let Ok(Ok(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(5), source.next_event()).await
        {
            events.push(event);
        }
    });
    events
}

fn observation_id(id: &StaticPeerId) -> ObservationId {
    ObservationId::new(
        STATIC_PEER_SOURCE_ID,
        ObservationKey::new(id.as_str()).expect("a peer id is a valid observation key"),
    )
}

// --- The pin decides the expectation, and that is the whole point ---

#[test]
fn an_entry_with_no_pin_expects_nothing_and_says_so() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(
            Some("Home desktop"),
            &["192.168.10.5:21820".into()],
            &FixedRng(0x11),
        )
        .expect("an entry with one endpoint is valid");

    assert_eq!(registry.expectation(&id), Some(PeerExpectation::Unpinned));
}

#[test]
fn a_pinned_entry_expects_exactly_the_device_it_pinned() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x11))
        .expect("an entry with one endpoint is valid");

    registry
        .pin(&id, device(0xab))
        .expect("a first pin is accepted");

    assert_eq!(
        registry.expectation(&id),
        Some(PeerExpectation::Device(device(0xab)))
    );
}

#[test]
fn a_pin_survives_a_reload_from_disk() {
    let path = scratch_path();
    let id = {
        let (mut registry, _source) =
            StaticPeerRegistry::load(&path).expect("a missing file loads");
        let id = registry
            .add(
                Some("Home desktop"),
                &["desktop.example:21820".into()],
                &FixedRng(0x22),
            )
            .expect("an entry with one endpoint is valid");
        registry
            .pin(&id, device(0xcd))
            .expect("a first pin is accepted");
        id
    };

    let (reloaded, _source) = StaticPeerRegistry::load(&path).expect("a written file reloads");

    assert_eq!(
        reloaded.expectation(&id),
        Some(PeerExpectation::Device(device(0xcd))),
        "a pin that does not survive a restart silently becomes Unpinned"
    );
}

#[test]
fn a_second_pin_naming_a_different_device_is_refused_and_changes_nothing() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x11))
        .expect("an entry with one endpoint is valid");
    registry
        .pin(&id, device(0xab))
        .expect("a first pin is accepted");

    let refused = registry.pin(&id, device(0x01));

    assert!(matches!(refused, Err(StaticPeerError::AlreadyPinned)));
    assert_eq!(
        registry.expectation(&id),
        Some(PeerExpectation::Device(device(0xab))),
        "a refused pin must not have overwritten the one that was there"
    );
}

#[test]
fn pinning_the_same_device_again_is_accepted_and_changes_nothing() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x11))
        .expect("an entry with one endpoint is valid");
    registry
        .pin(&id, device(0xab))
        .expect("a first pin is accepted");

    registry
        .pin(&id, device(0xab))
        .expect("re-pinning the same device is the caller connecting twice, not a mismatch");

    assert_eq!(
        registry.expectation(&id),
        Some(PeerExpectation::Device(device(0xab)))
    );
}

#[test]
fn an_unknown_entry_has_no_expectation_at_all() {
    let path = scratch_path();
    let (registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let absent = StaticPeerId::new(&"ab".repeat(16)).expect("32 hex characters is an id");

    assert_eq!(registry.expectation(&absent), None);
}

#[test]
fn removing_a_pinned_entry_removes_its_pin_with_it() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x11))
        .expect("an entry with one endpoint is valid");
    registry
        .pin(&id, device(0xab))
        .expect("a first pin is accepted");

    registry
        .remove(&id)
        .expect("an entry that exists is removable");

    assert_eq!(registry.expectation(&id), None);
}

// --- A malformed file must never be read as an empty one ---

#[test]
fn a_missing_file_is_an_empty_registry_rather_than_an_error() {
    let path = scratch_path();

    let (registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    assert!(registry.entries().is_empty());
}

#[test]
fn a_malformed_file_is_refused_rather_than_replaced_with_an_empty_one() {
    let path = scratch_path();
    std::fs::write(&path, b"{ this is not the file we wrote }")
        .expect("the scratch path is writable");

    let refused = StaticPeerRegistry::load(&path);

    assert!(
        matches!(refused, Err(StaticPeerError::Malformed(_))),
        "starting over deletes every pin the user holds"
    );
    let after = std::fs::read(&path).expect("the file is still there");
    assert_eq!(after, b"{ this is not the file we wrote }");
}

// --- What the source reports, and when ---

#[test]
fn a_hand_edited_endpoint_no_transport_can_parse_is_refused_with_the_file() {
    let path = scratch_path();
    // What `add` refuses, a text editor can still write. docs/03: an
    // endpoint no transport can parse is a peer that silently never
    // connects, and dropping it leaves an entry with no candidate at all.
    let json = format!(
        "{{\"entries\":[{{\"id\":\"{}\",\"label\":null,\"endpoints\":[\"192.168.10.5:21820{}\"],\"expect_device_id\":null}}]}}",
        "a".repeat(32),
        "\\u0007"
    );
    std::fs::write(&path, json.as_bytes()).expect("the scratch path is writable");

    let refused = StaticPeerRegistry::load(&path);

    assert!(
        matches!(refused, Err(StaticPeerError::Malformed(_))),
        "an entry observed with no candidate is a peer that can never be dialled and never says why"
    );
}

#[test]
fn adding_an_entry_observes_it_with_one_candidate_per_endpoint() {
    let path = scratch_path();
    let (mut registry, mut source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    let id = registry
        .add(
            Some("Home desktop"),
            &[
                "desktop.tail9f3c.ts.net:21820".into(),
                "192.168.10.5:21820".into(),
            ],
            &FixedRng(0x33),
        )
        .expect("an entry with two endpoints is valid");

    let events = drain(&mut source);
    let [DiscoveryEvent::Observed(observation)] = events.as_slice() else {
        panic!("adding an entry reports exactly one Observed, got {events:?}");
    };
    assert_eq!(observation.id(), &observation_id(&id));
    assert_eq!(observation.device_id(), None);
    assert_eq!(observation.candidates().len(), 2);
    for candidate in observation.candidates() {
        assert_eq!(candidate.transport(), TransportId::new("direct-quic"));
    }
    assert_eq!(
        observation.display_name().map(|n| n.as_str()),
        Some("Home desktop")
    );
}

#[test]
fn pinning_re_reports_the_same_observation_with_the_device_id_present() {
    let path = scratch_path();
    let (mut registry, mut source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x11))
        .expect("an entry with one endpoint is valid");
    let _add = drain(&mut source);

    registry
        .pin(&id, device(0xab))
        .expect("a first pin is accepted");

    let events = drain(&mut source);
    let [DiscoveryEvent::Observed(observation)] = events.as_slice() else {
        panic!("a pin reports exactly one Observed, got {events:?}");
    };
    assert_eq!(
        observation.id(),
        &observation_id(&id),
        "a re-report under a new id would leave two peers where there is one"
    );
    assert_eq!(observation.device_id(), Some(device(0xab)));
}

#[test]
fn removing_an_entry_loses_the_observation_it_was_reported_under() {
    let path = scratch_path();
    let (mut registry, mut source) = StaticPeerRegistry::load(&path).expect("a missing file loads");
    let id = registry
        .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x11))
        .expect("an entry with one endpoint is valid");
    let _add = drain(&mut source);

    registry
        .remove(&id)
        .expect("an entry that exists is removable");

    let events = drain(&mut source);
    assert_eq!(events, vec![DiscoveryEvent::Lost(observation_id(&id))]);
}

#[test]
fn a_loaded_registry_reports_every_entry_it_read_from_disk() {
    let path = scratch_path();
    let id = {
        let (mut registry, _source) =
            StaticPeerRegistry::load(&path).expect("a missing file loads");
        registry
            .add(None, &["192.168.10.5:21820".into()], &FixedRng(0x44))
            .expect("an entry with one endpoint is valid")
    };

    let (_registry, mut source) = StaticPeerRegistry::load(&path).expect("a written file reloads");

    let events = drain(&mut source);
    let [DiscoveryEvent::Observed(observation)] = events.as_slice() else {
        panic!("a loaded entry is reported once, got {events:?}");
    };
    assert_eq!(observation.id(), &observation_id(&id));
}

#[test]
fn the_source_names_itself_and_nothing_else() {
    let path = scratch_path();
    let (_registry, source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    assert_eq!(source.id(), STATIC_PEER_SOURCE_ID);
    assert_ne!(source.id(), SourceId::new("mdns"));
}

// --- An endpoint reaches the transport carrying a port ---

#[test]
fn an_endpoint_with_no_port_is_given_the_default_one() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    let id = registry
        .add(
            None,
            &[
                "desktop.tail9f3c.ts.net".into(),
                "192.168.10.5".into(),
                "fd7a:115c::1".into(),
            ],
            &FixedRng(0x55),
        )
        .expect("three endpoints with no port are valid");

    let entry = registry.entry(&id).expect("the entry was just added");
    let endpoints: Vec<&str> = entry.endpoints().iter().map(|e| e.as_str()).collect();
    assert!(
        endpoints.contains(&format!("desktop.tail9f3c.ts.net:{STATIC_PEER_DEFAULT_PORT}").as_str())
    );
    assert!(endpoints.contains(&format!("192.168.10.5:{STATIC_PEER_DEFAULT_PORT}").as_str()));
    assert!(
        endpoints.contains(&format!("[fd7a:115c::1]:{STATIC_PEER_DEFAULT_PORT}").as_str()),
        "an unbracketed IPv6 literal is ambiguous once a port is appended, got {endpoints:?}"
    );
}

#[test]
fn an_endpoint_that_already_names_a_port_keeps_it() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    let id = registry
        .add(
            None,
            &[
                "desktop.tail9f3c.ts.net:51820".into(),
                "192.168.10.5:9".into(),
                "[fd7a:115c::1]:9".into(),
            ],
            &FixedRng(0x66),
        )
        .expect("three endpoints with a port are valid");

    let entry = registry.entry(&id).expect("the entry was just added");
    assert_eq!(
        entry.endpoints(),
        &[
            "desktop.tail9f3c.ts.net:51820".to_string(),
            "192.168.10.5:9".to_string(),
            "[fd7a:115c::1]:9".to_string(),
        ]
    );
}

#[test]
fn an_entry_with_no_endpoint_at_all_is_refused() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    let refused = registry.add(Some("Nowhere"), &[], &FixedRng(0x77));

    assert!(matches!(refused, Err(StaticPeerError::NoEndpoints)));
}

#[test]
fn an_endpoint_carrying_a_control_character_is_refused() {
    let path = scratch_path();
    let (mut registry, _source) = StaticPeerRegistry::load(&path).expect("a missing file loads");

    let refused = registry.add(None, &["192.168.10.5:21820\u{7}".into()], &FixedRng(0x88));

    assert!(matches!(refused, Err(StaticPeerError::InvalidEndpoint(_))));
}

//! Tests for `BleSource`, `BleScanner`, and `ScanReport` (docs/03, ADR-0019).
//! No real Bluetooth radio, no wall clock, and no sleeping (rule E3).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tradr_core::{
    BoxFuture, Capabilities, Clock, DiscoveryError, DiscoveryEvent, DiscoverySource, Monotonic,
    ObservationId, ObservationKey, TransportId, UnixTime,
};
use tradr_discovery::{
    Advertisement, BLE_OBSERVATION_TTL_SECS, BLE_SOURCE_ID, BleError, BleScanner, BleSource,
    BroadcastSecret, BroadcastSecrets, EidWindow, PlatformCode, ScanReport, ScanReportError,
};

const BLE_GATT: TransportId = TransportId::new("ble-gatt");

struct FakeScanner {
    receiver: flume::Receiver<Result<ScanReport, BleError>>,
}

impl BleScanner for FakeScanner {
    fn next_report(&mut self) -> BoxFuture<'_, Result<ScanReport, BleError>> {
        Box::pin(async move {
            self.receiver
                .recv_async()
                .await
                .map_err(|_| BleError::Closed)?
        })
    }
}

#[derive(Clone)]
struct SharedSecrets {
    secrets: Arc<Mutex<Vec<BroadcastSecret>>>,
}

impl SharedSecrets {
    fn new(initial: Vec<BroadcastSecret>) -> Self {
        Self {
            secrets: Arc::new(Mutex::new(initial)),
        }
    }

    fn add(&self, secret: BroadcastSecret) {
        self.secrets
            .lock()
            .expect("secrets lock poisoned")
            .push(secret);
    }

    fn clear(&self) {
        self.secrets.lock().expect("secrets lock poisoned").clear();
    }
}

impl BroadcastSecrets for SharedSecrets {
    fn secrets(&self) -> Vec<BroadcastSecret> {
        self.secrets.lock().expect("secrets lock poisoned").clone()
    }
}

#[derive(Clone)]
struct SteppableClock {
    wall: Arc<AtomicI64>,
    base_instant: Instant,
    mono_offset: Arc<AtomicU64>,
}

impl SteppableClock {
    fn new(initial_wall_secs: i64) -> Self {
        Self {
            wall: Arc::new(AtomicI64::new(initial_wall_secs)),
            base_instant: Instant::now(),
            mono_offset: Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance_monotonic(&self, secs: u64) {
        self.mono_offset.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for SteppableClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.wall.load(Ordering::SeqCst))
    }

    fn monotonic_now(&self) -> Monotonic {
        let offset = Duration::from_secs(self.mono_offset.load(Ordering::SeqCst));
        Monotonic::from_instant(self.base_instant + offset)
    }
}

fn build_report(
    handle: &str,
    secret: &BroadcastSecret,
    window: EidWindow,
    capabilities: Capabilities,
) -> ScanReport {
    let eid = secret.eid(window);
    let ad = Advertisement::new(eid, PlatformCode::LINUX, capabilities);
    ScanReport::new(handle, &ad.service_data()).expect("valid scan report")
}

// Every test in this file drives BleSource off a channel it controls, so on
// the success path an event is already queued before this is awaited. The
// bound exists solely so a broken implementation that never produces an
// event fails the test instead of parking it forever (STATE.md open
// decision 22; precedent: tests/static_peer.rs).
const NEXT_EVENT_BOUND: Duration = Duration::from_secs(5);

async fn next_event(source: &mut BleSource) -> Result<DiscoveryEvent, DiscoveryError> {
    tokio::time::timeout(NEXT_EVENT_BOUND, source.next_event())
        .await
        .expect("BleSource::next_event did not complete within the test bound")
}

#[tokio::test]
async fn current_window_advertisement_is_observed_with_expected_fields() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secret = BroadcastSecret::bootstrap(b"account-test-1");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock.clone()));

    let window = EidWindow::containing(clock.now());
    let caps =
        Capabilities::from_bits(Capabilities::BLE_GATT.bits() | Capabilities::DIRECT_QUIC.bits());
    let report = build_report("dev-handle-1", &secret, window, caps);
    tx.send(Ok(report)).expect("send report");

    let event = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs) = event else {
        panic!("expected Observed, got {event:?}");
    };

    let expected_key = ObservationKey::new("dev-handle-1").expect("valid key");
    let expected_id = ObservationId::new(BLE_SOURCE_ID, expected_key);

    assert_eq!(obs.id(), &expected_id);
    assert_eq!(obs.device_id(), None);
    assert_eq!(obs.display_name(), None);
    assert_eq!(obs.capabilities(), caps);
    assert_eq!(obs.candidates().len(), 1);
    assert_eq!(obs.candidates()[0].transport(), BLE_GATT);
    assert_eq!(obs.candidates()[0].address(), "dev-handle-1");
}

#[tokio::test]
async fn window_matching_accepts_t_minus_1_and_rejects_t_minus_2() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secret = BroadcastSecret::bootstrap(b"account-test-2");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock.clone()));

    let current = EidWindow::containing(clock.now());
    let t_minus_1 = EidWindow::from_index(current.index() - 1);
    let t_minus_2 = EidWindow::from_index(current.index() - 2);

    let report_t_minus_2 = build_report(
        "handle-t-minus-2",
        &secret,
        t_minus_2,
        Capabilities::BLE_GATT,
    );
    let report_t_minus_1 = build_report(
        "handle-t-minus-1",
        &secret,
        t_minus_1,
        Capabilities::BLE_GATT,
    );

    tx.send(Ok(report_t_minus_2)).expect("send t-2");
    tx.send(Ok(report_t_minus_1)).expect("send t-1");

    let event = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(obs.id().key().as_str(), "handle-t-minus-1");
}

#[tokio::test]
async fn unmatched_secret_produces_no_event_and_source_continues() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let held_secret = BroadcastSecret::bootstrap(b"held-account");
    let stranger_secret = BroadcastSecret::bootstrap(b"stranger-account");
    let secrets = Box::new(SharedSecrets::new(vec![held_secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock.clone()));

    let window = EidWindow::containing(clock.now());
    let stranger_report = build_report(
        "handle-stranger",
        &stranger_secret,
        window,
        Capabilities::BLE_GATT,
    );
    let friend_report = build_report(
        "handle-friend",
        &held_secret,
        window,
        Capabilities::BLE_GATT,
    );

    tx.send(Ok(stranger_report)).expect("send stranger");
    tx.send(Ok(friend_report)).expect("send friend");

    let event = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(obs.id().key().as_str(), "handle-friend");
}

#[tokio::test]
async fn unknown_version_byte_produces_no_event_and_source_continues() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secret = BroadcastSecret::bootstrap(b"account-test-3");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock.clone()));

    let window = EidWindow::containing(clock.now());
    let mut bad_payload = [0x99; 10];
    bad_payload[1..9].copy_from_slice(secret.eid(window).as_bytes());
    let bad_report = ScanReport::new("handle-bad-version", &bad_payload).expect("valid report");

    let good_report = build_report("handle-good", &secret, window, Capabilities::BLE_GATT);

    tx.send(Ok(bad_report)).expect("send bad report");
    tx.send(Ok(good_report)).expect("send good report");

    let event = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(obs.id().key().as_str(), "handle-good");
}

#[tokio::test]
async fn broadcast_secrets_queried_per_report_rather_than_cached() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secrets_provider = SharedSecrets::new(vec![]);
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(
        scanner,
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
    );

    let window = EidWindow::containing(clock.now());
    let late_secret = BroadcastSecret::bootstrap(b"late-arriving-account");
    let late_report = build_report("handle-late", &late_secret, window, Capabilities::BLE_GATT);

    secrets_provider.add(late_secret);
    tx.send(Ok(late_report)).expect("send late report");

    let event = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(obs.id().key().as_str(), "handle-late");

    secrets_provider.clear();

    let removed_report = build_report(
        "handle-after-removal",
        &late_secret,
        window,
        Capabilities::BLE_GATT,
    );
    let new_secret = BroadcastSecret::bootstrap(b"new-secret-account");
    let new_report = build_report("handle-new", &new_secret, window, Capabilities::BLE_GATT);

    secrets_provider.add(new_secret);
    tx.send(Ok(removed_report)).expect("send removed report");
    tx.send(Ok(new_report)).expect("send new report");

    let event = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs) = event else {
        panic!("expected Observed, got {event:?}");
    };
    assert_eq!(obs.id().key().as_str(), "handle-new");
}

#[tokio::test]
async fn identical_advertisement_is_suppressed_and_capability_change_emits() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secret = BroadcastSecret::bootstrap(b"account-test-4");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock.clone()));

    let window = EidWindow::containing(clock.now());
    let rep1 = build_report("handle-dup", &secret, window, Capabilities::BLE_GATT);
    let rep_dup = build_report("handle-dup", &secret, window, Capabilities::BLE_GATT);
    let rep_other = build_report("handle-other", &secret, window, Capabilities::BLE_GATT);

    tx.send(Ok(rep1)).expect("send rep1");
    let event1 = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs1) = event1 else {
        panic!("expected Observed, got {event1:?}");
    };
    assert_eq!(obs1.id().key().as_str(), "handle-dup");

    tx.send(Ok(rep_dup)).expect("send duplicate");
    tx.send(Ok(rep_other)).expect("send other");

    let event2 = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs2) = event2 else {
        panic!("expected Observed, got {event2:?}");
    };
    assert_eq!(obs2.id().key().as_str(), "handle-other");

    let rep_changed = build_report(
        "handle-dup",
        &secret,
        window,
        Capabilities::from_bits(Capabilities::BLE_GATT.bits() | Capabilities::DIRECT_QUIC.bits()),
    );
    tx.send(Ok(rep_changed)).expect("send changed");

    let event3 = next_event(&mut source).await.expect("observation expected");
    let DiscoveryEvent::Observed(obs3) = event3 else {
        panic!("expected Observed, got {event3:?}");
    };
    assert_eq!(obs3.id().key().as_str(), "handle-dup");
    assert_eq!(
        obs3.capabilities(),
        Capabilities::from_bits(Capabilities::BLE_GATT.bits() | Capabilities::DIRECT_QUIC.bits())
    );
}

#[tokio::test]
async fn age_out_emits_lost_after_ttl_and_not_before() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secret = BroadcastSecret::bootstrap(b"account-test-5");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock.clone()));

    let window = EidWindow::containing(clock.now());
    let rep_a = build_report("handle-a", &secret, window, Capabilities::BLE_GATT);
    tx.send(Ok(rep_a)).expect("send a");

    let event_a = next_event(&mut source).await.expect("observe a");
    assert!(matches!(event_a, DiscoveryEvent::Observed(_)));

    // Step clock by TTL - 1: handle-a has not aged out.
    clock.advance_monotonic(BLE_OBSERVATION_TTL_SECS - 1);
    let rep_b = build_report("handle-b", &secret, window, Capabilities::BLE_GATT);
    tx.send(Ok(rep_b)).expect("send b");

    let event_b = next_event(&mut source).await.expect("observe b");
    let DiscoveryEvent::Observed(obs_b) = event_b else {
        panic!("expected Observed b, got {event_b:?}");
    };
    assert_eq!(obs_b.id().key().as_str(), "handle-b");

    // Advance clock past TTL: handle-a was seen TTL + 1 ago.
    clock.advance_monotonic(2);
    let rep_c = build_report("handle-c", &secret, window, Capabilities::BLE_GATT);
    tx.send(Ok(rep_c)).expect("send c");

    let event_lost = next_event(&mut source).await.expect("lost event expected");
    let DiscoveryEvent::Lost(lost_id) = event_lost else {
        panic!("expected Lost, got {event_lost:?}");
    };
    assert_eq!(lost_id.key().as_str(), "handle-a");

    let event_c = next_event(&mut source).await.expect("observe c");
    let DiscoveryEvent::Observed(obs_c) = event_c else {
        panic!("expected Observed c, got {event_c:?}");
    };
    assert_eq!(obs_c.id().key().as_str(), "handle-c");
}

#[tokio::test]
async fn scanner_errors_are_narrowed_to_discovery_errors() {
    let (tx, rx) = flume::unbounded();
    let scanner = Box::new(FakeScanner { receiver: rx });
    let secrets = Box::new(SharedSecrets::new(vec![]));
    let clock = SteppableClock::new(1_700_000_000);
    let mut source = BleSource::new(scanner, secrets, Box::new(clock));

    tx.send(Err(BleError::PermissionDenied))
        .expect("send perm err");
    let err1 = next_event(&mut source).await.expect_err("must error");
    assert_eq!(
        err1,
        DiscoveryError::Io(std::io::ErrorKind::PermissionDenied)
    );

    tx.send(Err(BleError::Closed)).expect("send closed");
    let err2 = next_event(&mut source).await.expect_err("must error");
    assert_eq!(err2, DiscoveryError::Closed);

    // docs/03: Unsupported is what a platform reports when it cannot take
    // the BLE peripheral role, the value Change Drill D4's scan-only retreat
    // depends on, so it must not be narrowed to something else unnoticed.
    tx.send(Err(BleError::Unsupported))
        .expect("send unsupported");
    let err3 = next_event(&mut source).await.expect_err("must error");
    assert_eq!(err3, DiscoveryError::Io(std::io::ErrorKind::Unsupported));

    tx.send(Err(BleError::AdapterUnavailable))
        .expect("send adapter unavailable");
    let err4 = next_event(&mut source).await.expect_err("must error");
    assert_eq!(err4, DiscoveryError::Io(std::io::ErrorKind::NotConnected));
}

#[test]
fn scan_report_constructor_validates_handle_and_length() {
    let valid_data = [0u8; 10];
    assert!(ScanReport::new("valid-handle", &valid_data).is_ok());

    let empty = ScanReport::new("", &valid_data);
    assert!(matches!(empty, Err(ScanReportError::InvalidHandle(_))));

    let control = ScanReport::new("bad\nhandle", &valid_data);
    assert!(matches!(control, Err(ScanReportError::InvalidHandle(_))));

    let short_data = [0u8; 9];
    let short = ScanReport::new("valid-handle", &short_data);
    assert_eq!(
        short,
        Err(ScanReportError::WrongLength {
            expected: 10,
            actual: 9,
        })
    );

    let long_data = [0u8; 11];
    let long = ScanReport::new("valid-handle", &long_data);
    assert_eq!(
        long,
        Err(ScanReportError::WrongLength {
            expected: 10,
            actual: 11,
        })
    );
}

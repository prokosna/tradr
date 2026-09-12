#![forbid(unsafe_code)]
//! Tests for BleDiscovery and event_line in the composition root (WI-M7-007o, DCR-107).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri_plugin_tradr::ble_source::{BleDiscovery, event_line};
use tradr_core::{
    BoxFuture, Capabilities, Clock, DiscoveryEvent, Monotonic, ObservationId, ObservationKey,
    PeerList, PeerObservation, UnixTime,
};
use tradr_discovery::{
    Advertisement, BLE_OBSERVATION_TTL_SECS, BLE_SOURCE_ID, BleError, BleScanner, BroadcastSecret,
    BroadcastSecrets, EidWindow, PlatformCode, ScanReport,
};

#[derive(Clone, Default)]
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
            .expect("shared secrets lock poisoned")
            .push(secret);
    }
}

impl BroadcastSecrets for SharedSecrets {
    fn secrets(&self) -> Vec<BroadcastSecret> {
        self.secrets
            .lock()
            .expect("shared secrets lock poisoned")
            .clone()
    }

    fn advertised(&self) -> Vec<BroadcastSecret> {
        self.secrets()
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

#[derive(Clone)]
struct ScannerParkGate {
    parked: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl ScannerParkGate {
    fn new() -> Self {
        Self {
            parked: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn wait_for_park(&self) {
        self.parked.notified().await;
    }

    fn release(&self) {
        self.release.notify_one();
    }
}

enum ScannerAction {
    Report(ScanReport),
    AdvanceMonotonic(u64),
    AddSecret(BroadcastSecret),
    Park,
    Fail(BleError),
}

struct ScriptedScanner {
    clock: SteppableClock,
    shared_secrets: Option<SharedSecrets>,
    park_gate: Option<ScannerParkGate>,
    steps: VecDeque<ScannerAction>,
}

impl ScriptedScanner {
    fn new(clock: SteppableClock, steps: Vec<ScannerAction>) -> Self {
        Self {
            clock,
            shared_secrets: None,
            park_gate: None,
            steps: VecDeque::from(steps),
        }
    }

    fn with_shared_secrets(
        clock: SteppableClock,
        shared_secrets: SharedSecrets,
        steps: Vec<ScannerAction>,
    ) -> Self {
        Self {
            clock,
            shared_secrets: Some(shared_secrets),
            park_gate: None,
            steps: VecDeque::from(steps),
        }
    }

    fn with_park_gate(
        clock: SteppableClock,
        park_gate: ScannerParkGate,
        steps: Vec<ScannerAction>,
    ) -> Self {
        Self {
            clock,
            shared_secrets: None,
            park_gate: Some(park_gate),
            steps: VecDeque::from(steps),
        }
    }
}

impl BleScanner for ScriptedScanner {
    fn next_report(&mut self) -> BoxFuture<'_, Result<ScanReport, BleError>> {
        Box::pin(async move {
            loop {
                match self.steps.pop_front() {
                    Some(ScannerAction::AdvanceMonotonic(secs)) => {
                        self.clock.advance_monotonic(secs);
                    }
                    Some(ScannerAction::AddSecret(secret)) => {
                        if let Some(ref secrets) = self.shared_secrets {
                            secrets.add(secret);
                        }
                    }
                    Some(ScannerAction::Park) => {
                        if let Some(ref gate) = self.park_gate {
                            gate.parked.notify_one();
                            gate.release.notified().await;
                        }
                    }
                    Some(ScannerAction::Report(report)) => {
                        return Ok(report);
                    }
                    Some(ScannerAction::Fail(err)) => {
                        return Err(err);
                    }
                    None => {
                        panic!(
                            "the scanner script ran out: the pump asked for a report after its last step"
                        );
                    }
                }
            }
        })
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

#[tokio::test]
async fn run_with_unsupported_error_returns_leaving_peer_list_empty() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let secrets = Box::new(SharedSecrets::default());
    let discovery = BleDiscovery::new(secrets, Box::new(clock), peers.clone());

    discovery.run(Err(BleError::Unsupported)).await;

    let list = peers.lock().await;
    assert!(list.peers().is_empty());
}

#[tokio::test]
async fn single_matching_report_leaves_one_peer_with_ble_gatt_candidate() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let secret = BroadcastSecret::bootstrap(b"account-test-1");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let window = EidWindow::containing(clock.now());
    let report = build_report("dev-handle-1", &secret, window, Capabilities::BLE_GATT);

    let scanner = ScriptedScanner::new(
        clock.clone(),
        vec![
            ScannerAction::Report(report),
            ScannerAction::Fail(BleError::Closed),
        ],
    );

    let discovery = BleDiscovery::new(secrets, Box::new(clock), peers.clone());
    discovery.run(Ok(Box::new(scanner))).await;

    let list = peers.lock().await;
    let peer_entries = list.peers();
    assert_eq!(peer_entries.len(), 1);
    let peer = &peer_entries[0];
    assert_eq!(peer.candidates().len(), 1);
    let candidate = &peer.candidates()[0];
    assert_eq!(candidate.transport().as_str(), "ble-gatt");
    assert_eq!(candidate.address(), "dev-handle-1");
}

#[tokio::test]
async fn unmatched_report_is_skipped_and_subsequent_matching_report_is_listed() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let held_secret = BroadcastSecret::bootstrap(b"held-account");
    let unheld_secret = BroadcastSecret::bootstrap(b"unheld-account");
    let secrets = Box::new(SharedSecrets::new(vec![held_secret]));
    let window = EidWindow::containing(clock.now());

    let unmatched_report = build_report(
        "unmatched-handle",
        &unheld_secret,
        window,
        Capabilities::BLE_GATT,
    );
    let matched_report = build_report(
        "matched-handle",
        &held_secret,
        window,
        Capabilities::BLE_GATT,
    );

    let scanner = ScriptedScanner::new(
        clock.clone(),
        vec![
            ScannerAction::Report(unmatched_report),
            ScannerAction::Report(matched_report),
            ScannerAction::Fail(BleError::Closed),
        ],
    );

    let discovery = BleDiscovery::new(secrets, Box::new(clock), peers.clone());
    discovery.run(Ok(Box::new(scanner))).await;

    let list = peers.lock().await;
    let peer_entries = list.peers();
    assert_eq!(peer_entries.len(), 1);
    let peer = &peer_entries[0];
    assert_eq!(peer.candidates().len(), 1);
    assert_eq!(peer.candidates()[0].address(), "matched-handle");
}

#[tokio::test]
async fn non_closed_error_terminates_run_without_processing_subsequent_reports() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let secret = BroadcastSecret::bootstrap(b"account-test-error-terminates");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let window = EidWindow::containing(clock.now());
    let report_a = build_report("handle-a", &secret, window, Capabilities::BLE_GATT);
    let report_b = build_report("handle-b", &secret, window, Capabilities::BLE_GATT);

    let scanner = ScriptedScanner::new(
        clock.clone(),
        vec![
            ScannerAction::Report(report_a),
            ScannerAction::Fail(BleError::Io(std::io::ErrorKind::NotConnected)),
            ScannerAction::Report(report_b),
        ],
    );

    let discovery = BleDiscovery::new(secrets, Box::new(clock), peers.clone());
    discovery.run(Ok(Box::new(scanner))).await;

    let list = peers.lock().await;
    let peer_entries = list.peers();
    assert_eq!(peer_entries.len(), 1);
    assert_eq!(peer_entries[0].candidates().len(), 1);
    assert_eq!(peer_entries[0].candidates()[0].address(), "handle-a");
}

#[tokio::test]
async fn peer_list_lock_is_not_held_across_next_event() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let secret = BroadcastSecret::bootstrap(b"account-test-park");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let window = EidWindow::containing(clock.now());
    let report = build_report("handle-park", &secret, window, Capabilities::BLE_GATT);

    let gate = ScannerParkGate::new();
    let scanner = ScriptedScanner::with_park_gate(
        clock.clone(),
        gate.clone(),
        vec![
            ScannerAction::Report(report),
            ScannerAction::Park,
            ScannerAction::Fail(BleError::Closed),
        ],
    );

    let discovery = BleDiscovery::new(secrets, Box::new(clock), peers.clone());
    let task = tokio::spawn(async move {
        discovery.run(Ok(Box::new(scanner))).await;
    });

    gate.wait_for_park().await;

    let locked = peers.try_lock();
    assert!(
        locked.is_ok(),
        "peer list lock must not be held across next_event"
    );
    let list = locked.expect("unlocked peer list");
    assert_eq!(list.peers().len(), 1);
    assert_eq!(list.peers()[0].candidates()[0].address(), "handle-park");
    drop(list);

    gate.release();
    task.await.expect("discovery task completed");
}

#[tokio::test]
async fn handle_ages_out_after_ttl_when_second_handle_reports() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let secret = BroadcastSecret::bootstrap(b"account-test-ttl");
    let secrets = Box::new(SharedSecrets::new(vec![secret]));
    let window = EidWindow::containing(clock.now());

    let first_report = build_report("first-handle", &secret, window, Capabilities::BLE_GATT);
    let second_report = build_report("second-handle", &secret, window, Capabilities::BLE_GATT);

    let scanner = ScriptedScanner::new(
        clock.clone(),
        vec![
            ScannerAction::Report(first_report),
            ScannerAction::AdvanceMonotonic(BLE_OBSERVATION_TTL_SECS),
            ScannerAction::Report(second_report),
            ScannerAction::Fail(BleError::Closed),
        ],
    );

    let discovery = BleDiscovery::new(secrets, Box::new(clock), peers.clone());
    discovery.run(Ok(Box::new(scanner))).await;

    let list = peers.lock().await;
    let peer_entries = list.peers();
    assert_eq!(peer_entries.len(), 1);
    assert_eq!(peer_entries[0].candidates()[0].address(), "second-handle");
}

#[tokio::test]
async fn secret_set_read_per_report_recognizes_newly_added_secret() {
    let peers = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let clock = SteppableClock::new(1_700_000_000);
    let secret = BroadcastSecret::bootstrap(b"dynamically-added-secret");
    let shared_secrets = SharedSecrets::default();
    let window = EidWindow::containing(clock.now());

    let report1 = build_report("dynamic-handle", &secret, window, Capabilities::BLE_GATT);
    let report2 = build_report("dynamic-handle", &secret, window, Capabilities::BLE_GATT);

    let scanner = ScriptedScanner::with_shared_secrets(
        clock.clone(),
        shared_secrets.clone(),
        vec![
            ScannerAction::Report(report1),
            ScannerAction::AddSecret(secret),
            ScannerAction::Report(report2),
            ScannerAction::Fail(BleError::Closed),
        ],
    );

    let discovery = BleDiscovery::new(Box::new(shared_secrets), Box::new(clock), peers.clone());
    discovery.run(Ok(Box::new(scanner))).await;

    let list = peers.lock().await;
    let peer_entries = list.peers();
    assert_eq!(peer_entries.len(), 1);
    assert_eq!(peer_entries[0].candidates()[0].address(), "dynamic-handle");
}

#[test]
fn event_line_reports_handle_and_distinguishes_arrival_from_departure() {
    let key_obs = ObservationKey::new("handle-alpha").expect("valid observation key");
    let id_obs = ObservationId::new(BLE_SOURCE_ID, key_obs);
    let obs = PeerObservation::new(id_obs, vec![]);
    let arrival_event = DiscoveryEvent::Observed(obs);

    let key_lost = ObservationKey::new("handle-beta").expect("valid observation key");
    let id_lost = ObservationId::new(BLE_SOURCE_ID, key_lost);
    let departure_event = DiscoveryEvent::Lost(id_lost);

    let line_arrival = event_line(&arrival_event);
    let line_departure = event_line(&departure_event);

    assert_eq!(line_arrival, "ble discovery: arrival handle=handle-alpha");
    assert_eq!(
        line_departure,
        "ble discovery: departure handle=handle-beta"
    );
    assert_ne!(line_arrival, line_departure);
    assert!(line_arrival.starts_with("ble discovery: "));
    assert!(line_departure.starts_with("ble discovery: "));
}

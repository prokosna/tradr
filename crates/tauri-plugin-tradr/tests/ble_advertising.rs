#![forbid(unsafe_code)]
//! Tests for BLE advertising composition root (WI-M7-011, DCR-109).

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri_plugin_tradr::ble_advertising::{
    AdvertisingReporter, BleAdvertising, local_platform_code, slot_outcome,
};
use tradr_core::{BoxFuture, Capabilities, Clock, Monotonic, UnixTime};
use tradr_discovery::{
    BLE_ADVERTISED_SET_MAX, BLE_ADVERTISEMENT_SLOT_SECS, BleAdvertiser, BleError, BleRotation,
    BroadcastSecret, BroadcastSecrets, DeclaredCapabilities, EID_WINDOW_SECS, PlatformCode,
    SERVICE_DATA_LEN,
};

struct FakeAdvertiser {
    script: Arc<Mutex<VecDeque<Result<(), BleError>>>>,
    starts: Arc<AtomicUsize>,
}

impl FakeAdvertiser {
    fn new(script: Vec<Result<(), BleError>>) -> (Self, Arc<AtomicUsize>) {
        let starts = Arc::new(AtomicUsize::new(0));
        (
            Self {
                script: Arc::new(Mutex::new(VecDeque::from(script))),
                starts: Arc::clone(&starts),
            },
            starts,
        )
    }
}

impl BleAdvertiser for FakeAdvertiser {
    fn start(
        &mut self,
        _service_data: [u8; SERVICE_DATA_LEN],
    ) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let mut script = self.script.lock().expect("script lock poisoned");
            script.pop_front().unwrap_or(Ok(()))
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move { Ok(()) })
    }
}

#[derive(Clone)]
struct CountingSecrets {
    advertised: Vec<BroadcastSecret>,
    advertised_count: Arc<AtomicUsize>,
}

impl CountingSecrets {
    fn new(advertised: Vec<BroadcastSecret>) -> (Self, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                advertised,
                advertised_count: Arc::clone(&count),
            },
            count,
        )
    }
}

impl BroadcastSecrets for CountingSecrets {
    fn secrets(&self) -> Vec<BroadcastSecret> {
        self.advertised.clone()
    }

    fn advertised(&self) -> Vec<BroadcastSecret> {
        self.advertised_count.fetch_add(1, Ordering::SeqCst);
        self.advertised.clone()
    }
}

struct FixedCapabilities(Capabilities);

impl DeclaredCapabilities for FixedCapabilities {
    fn capabilities(&self) -> Capabilities {
        self.0
    }
}

// Advancing by an EID window per tick forces a new payload each slot so start is called to reach scripted results.
struct AutoAdvancingClock {
    wall: AtomicI64,
    step: i64,
    base_instant: Instant,
}

impl AutoAdvancingClock {
    fn new(start_secs: i64, step_secs: i64) -> Self {
        Self {
            wall: AtomicI64::new(start_secs),
            step: step_secs,
            base_instant: Instant::now(),
        }
    }
}

impl Clock for AutoAdvancingClock {
    fn now(&self) -> UnixTime {
        let prev = self.wall.fetch_add(self.step, Ordering::SeqCst);
        UnixTime::from_secs(prev)
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(self.base_instant)
    }
}

fn make_rotation(
    advertiser: Box<dyn BleAdvertiser>,
    secrets: Vec<BroadcastSecret>,
    clock: Box<dyn Clock + Send + Sync>,
) -> BleRotation {
    BleRotation::new(
        advertiser,
        Box::new(CountingSecrets::new(secrets).0),
        clock,
        Arc::new(FixedCapabilities(Capabilities::empty())),
        PlatformCode::LINUX,
    )
}

#[test]
fn unsupported_retreats_and_no_other_error_does() {
    let outcome = slot_outcome(&Err(BleError::Unsupported), None);
    assert!(outcome.retreat());
    assert_eq!(
        outcome.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );
    assert_eq!(
        outcome.reports(),
        &["ble advertising: unsupported on this platform, scanning only from now on".to_string()]
    );

    let outcome_prev = slot_outcome(&Err(BleError::Unsupported), Some(BleError::Unsupported));
    assert!(outcome_prev.retreat());
    assert_eq!(
        outcome_prev.reports(),
        &["ble advertising: unsupported on this platform, scanning only from now on".to_string()]
    );

    let other_errors = [
        BleError::PermissionDenied,
        BleError::AdapterUnavailable,
        BleError::Io(ErrorKind::Other),
        BleError::Closed,
    ];
    for err in other_errors {
        let outcome = slot_outcome(&Err(err), None);
        assert!(!outcome.retreat());
        let outcome_prev = slot_outcome(&Err(err), Some(err));
        assert!(!outcome_prev.retreat());
    }
}

#[test]
fn unchanged_error_is_reported_once_and_not_per_slot() {
    let err = BleError::Io(ErrorKind::Other);
    let outcome_new = slot_outcome(&Err(err), None);
    assert_eq!(outcome_new.reports(), &[format!("ble advertising: {err}")]);

    let outcome_same = slot_outcome(&Err(err), Some(err));
    assert!(outcome_same.reports().is_empty());

    let diff_err = BleError::AdapterUnavailable;
    let outcome_diff = slot_outcome(&Err(diff_err), Some(err));
    assert_eq!(
        outcome_diff.reports(),
        &[format!("ble advertising: {diff_err}")]
    );
}

#[tokio::test]
async fn cleared_error_is_reported_and_first_success_is_not() {
    let (adv, _) = FakeAdvertiser::new(vec![Ok(())]);
    let secret = BroadcastSecret::from_bytes(&[0x10; 32]).expect("valid secret");
    let clock = Box::new(AutoAdvancingClock::new(1_700_000_000, 0));
    let mut rotation = make_rotation(Box::new(adv), vec![secret], clock);

    let tick = rotation.tick().await;
    assert!(tick.is_ok());

    let resumed = slot_outcome(&tick, Some(BleError::AdapterUnavailable));
    assert_eq!(
        resumed.reports(),
        &["ble advertising: advertising resumed".to_string()]
    );
    assert!(!resumed.retreat());

    let first_success = slot_outcome(&tick, None);
    assert!(first_success.reports().is_empty());
    assert!(!first_success.retreat());
}

#[tokio::test]
async fn tick_report_carried_through_after_resumed_line() {
    let (adv, _) = FakeAdvertiser::new(vec![Ok(())]);
    let mut secrets = Vec::new();
    for i in 0..=BLE_ADVERTISED_SET_MAX {
        let mut b = [0u8; 32];
        b[0] = (i + 1) as u8;
        secrets.push(BroadcastSecret::from_bytes(&b).expect("valid secret"));
    }
    let clock = Box::new(AutoAdvancingClock::new(1_700_000_000, 0));
    let mut rotation = make_rotation(Box::new(adv), secrets, clock);

    let tick = rotation.tick().await;
    assert!(tick.is_ok());

    let resumed_and_reported = slot_outcome(&tick, Some(BleError::AdapterUnavailable));
    assert_eq!(
        resumed_and_reported.reports(),
        &[
            "ble advertising: advertising resumed".to_string(),
            "ble rotation: advertised set exceeds maximum cycle bound".to_string(),
        ]
    );

    let report_alone = slot_outcome(&tick, None);
    assert_eq!(
        report_alone.reports(),
        &["ble rotation: advertised set exceeds maximum cycle bound".to_string()]
    );
}

#[tokio::test(start_paused = true)]
async fn task_waits_tick_duration_and_one_slot_after_failure() {
    let script = vec![
        Ok(()),
        Ok(()),
        Err(BleError::Io(ErrorKind::Other)),
        Ok(()),
        Err(BleError::Unsupported),
    ];
    let (adv, _starts) = FakeAdvertiser::new(script);
    let secret = BroadcastSecret::from_bytes(&[0x20; 32]).expect("valid secret");
    let (secrets, _) = CountingSecrets::new(vec![secret]);
    let clock = AutoAdvancingClock::new(1_700_000_000, EID_WINDOW_SECS);
    let advertising = BleAdvertising::new(
        Box::new(secrets),
        Box::new(clock),
        Arc::new(FixedCapabilities(Capabilities::empty())),
        PlatformCode::LINUX,
    );

    let start = tokio::time::Instant::now();
    advertising.run(Ok(Box::new(adv))).await;
    let elapsed = start.elapsed();
    assert_eq!(
        elapsed,
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS * 4)
    );
}

#[tokio::test(start_paused = true)]
async fn non_unsupported_failure_leaves_task_running_and_unsupported_ends_it() {
    let script = vec![
        Ok(()),
        Ok(()),
        Err(BleError::Io(ErrorKind::Other)),
        Ok(()),
        Err(BleError::Unsupported),
    ];
    let (adv, starts) = FakeAdvertiser::new(script);
    let secret = BroadcastSecret::from_bytes(&[0x20; 32]).expect("valid secret");
    let (secrets, _) = CountingSecrets::new(vec![secret]);
    let clock = AutoAdvancingClock::new(1_700_000_000, EID_WINDOW_SECS);
    let advertising = BleAdvertising::new(
        Box::new(secrets),
        Box::new(clock),
        Arc::new(FixedCapabilities(Capabilities::empty())),
        PlatformCode::LINUX,
    );

    advertising.run(Ok(Box::new(adv))).await;
    assert_eq!(starts.load(Ordering::SeqCst), 5);
}

#[tokio::test(start_paused = true)]
async fn advertiser_unavailable_stops_task_before_asking_for_secret() {
    let secret = BroadcastSecret::from_bytes(&[0x30; 32]).expect("valid secret");
    let (secrets, advertised_count) = CountingSecrets::new(vec![secret]);
    let clock = AutoAdvancingClock::new(1_700_000_000, 0);
    let advertising = BleAdvertising::new(
        Box::new(secrets),
        Box::new(clock),
        Arc::new(FixedCapabilities(Capabilities::empty())),
        PlatformCode::LINUX,
    );

    advertising.run(Err(BleError::AdapterUnavailable)).await;
    assert_eq!(advertised_count.load(Ordering::SeqCst), 0);
}

#[test]
fn local_platform_code_names_this_build() {
    #[cfg(target_os = "linux")]
    assert_eq!(local_platform_code(), PlatformCode::LINUX);
    #[cfg(target_os = "windows")]
    assert_eq!(local_platform_code(), PlatformCode::WINDOWS);
    #[cfg(target_os = "macos")]
    assert_eq!(local_platform_code(), PlatformCode::MAC);
    #[cfg(target_os = "android")]
    assert_eq!(local_platform_code(), PlatformCode::ANDROID);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "android"
    )))]
    assert_eq!(local_platform_code(), PlatformCode::UNKNOWN);
}

#[tokio::test]
async fn cause_is_reported_once_per_change_across_a_run_of_slots() {
    let (adv, _) = FakeAdvertiser::new(vec![Ok(())]);
    let secret = BroadcastSecret::from_bytes(&[0x10; 32]).expect("valid secret");
    let clock = Box::new(AutoAdvancingClock::new(1_700_000_000, 0));
    let mut rotation = make_rotation(Box::new(adv), vec![secret], clock);

    let ok_tick = rotation.tick().await;
    assert!(ok_tick.is_ok());

    let mut reporter = AdvertisingReporter::default();

    let err_other = BleError::Io(ErrorKind::Other);
    let slot1 = reporter.slot(&Err(err_other));
    assert_eq!(slot1.reports(), &[format!("ble advertising: {err_other}")]);

    let slot2 = reporter.slot(&Err(err_other));
    assert!(slot2.reports().is_empty());

    let err_adapter = BleError::AdapterUnavailable;
    let slot3 = reporter.slot(&Err(err_adapter));
    assert_eq!(
        slot3.reports(),
        &[format!("ble advertising: {err_adapter}")]
    );

    let slot4 = reporter.slot(&ok_tick);
    assert_eq!(
        slot4.reports(),
        &["ble advertising: advertising resumed".to_string()]
    );

    let slot5 = reporter.slot(&ok_tick);
    assert!(slot5.reports().is_empty());
}

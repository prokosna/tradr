//! Tests for `BleRotation` advertising rotation (docs/03, DCR-109).
//! No real Bluetooth radio, no wall clock, and no sleeping (rule E3).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tradr_core::{BoxFuture, Capabilities, Clock, Monotonic, UnixTime};
use tradr_discovery::{
    Advertisement, BLE_ADVERTISED_SET_MAX, BLE_ADVERTISEMENT_SLOT_SECS, BleAdvertiser, BleError,
    BleRotation, BroadcastSecret, BroadcastSecrets, DeclaredCapabilities, EID_WINDOW_SECS,
    EidWindow, PlatformCode, SERVICE_DATA_LEN,
};

struct FakeAdvertiser {
    starts: Arc<Mutex<Vec<[u8; SERVICE_DATA_LEN]>>>,
    stops: Arc<Mutex<usize>>,
    start_error: Arc<Mutex<Option<BleError>>>,
    stop_error: Arc<Mutex<Option<BleError>>>,
}

#[derive(Clone)]
struct AdvertiserRecorder {
    starts: Arc<Mutex<Vec<[u8; SERVICE_DATA_LEN]>>>,
    stops: Arc<Mutex<usize>>,
    start_error: Arc<Mutex<Option<BleError>>>,
    stop_error: Arc<Mutex<Option<BleError>>>,
}

impl AdvertiserRecorder {
    fn starts(&self) -> Vec<[u8; SERVICE_DATA_LEN]> {
        self.starts.lock().expect("lock poisoned").clone()
    }

    fn stops(&self) -> usize {
        *self.stops.lock().expect("lock poisoned")
    }

    fn set_start_error(&self, error: Option<BleError>) {
        *self.start_error.lock().expect("lock poisoned") = error;
    }

    fn set_stop_error(&self, error: Option<BleError>) {
        *self.stop_error.lock().expect("lock poisoned") = error;
    }
}

impl FakeAdvertiser {
    fn new() -> (Self, AdvertiserRecorder) {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let stops = Arc::new(Mutex::new(0));
        let start_error = Arc::new(Mutex::new(None));
        let stop_error = Arc::new(Mutex::new(None));
        (
            Self {
                starts: Arc::clone(&starts),
                stops: Arc::clone(&stops),
                start_error: Arc::clone(&start_error),
                stop_error: Arc::clone(&stop_error),
            },
            AdvertiserRecorder {
                starts,
                stops,
                start_error,
                stop_error,
            },
        )
    }
}

impl BleAdvertiser for FakeAdvertiser {
    fn start(
        &mut self,
        service_data: [u8; SERVICE_DATA_LEN],
    ) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            self.starts
                .lock()
                .expect("lock poisoned")
                .push(service_data);
            if let Some(err) = *self.start_error.lock().expect("lock poisoned") {
                return Err(err);
            }
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            *self.stops.lock().expect("lock poisoned") += 1;
            if let Some(err) = *self.stop_error.lock().expect("lock poisoned") {
                return Err(err);
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct SettableSecrets {
    advertised: Arc<Mutex<Vec<BroadcastSecret>>>,
    matching: Arc<Mutex<Vec<BroadcastSecret>>>,
}

impl SettableSecrets {
    fn new(advertised: Vec<BroadcastSecret>) -> Self {
        Self {
            matching: Arc::new(Mutex::new(advertised.clone())),
            advertised: Arc::new(Mutex::new(advertised)),
        }
    }

    fn set_advertised(&self, secrets: Vec<BroadcastSecret>) {
        *self.advertised.lock().expect("lock poisoned") = secrets;
    }

    fn set_matching(&self, secrets: Vec<BroadcastSecret>) {
        *self.matching.lock().expect("lock poisoned") = secrets;
    }

    fn add_advertised(&self, secret: BroadcastSecret) {
        self.advertised.lock().expect("lock poisoned").push(secret);
    }
}

impl BroadcastSecrets for SettableSecrets {
    fn secrets(&self) -> Vec<BroadcastSecret> {
        self.matching.lock().expect("lock poisoned").clone()
    }

    fn advertised(&self) -> Vec<BroadcastSecret> {
        self.advertised.lock().expect("lock poisoned").clone()
    }
}

#[derive(Clone)]
struct SettableCapabilities {
    caps: Arc<Mutex<Capabilities>>,
}

impl SettableCapabilities {
    fn new(caps: Capabilities) -> Self {
        Self {
            caps: Arc::new(Mutex::new(caps)),
        }
    }

    fn set(&self, caps: Capabilities) {
        *self.caps.lock().expect("lock poisoned") = caps;
    }
}

impl DeclaredCapabilities for SettableCapabilities {
    fn capabilities(&self) -> Capabilities {
        *self.caps.lock().expect("lock poisoned")
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

    fn advance_wall_secs(&self, secs: i64) {
        self.wall.fetch_add(secs, Ordering::SeqCst);
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

#[tokio::test]
async fn first_start_payload_equals_independently_computed_advertisement() {
    let (adv, recorder) = FakeAdvertiser::new();
    let secret = BroadcastSecret::from_bytes(&[0x11; 32]).expect("valid 32-byte secret");
    let secrets = Box::new(SettableSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    let tick = rotation.tick().await.expect("tick succeeds");
    assert_eq!(
        tick.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );

    let starts = recorder.starts();
    assert_eq!(starts.len(), 1);
    assert_eq!(recorder.stops(), 0);

    let expected_eid = secret.eid(EidWindow::containing(clock.now()));
    let expected_payload = Advertisement::new(expected_eid, platform, caps).service_data();
    assert_eq!(starts[0], expected_payload);
}

#[tokio::test]
async fn one_secret_two_ticks_in_same_window_calls_start_once() {
    let (adv, recorder) = FakeAdvertiser::new();
    let secret = BroadcastSecret::from_bytes(&[0x22; 32]).expect("valid 32-byte secret");
    let secrets = Box::new(SettableSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    rotation.tick().await.expect("tick 2 succeeds");

    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 0);
}

#[tokio::test]
async fn one_secret_clock_stepped_full_window_calls_start_twice_with_differing_payloads() {
    let (adv, recorder) = FakeAdvertiser::new();
    let secret = BroadcastSecret::from_bytes(&[0x33; 32]).expect("valid 32-byte secret");
    let secrets = Box::new(SettableSecrets::new(vec![secret]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    clock.advance_wall_secs(EID_WINDOW_SECS);
    rotation.tick().await.expect("tick 2 succeeds");

    let starts = recorder.starts();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0], starts[1]);
    assert_eq!(recorder.stops(), 0);
}

#[tokio::test]
async fn three_secrets_rotate_in_order_and_wrap() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x01; 32]).expect("valid secret");
    let s1 = BroadcastSecret::from_bytes(&[0x02; 32]).expect("valid secret");
    let s2 = BroadcastSecret::from_bytes(&[0x03; 32]).expect("valid secret");
    let secrets = Box::new(SettableSecrets::new(vec![s0, s1, s2]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    for _ in 0..4 {
        rotation.tick().await.expect("tick succeeds");
        clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    }

    let starts = recorder.starts();
    assert_eq!(starts.len(), 4);
    assert_eq!(recorder.stops(), 0);

    let window = EidWindow::containing(UnixTime::from_secs(1_700_000_000));
    let ad0 = Advertisement::from_service_data(&starts[0]).expect("valid ad");
    let ad1 = Advertisement::from_service_data(&starts[1]).expect("valid ad");
    let ad2 = Advertisement::from_service_data(&starts[2]).expect("valid ad");
    let ad3 = Advertisement::from_service_data(&starts[3]).expect("valid ad");

    assert_eq!(ad0.eid(), s0.eid(window));
    assert_eq!(ad1.eid(), s1.eid(window));
    assert_eq!(ad2.eid(), s2.eid(window));
    assert_eq!(ad3.eid(), s0.eid(window));
}

#[tokio::test]
async fn secret_added_between_ticks_takes_slot_without_restart() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x01; 32]).expect("valid secret");
    let s1 = BroadcastSecret::from_bytes(&[0x02; 32]).expect("valid secret");
    let secrets_provider = SettableSecrets::new(vec![s0]);
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(recorder.starts().len(), 1);

    secrets_provider.add_advertised(s1);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);

    rotation.tick().await.expect("tick 2 succeeds");

    let starts = recorder.starts();
    assert_eq!(starts.len(), 2);
    assert_eq!(recorder.stops(), 0);

    let window = EidWindow::containing(UnixTime::from_secs(1_700_000_000));
    let ad1 = Advertisement::from_service_data(&starts[1]).expect("valid ad");
    assert_eq!(ad1.eid(), s1.eid(window));
}

#[tokio::test]
async fn capability_bits_changed_between_ticks_changes_payload() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x01; 32]).expect("valid secret");
    let secrets = Box::new(SettableSecrets::new(vec![s0]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps1 = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = SettableCapabilities::new(caps1);
    let cap_trait: Arc<dyn DeclaredCapabilities> = Arc::new(cap_provider.clone());
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_trait,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(recorder.starts().len(), 1);

    let caps2 =
        Capabilities::from_bits(Capabilities::BLE_GATT.bits() | Capabilities::DIRECT_QUIC.bits());
    cap_provider.set(caps2);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);

    rotation.tick().await.expect("tick 2 succeeds");

    let starts = recorder.starts();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0], starts[1]);

    let ad1 = Advertisement::from_service_data(&starts[0]).expect("valid ad");
    let ad2 = Advertisement::from_service_data(&starts[1]).expect("valid ad");
    assert_eq!(ad1.capabilities(), caps1);
    assert_eq!(ad2.capabilities(), caps2);
    assert_eq!(recorder.stops(), 0);
}

#[tokio::test]
async fn empty_set_with_something_on_air_calls_stop_once_and_start_never() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x01; 32]).expect("valid secret");
    let secrets_provider = SettableSecrets::new(vec![s0]);
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 0);

    secrets_provider.set_advertised(vec![]);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);

    rotation.tick().await.expect("tick 2 succeeds");
    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 1);

    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    rotation.tick().await.expect("tick 3 succeeds");
    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 1);
}

#[tokio::test]
async fn empty_set_with_nothing_on_air_calls_neither() {
    let (adv, recorder) = FakeAdvertiser::new();
    let secrets = Box::new(SettableSecrets::new(vec![]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    let tick = rotation.tick().await.expect("tick succeeds");
    assert_eq!(recorder.starts().len(), 0);
    assert_eq!(recorder.stops(), 0);
    assert_eq!(
        tick.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );
    assert_eq!(tick.report(), None);
}

#[tokio::test]
async fn set_that_becomes_non_empty_again_starts_advertising_on_next_tick() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x01; 32]).expect("valid secret");
    let secrets_provider = SettableSecrets::new(vec![]);
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(recorder.starts().len(), 0);

    secrets_provider.set_advertised(vec![s0]);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);

    rotation.tick().await.expect("tick 2 succeeds");
    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 0);
}

#[tokio::test]
async fn overbound_set_reports_once_and_every_secret_takes_a_slot() {
    let (adv, recorder) = FakeAdvertiser::new();
    let count = BLE_ADVERTISED_SET_MAX + 1;
    let mut secrets_list = Vec::with_capacity(count);
    for i in 0..count {
        let mut bytes = [0u8; 32];
        bytes[0] = (i + 1) as u8;
        secrets_list.push(BroadcastSecret::from_bytes(&bytes).expect("valid secret"));
    }
    let secrets = Box::new(SettableSecrets::new(secrets_list.clone()));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    let tick1 = rotation.tick().await.expect("tick 1 succeeds");
    assert!(tick1.report().is_some());

    let tick2 = rotation.tick().await.expect("tick 2 succeeds");
    assert_eq!(tick2.report(), None);

    for _ in 2..count {
        let tick = rotation.tick().await.expect("tick succeeds");
        assert_eq!(tick.report(), None);
    }

    let starts = recorder.starts();
    assert_eq!(starts.len(), count);
    assert_eq!(recorder.stops(), 0);

    let window = EidWindow::containing(clock.now());
    for i in 0..count {
        let ad = Advertisement::from_service_data(&starts[i]).expect("valid ad");
        assert_eq!(ad.eid(), secrets_list[i].eid(window));
    }
}

#[tokio::test]
async fn report_presents_clearing_when_set_shrinks_back_inside_bound() {
    let (adv, _) = FakeAdvertiser::new();
    let count = BLE_ADVERTISED_SET_MAX + 1;
    let mut secrets_list = Vec::with_capacity(count);
    for i in 0..count {
        let mut bytes = [0u8; 32];
        bytes[0] = (i + 1) as u8;
        secrets_list.push(BroadcastSecret::from_bytes(&bytes).expect("valid secret"));
    }
    let secrets_provider = SettableSecrets::new(secrets_list.clone());
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    let tick1 = rotation.tick().await.expect("tick 1 succeeds");
    assert!(tick1.report().is_some());

    secrets_provider.set_advertised(secrets_list[..BLE_ADVERTISED_SET_MAX].to_vec());
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);

    let tick2 = rotation.tick().await.expect("tick 2 succeeds");
    assert!(tick2.report().is_some());
    let report_str = tick2.report().unwrap_or("");
    assert!(report_str.contains("within") || report_str.contains("cleared"));

    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    let tick3 = rotation.tick().await.expect("tick 3 succeeds");
    assert_eq!(tick3.report(), None);
}

#[tokio::test]
async fn advertiser_start_unsupported_error_clears_on_air_and_retries_same_payload() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x55; 32]).expect("valid secret");
    let secrets = Box::new(SettableSecrets::new(vec![s0]));
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        secrets,
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    recorder.set_start_error(Some(BleError::Unsupported));

    let err = rotation
        .tick()
        .await
        .expect_err("tick must fail with Unsupported");
    assert_eq!(err, BleError::Unsupported);

    recorder.set_start_error(None);

    let tick2 = rotation.tick().await.expect("tick 2 succeeds");
    assert_eq!(
        tick2.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );

    let starts = recorder.starts();
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0], starts[1]);
    assert_eq!(recorder.stops(), 0);
}

#[tokio::test]
async fn tick_never_starts_payload_matching_secret_in_secrets_but_not_in_advertised() {
    let (adv, recorder) = FakeAdvertiser::new();
    let advertised_secret = BroadcastSecret::from_bytes(&[0xaa; 32]).expect("valid secret");
    let matching_only_secret = BroadcastSecret::from_bytes(&[0xbb; 32]).expect("valid secret");

    let secrets_provider = SettableSecrets::new(vec![advertised_secret]);
    secrets_provider.set_matching(vec![advertised_secret, matching_only_secret]);
    secrets_provider.set_advertised(vec![advertised_secret]);

    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick succeeds");

    let starts = recorder.starts();
    assert_eq!(starts.len(), 1);

    let ad = Advertisement::from_service_data(&starts[0]).expect("valid ad");
    let eid = ad.eid();

    let now = clock.now();
    assert!(advertised_secret.matches(&eid, now).is_some());
    assert!(matching_only_secret.matches(&eid, now).is_none());
}

#[tokio::test]
async fn every_tick_answers_slot_duration() {
    let (adv, _) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x01; 32]).expect("valid secret");
    let secrets_provider = SettableSecrets::new(vec![s0]);
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    let tick1 = rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(
        tick1.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );

    secrets_provider.set_advertised(vec![]);
    let tick2 = rotation.tick().await.expect("tick 2 succeeds");
    assert_eq!(
        tick2.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );

    let tick3 = rotation.tick().await.expect("tick 3 succeeds");
    assert_eq!(
        tick3.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );
}

#[tokio::test]
async fn advertiser_stop_error_answers_err_and_retries_stop_on_following_tick() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x66; 32]).expect("valid secret");
    let secrets_provider = SettableSecrets::new(vec![s0]);
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 0);

    secrets_provider.set_advertised(vec![]);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    recorder.set_stop_error(Some(BleError::AdapterUnavailable));

    let err = rotation
        .tick()
        .await
        .expect_err("tick 2 must fail when stop fails");
    assert_eq!(err, BleError::AdapterUnavailable);
    assert_eq!(recorder.stops(), 1);

    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    let err2 = rotation
        .tick()
        .await
        .expect_err("tick 3 must retry stop and fail again while error persists");
    assert_eq!(err2, BleError::AdapterUnavailable);
    assert_eq!(recorder.stops(), 2);
    assert_eq!(recorder.starts().len(), 1);
}

#[tokio::test]
async fn advertiser_retried_stop_succeeds_then_further_ticks_call_stop_no_more() {
    let (adv, recorder) = FakeAdvertiser::new();
    let s0 = BroadcastSecret::from_bytes(&[0x77; 32]).expect("valid secret");
    let secrets_provider = SettableSecrets::new(vec![s0]);
    let clock = SteppableClock::new(1_700_000_000);
    let caps = Capabilities::from_bits(Capabilities::BLE_GATT.bits());
    let cap_provider = Arc::new(SettableCapabilities::new(caps));
    let platform = PlatformCode::LINUX;

    let mut rotation = BleRotation::new(
        Box::new(adv),
        Box::new(secrets_provider.clone()),
        Box::new(clock.clone()),
        cap_provider,
        platform,
    );

    rotation.tick().await.expect("tick 1 succeeds");
    assert_eq!(recorder.starts().len(), 1);
    assert_eq!(recorder.stops(), 0);

    secrets_provider.set_advertised(vec![]);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    recorder.set_stop_error(Some(BleError::AdapterUnavailable));

    let err = rotation
        .tick()
        .await
        .expect_err("tick 2 must fail when stop fails");
    assert_eq!(err, BleError::AdapterUnavailable);
    assert_eq!(recorder.stops(), 1);

    recorder.set_stop_error(None);
    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    let tick3 = rotation
        .tick()
        .await
        .expect("tick 3 succeeds on retried stop");
    assert_eq!(
        tick3.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );
    assert_eq!(recorder.stops(), 2);

    clock.advance_wall_secs(BLE_ADVERTISEMENT_SLOT_SECS as i64);
    let tick4 = rotation.tick().await.expect("tick 4 succeeds");
    assert_eq!(
        tick4.wait(),
        Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS)
    );
    assert_eq!(recorder.stops(), 2);
    assert_eq!(recorder.starts().len(), 1);
}

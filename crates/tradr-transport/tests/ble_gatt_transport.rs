mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tradr_core::{
    BoxFuture, Candidate, DeviceId, Incoming, PeerExpectation, SecureChannel, Transport,
    TransportError, TransportId,
};
use tradr_transport::ble::{BLE_GATT_DIAL_TIMEOUT, BleGattTransport, GattCentral, GattPeripheral};

enum DialOutcome {
    Channel(Option<Box<dyn SecureChannel>>),
    DelayedChannel(Option<Box<dyn SecureChannel>>, Duration),
    Failure(TransportError),
    NeverEnding,
}

struct RecordingCentral {
    outcome: Mutex<DialOutcome>,
    abandon_calls: Mutex<Vec<String>>,
    abandon_error: Option<TransportError>,
}

impl RecordingCentral {
    fn returning_channel(channel: impl SecureChannel + 'static) -> Self {
        Self {
            outcome: Mutex::new(DialOutcome::Channel(Some(Box::new(channel)))),
            abandon_calls: Mutex::new(Vec::new()),
            abandon_error: None,
        }
    }

    fn returning_channel_after(channel: impl SecureChannel + 'static, delay: Duration) -> Self {
        Self {
            outcome: Mutex::new(DialOutcome::DelayedChannel(Some(Box::new(channel)), delay)),
            abandon_calls: Mutex::new(Vec::new()),
            abandon_error: None,
        }
    }

    fn failing_with(err: TransportError) -> Self {
        Self {
            outcome: Mutex::new(DialOutcome::Failure(err)),
            abandon_calls: Mutex::new(Vec::new()),
            abandon_error: None,
        }
    }

    fn never_finishing() -> Self {
        Self {
            outcome: Mutex::new(DialOutcome::NeverEnding),
            abandon_calls: Mutex::new(Vec::new()),
            abandon_error: None,
        }
    }

    fn failing_dial_and_abandon(dial_err: TransportError, abandon_err: TransportError) -> Self {
        Self {
            outcome: Mutex::new(DialOutcome::Failure(dial_err)),
            abandon_calls: Mutex::new(Vec::new()),
            abandon_error: Some(abandon_err),
        }
    }

    fn abandon_calls(&self) -> Vec<String> {
        self.abandon_calls.lock().expect("mutex lock").clone()
    }
}

impl GattCentral for RecordingCentral {
    fn dial<'a>(
        &'a self,
        _address: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            let (channel, delay, never_ending) = {
                let mut guard = self.outcome.lock().expect("mutex lock");
                match &mut *guard {
                    DialOutcome::Channel(opt) => (opt.take(), Duration::ZERO, false),
                    DialOutcome::DelayedChannel(opt, d) => (opt.take(), *d, false),
                    DialOutcome::Failure(e) => return Err(*e),
                    DialOutcome::NeverEnding => (None, Duration::ZERO, true),
                }
            };
            if never_ending {
                std::future::pending::<()>().await;
                return Err(TransportError::TimedOut);
            }
            let chan = channel.expect("channel present");
            tokio::time::sleep(delay).await;
            Ok(chan)
        })
    }

    fn abandon<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<(), TransportError>> {
        let mut guard = self.abandon_calls.lock().expect("mutex lock");
        guard.push(address.to_string());
        let res = match self.abandon_error {
            Some(err) => Err(err),
            None => Ok(()),
        };
        Box::pin(async move { res })
    }
}

struct MockIncoming;

impl Incoming for MockIncoming {
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }
}

struct MockPeripheral;

impl GattPeripheral for MockPeripheral {
    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async { Ok(Box::new(MockIncoming) as Box<dyn Incoming>) })
    }
}

#[tokio::test]
async fn transport_id_is_ble_gatt() {
    let transport = BleGattTransport::new(None, None);
    assert_eq!(transport.id().as_str(), "ble-gatt");
}

#[tokio::test]
async fn connect_with_no_central_is_unsupported() {
    let transport = BleGattTransport::new(None, None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");
    let err = match transport
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected unsupported error"),
    };
    assert_eq!(err, TransportError::Io(std::io::ErrorKind::Unsupported));
}

#[tokio::test]
async fn listen_with_no_peripheral_is_unsupported() {
    let transport = BleGattTransport::new(None, None);
    let err = match transport.listen().await {
        Err(e) => e,
        Ok(_) => panic!("expected unsupported error"),
    };
    assert_eq!(err, TransportError::Io(std::io::ErrorKind::Unsupported));
}

#[tokio::test]
async fn listen_with_peripheral_returns_incoming() {
    let peripheral = Arc::new(MockPeripheral);
    let transport = BleGattTransport::new(None, Some(peripheral));
    let mut incoming = transport.listen().await.expect("listen succeeds");
    let err = match incoming.accept().await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err, TransportError::Closed);
}

#[tokio::test]
async fn dial_success_under_unpinned_returns_channel_and_no_abandon() {
    let (chan, _) = common::connected_channels(false);
    let expected_id = chan.peer();
    let central = Arc::new(RecordingCentral::returning_channel(chan));
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let channel = transport
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await
        .expect("dial succeeds");
    assert_eq!(channel.peer(), expected_id);
    assert_eq!(central.abandon_calls().len(), 0);
}

#[tokio::test]
async fn dial_failure_rejected_returns_rejected_and_abandons_once() {
    let central = Arc::new(RecordingCentral::failing_with(TransportError::Rejected));
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let err = match transport
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected rejected error"),
    };
    assert_eq!(err, TransportError::Rejected);
    assert_eq!(central.abandon_calls(), vec!["handle:0x0042"]);
}

#[tokio::test(start_paused = true)]
async fn dial_never_finishing_times_out_and_abandons_once() {
    let central = Arc::new(RecordingCentral::never_finishing());
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        transport.connect(&candidate, &PeerExpectation::Unpinned),
    )
    .await
    .expect("outer timeout must not expire");

    let elapsed = start.elapsed();
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected timeout error"),
    };
    assert_eq!(err, TransportError::TimedOut);
    assert_eq!(BLE_GATT_DIAL_TIMEOUT, Duration::from_secs(10));
    assert_eq!(elapsed, BLE_GATT_DIAL_TIMEOUT);
    assert_eq!(central.abandon_calls(), vec!["handle:0x0042"]);
}

#[tokio::test(start_paused = true)]
async fn dial_finishing_one_second_inside_bound_succeeds() {
    let (chan, _) = common::connected_channels(false);
    let expected_id = chan.peer();
    let delay = BLE_GATT_DIAL_TIMEOUT - Duration::from_secs(1);
    let central = Arc::new(RecordingCentral::returning_channel_after(chan, delay));
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        transport.connect(&candidate, &PeerExpectation::Unpinned),
    )
    .await
    .expect("outer timeout must not expire");

    let elapsed = start.elapsed();
    let channel = result.expect("dial within bound must succeed");
    assert_eq!(channel.peer(), expected_id);
    assert_eq!(elapsed, delay);
    assert_eq!(central.abandon_calls().len(), 0);
}

#[tokio::test]
async fn peer_expectation_mismatch_fails_authentication_and_abandons_once() {
    let (chan, _) = common::connected_channels(false);
    let other = DeviceId::from_identity_digest(&[0x42; 32]);
    assert_ne!(chan.peer(), other);

    let central = Arc::new(RecordingCentral::returning_channel(chan));
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let err = match transport
        .connect(&candidate, &PeerExpectation::Device(other))
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected authentication failed error"),
    };
    assert_eq!(err, TransportError::AuthenticationFailed);
    assert_eq!(central.abandon_calls(), vec!["handle:0x0042"]);
}

#[tokio::test]
async fn peer_expectation_match_succeeds_and_does_not_abandon() {
    let (chan, _) = common::connected_channels(false);
    let same = chan.peer();

    let central = Arc::new(RecordingCentral::returning_channel(chan));
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let channel = transport
        .connect(&candidate, &PeerExpectation::Device(same))
        .await
        .expect("peer id matches");
    assert_eq!(channel.peer(), same);
    assert_eq!(central.abandon_calls().len(), 0);
}

#[tokio::test]
async fn failing_abandon_preserves_dial_error() {
    let central = Arc::new(RecordingCentral::failing_dial_and_abandon(
        TransportError::Rejected,
        TransportError::Io(std::io::ErrorKind::BrokenPipe),
    ));
    let transport = BleGattTransport::new(Some(central.clone()), None);
    let candidate = Candidate::new(TransportId::new("ble-gatt"), "handle:0x0042").expect("valid");

    let err = match transport
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected rejected error"),
    };
    assert_eq!(err, TransportError::Rejected);
    assert_eq!(central.abandon_calls(), vec!["handle:0x0042"]);
}

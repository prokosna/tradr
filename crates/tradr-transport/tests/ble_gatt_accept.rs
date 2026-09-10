mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tradr_core::{BoxFuture, Clock, Monotonic, SecureChannel, TransportError, UnixTime};
use tradr_proto::mux::StreamOpener;
use tradr_transport::ble::{BLE_GATT_TRANSPORT_ID, accept_link};
use tradr_transport::noise::{
    BLE_GATT_MAX_FRAME_SIZE, BLE_GATT_MAX_RECORD, ByteSink, ByteSource, LinkSink, NoiseChannel,
    NoiseChannelConfig, RecordSink, RecordSource, handshake_as_initiator,
};

#[derive(Clone)]
struct SteppableClock {
    base_instant: Instant,
    mono_offset_ms: Arc<AtomicU64>,
}

impl SteppableClock {
    fn new() -> Self {
        Self {
            base_instant: Instant::now(),
            mono_offset_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance_monotonic(&self, ms: u64) {
        self.mono_offset_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for SteppableClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(common::NOW)
    }

    fn monotonic_now(&self) -> Monotonic {
        let offset = Duration::from_millis(self.mono_offset_ms.load(Ordering::SeqCst));
        Monotonic::from_instant(self.base_instant + offset)
    }
}

struct ChannelByteSink {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ByteSink for ChannelByteSink {
    fn send_bytes<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.tx
                .send(bytes.to_vec())
                .await
                .map_err(|_| TransportError::Closed)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

struct ChannelByteSource {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl ByteSource for ChannelByteSource {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { Ok(self.rx.recv().await) })
    }
}

fn connected_byte_stream_pair(
    capacity: usize,
) -> (
    (ChannelByteSink, ChannelByteSource),
    (ChannelByteSink, ChannelByteSource),
) {
    let (a_tx, b_rx) = tokio::sync::mpsc::channel(capacity);
    let (b_tx, a_rx) = tokio::sync::mpsc::channel(capacity);
    (
        (ChannelByteSink { tx: a_tx }, ChannelByteSource { rx: a_rx }),
        (ChannelByteSink { tx: b_tx }, ChannelByteSource { rx: b_rx }),
    )
}

struct ClockAdvancingByteSource<S: ByteSource> {
    inner: S,
    clock: SteppableClock,
    calls: usize,
}

impl<S: ByteSource> ClockAdvancingByteSource<S> {
    fn new(inner: S, clock: SteppableClock) -> Self {
        Self {
            inner,
            clock,
            calls: 0,
        }
    }
}

impl<S: ByteSource> ByteSource for ClockAdvancingByteSource<S> {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            let bytes = self.inner.recv_bytes().await?;
            if bytes.is_some() {
                if self.calls == 0 {
                    self.clock.advance_monotonic(700);
                } else {
                    self.clock.advance_monotonic(50);
                }
                self.calls += 1;
            }
            Ok(bytes)
        })
    }
}

struct EmptyByteSource;

impl ByteSource for EmptyByteSource {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { Ok(None) })
    }
}

struct FakeRecordByteSource {
    bytes: Option<Vec<u8>>,
}

impl FakeRecordByteSource {
    fn new(record: Vec<u8>) -> Self {
        let len = (record.len() as u16).to_be_bytes();
        let mut framed = Vec::with_capacity(2 + record.len());
        framed.extend_from_slice(&len);
        framed.extend_from_slice(&record);
        Self {
            bytes: Some(framed),
        }
    }
}

impl ByteSource for FakeRecordByteSource {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { Ok(self.bytes.take()) })
    }
}

#[tokio::test]
async fn handshake_completes_and_initiator_stream_is_accepted_by_listener() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();

    let ((init_sink, init_source), (resp_sink, resp_source)) = connected_byte_stream_pair(16);

    let initiator_task = tokio::spawn(async move {
        let sink: Arc<dyn LinkSink> = Arc::new(RecordSink::new(init_sink, BLE_GATT_MAX_RECORD));
        let mut source = RecordSource::new(init_source, BLE_GATT_MAX_RECORD);
        let session = handshake_as_initiator(initiator, &*sink, &mut source)
            .await
            .expect("initiator handshake succeeds");
        let config = NoiseChannelConfig {
            transport: BLE_GATT_TRANSPORT_ID,
            opener: StreamOpener::Dialler,
            max_frame_size: BLE_GATT_MAX_FRAME_SIZE,
            record_limit: BLE_GATT_MAX_FRAME_SIZE,
            rtt: Duration::from_millis(10),
        };
        NoiseChannel::new(session, sink, Box::new(source), config).expect("initiator channel")
    });

    let resp_channel = accept_link(resp_sink, resp_source, responder, &clock)
        .await
        .expect("accept_link succeeds");
    let init_channel = initiator_task.await.expect("initiator task joins");

    let (mut init_send, mut init_recv) = init_channel.open_bi().await.expect("open_bi succeeds");
    init_send
        .write_all(b"hello from initiator")
        .await
        .expect("initiator writes");
    init_send.finish().await.expect("initiator finishes");

    let (mut resp_send, mut resp_recv) =
        resp_channel.accept_bi().await.expect("accept_bi succeeds");
    let mut buf = [0u8; 64];
    let n = resp_recv.read(&mut buf).await.expect("responder reads");
    assert_eq!(&buf[..n], b"hello from initiator");

    resp_send
        .write_all(b"hello from responder")
        .await
        .expect("responder writes");
    resp_send.finish().await.expect("responder finishes");

    let n = init_recv.read(&mut buf).await.expect("initiator reads");
    assert_eq!(&buf[..n], b"hello from responder");
}

#[tokio::test]
async fn channel_reports_ble_gatt_transport_and_512_max_frame_size() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();

    let ((init_sink, init_source), (resp_sink, resp_source)) = connected_byte_stream_pair(16);

    let initiator_task = tokio::spawn(async move {
        let sink: Arc<dyn LinkSink> = Arc::new(RecordSink::new(init_sink, BLE_GATT_MAX_RECORD));
        let mut source = RecordSource::new(init_source, BLE_GATT_MAX_RECORD);
        handshake_as_initiator(initiator, &*sink, &mut source)
            .await
            .expect("initiator handshake succeeds")
    });

    let resp_channel = accept_link(resp_sink, resp_source, responder, &clock)
        .await
        .expect("accept_link succeeds");
    initiator_task.await.expect("initiator task joins");

    assert_eq!(resp_channel.transport(), BLE_GATT_TRANSPORT_ID);
    assert_eq!(resp_channel.transport().as_str(), "ble-gatt");
    assert_eq!(resp_channel.max_frame_size(), 512);
}

#[tokio::test]
async fn rtt_measurement_excludes_wait_for_message_1() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();

    let ((init_sink, init_source), (resp_sink, resp_source)) = connected_byte_stream_pair(16);
    let advancing_source = ClockAdvancingByteSource::new(resp_source, clock.clone());

    let initiator_task = tokio::spawn(async move {
        let sink: Arc<dyn LinkSink> = Arc::new(RecordSink::new(init_sink, BLE_GATT_MAX_RECORD));
        let mut source = RecordSource::new(init_source, BLE_GATT_MAX_RECORD);
        handshake_as_initiator(initiator, &*sink, &mut source)
            .await
            .expect("initiator handshake succeeds")
    });

    let resp_channel = accept_link(resp_sink, advancing_source, responder, &clock)
        .await
        .expect("accept_link succeeds");
    initiator_task.await.expect("initiator task joins");

    assert_eq!(resp_channel.rtt(), Duration::from_millis(50));
}

#[tokio::test]
async fn byte_source_ending_before_message_1_yields_closed() {
    let pair = common::Pair::new();
    let responder = pair.responder();
    let clock = SteppableClock::new();

    let ((sink, _), _) = connected_byte_stream_pair(16);
    let result = accept_link(sink, EmptyByteSource, responder, &clock).await;

    assert_eq!(result.err(), Some(TransportError::Closed));
}

#[tokio::test]
async fn well_formed_record_not_valid_noise_message_yields_authentication_failed() {
    let pair = common::Pair::new();
    let responder = pair.responder();
    let clock = SteppableClock::new();

    let ((sink, _), _) = connected_byte_stream_pair(16);
    let fake_source = FakeRecordByteSource::new(vec![0x42; 32]);
    let result = accept_link(sink, fake_source, responder, &clock).await;

    assert_eq!(result.err(), Some(TransportError::AuthenticationFailed));
}

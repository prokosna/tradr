mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tradr_core::{BoxFuture, Clock, Monotonic, TransportError, UnixTime};
use tradr_transport::noise::{
    LinkSink, LinkSource, handshake_as_initiator, handshake_as_responder,
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

struct ClockAdvancingSource {
    inner: Box<dyn LinkSource>,
    clock: SteppableClock,
    records_yielded: usize,
}

impl ClockAdvancingSource {
    fn new(inner: Box<dyn LinkSource>, clock: SteppableClock) -> Self {
        Self {
            inner,
            clock,
            records_yielded: 0,
        }
    }
}

impl LinkSource for ClockAdvancingSource {
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            let record = self.inner.recv_record().await?;
            if record.is_some() {
                if self.records_yielded == 0 {
                    self.clock.advance_monotonic(700);
                } else if self.records_yielded == 1 {
                    self.clock.advance_monotonic(50);
                }
                self.records_yielded += 1;
            }
            Ok(record)
        })
    }
}

struct EmptySource;

impl LinkSource for EmptySource {
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { Ok(None) })
    }
}

#[tokio::test]
async fn full_handshake_completes_and_identifies_peers() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();
    let ((init_sink, mut init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);

    let initiator_task = tokio::spawn(async move {
        handshake_as_initiator(initiator, &*init_sink, &mut *init_source).await
    });

    let (resp_session, _rtt) =
        handshake_as_responder(responder, &*resp_sink, &mut *resp_source, &clock)
            .await
            .expect("responder handshake completes");
    let init_session = initiator_task
        .await
        .expect("initiator task joins")
        .expect("initiator handshake completes");

    assert_eq!(resp_session.peer(), pair.initiator_store.device_id());
    assert_eq!(init_session.peer(), pair.responder_store.device_id());
}

#[tokio::test]
async fn measurement_excludes_wait_for_peer() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();
    let ((init_sink, mut init_source), (resp_sink, resp_source)) =
        common::memory_link_pair(16, false);
    let mut decorating_source = ClockAdvancingSource::new(resp_source, clock.clone());

    let initiator_task = tokio::spawn(async move {
        handshake_as_initiator(initiator, &*init_sink, &mut *init_source).await
    });

    let (_resp_session, rtt) =
        handshake_as_responder(responder, &*resp_sink, &mut decorating_source, &clock)
            .await
            .expect("responder handshake completes");
    initiator_task
        .await
        .expect("initiator task joins")
        .expect("initiator handshake completes");

    assert_eq!(rtt, Duration::from_millis(50));
    assert_ne!(rtt, Duration::from_millis(750));
}

#[tokio::test]
async fn link_ending_before_message_1_yields_closed() {
    let pair = common::Pair::new();
    let responder = pair.responder();
    let clock = SteppableClock::new();
    let counting_sink = common::CountingSink::new(common::MemorySink::dummy());
    let mut empty_source = EmptySource;

    let result = handshake_as_responder(responder, &counting_sink, &mut empty_source, &clock).await;

    assert_eq!(result.err(), Some(TransportError::Closed));
    assert_eq!(counting_sink.sends(), 0);
}

#[tokio::test]
async fn link_ending_before_message_3_yields_closed() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();
    let ((init_sink, mut init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);
    let counting_sink = common::CountingSink::new(resp_sink);

    let (awaiting_response, msg1) = initiator.write_first().expect("message 1 writes");
    init_sink.send_record(&msg1).await.expect("message 1 sends");
    drop(init_sink);

    let result = handshake_as_responder(responder, &counting_sink, &mut *resp_source, &clock).await;

    assert_eq!(result.err(), Some(TransportError::Closed));
    assert_eq!(counting_sink.sends(), 1);

    let msg2 = init_source
        .recv_record()
        .await
        .expect("receive completes")
        .expect("message 2 arrives");
    awaiting_response
        .read_second(&msg2)
        .expect("the one record the responder sent is message 2");
}

#[tokio::test]
async fn message_1_corrupted_yields_authentication_failed_and_no_reply() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();
    let ((init_sink, _init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);
    let counting_sink = common::CountingSink::new(resp_sink);

    let (_awaiting_response, mut msg1) = initiator.write_first().expect("message 1 writes");
    let last = msg1.len() - 1;
    msg1[last] ^= 0xff;
    init_sink
        .send_record(&msg1)
        .await
        .expect("corrupted message 1 sends");

    let result = handshake_as_responder(responder, &counting_sink, &mut *resp_source, &clock).await;

    assert_eq!(result.err(), Some(TransportError::AuthenticationFailed));
    assert_eq!(counting_sink.sends(), 0);
}

#[tokio::test]
async fn message_3_corrupted_yields_authentication_failed() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let clock = SteppableClock::new();
    let ((init_sink, mut init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);

    let initiator_task = tokio::spawn(async move {
        let (awaiting_response, msg1) = initiator.write_first().expect("message 1 writes");
        init_sink.send_record(&msg1).await.expect("message 1 sends");
        let msg2 = init_source
            .recv_record()
            .await
            .expect("receive completes")
            .expect("message 2 arrives");
        let ready = awaiting_response
            .read_second(&msg2)
            .expect("second message is valid");
        let (_session, mut msg3) = ready.write_third().expect("third message writes");
        let last = msg3.len() - 1;
        msg3[last] ^= 0xff;
        init_sink
            .send_record(&msg3)
            .await
            .expect("corrupted message 3 sends");
    });

    let result = handshake_as_responder(responder, &*resp_sink, &mut *resp_source, &clock).await;
    initiator_task.await.expect("initiator task joins");

    assert_eq!(result.err(), Some(TransportError::AuthenticationFailed));
}

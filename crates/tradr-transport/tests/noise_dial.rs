mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use tradr_core::{BoxFuture, TransportError};
use tradr_transport::noise::{LinkSink, LinkSource, handshake_as_initiator};

#[tokio::test]
async fn full_handshake_completes_and_identifies_peers() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let ((init_sink, mut init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);

    let responder_task = tokio::spawn(async move {
        let msg1 = resp_source
            .recv_record()
            .await
            .expect("receive completes")
            .expect("message 1 arrives");
        let awaiting_reply = responder.read_first(&msg1).expect("first message is valid");
        let (awaiting_confirmation, msg2) = awaiting_reply
            .write_second()
            .expect("second message writes");
        resp_sink.send_record(&msg2).await.expect("message 2 sends");
        let msg3 = resp_source
            .recv_record()
            .await
            .expect("receive completes")
            .expect("message 3 arrives");
        awaiting_confirmation
            .read_third(&msg3)
            .expect("third message is valid")
    });

    let init_session = handshake_as_initiator(initiator, &*init_sink, &mut *init_source)
        .await
        .expect("initiator handshake completes");
    let resp_session = responder_task.await.expect("responder task joins");

    assert_eq!(init_session.peer(), pair.responder_store.device_id());
    assert_eq!(resp_session.peer(), pair.initiator_store.device_id());
}

struct CountingSource {
    inner: Box<dyn LinkSource>,
    receives: AtomicUsize,
}

impl CountingSource {
    fn new(inner: Box<dyn LinkSource>) -> Self {
        Self {
            inner,
            receives: AtomicUsize::new(0),
        }
    }
}

impl LinkSource for CountingSource {
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        self.receives.fetch_add(1, Ordering::SeqCst);
        self.inner.recv_record()
    }
}

#[tokio::test]
async fn exactly_three_records_cross_link_with_expected_count_direction_and_size() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let ((init_sink, init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);
    let counting_sink = common::CountingSink::new(init_sink);
    let mut counting_source = CountingSource::new(init_source);

    let responder_task = tokio::spawn(async move {
        let msg1 = resp_source
            .recv_record()
            .await
            .expect("receive completes")
            .expect("message 1 arrives");

        let awaiting_reply = responder.read_first(&msg1).expect("first message is valid");
        let (awaiting_confirmation, msg2) = awaiting_reply
            .write_second()
            .expect("second message writes");

        assert_eq!(msg2.len(), 299);
        resp_sink.send_record(&msg2).await.expect("message 2 sends");

        let msg3 = resp_source
            .recv_record()
            .await
            .expect("receive completes")
            .expect("message 3 arrives");

        let _resp_session = awaiting_confirmation
            .read_third(&msg3)
            .expect("third message is valid");
    });

    let _init_session = handshake_as_initiator(initiator, &counting_sink, &mut counting_source)
        .await
        .expect("initiator handshake completes");

    assert_eq!(counting_sink.sends(), 2);
    assert_eq!(counting_source.receives.load(Ordering::SeqCst), 1);

    responder_task.await.expect("responder task joins");
}

#[tokio::test]
async fn source_answering_none_before_message_2_yields_closed() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let ((init_sink, mut init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);

    // The memory pair is cross-wired, so dropping the responder's sink closes the initiator's source.
    drop(resp_sink);

    let result = handshake_as_initiator(initiator, &*init_sink, &mut *init_source).await;
    assert_eq!(result.err(), Some(TransportError::Closed));

    let msg1 = resp_source
        .recv_record()
        .await
        .expect("receive completes")
        .expect("message 1 arrives");
    assert!(!msg1.is_empty());
}

#[tokio::test]
async fn message_2_with_one_byte_flipped_yields_authentication_failed() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let responder = pair.responder();
    let ((init_sink, mut init_source), (resp_sink, mut resp_source)) =
        common::memory_link_pair(16, false);

    let responder_task = tokio::spawn(async move {
        let msg1 = resp_source
            .recv_record()
            .await
            .expect("receive completes")
            .expect("message 1 arrives");
        let awaiting_reply = responder.read_first(&msg1).expect("first message is valid");
        let (_awaiting_confirmation, mut msg2) = awaiting_reply
            .write_second()
            .expect("second message writes");

        msg2[0] ^= 0xff;
        resp_sink
            .send_record(&msg2)
            .await
            .expect("corrupted message 2 sends");
    });

    let result = handshake_as_initiator(initiator, &*init_sink, &mut *init_source).await;
    responder_task.await.expect("responder task joins");

    assert_eq!(result.err(), Some(TransportError::AuthenticationFailed));
}

struct FailingSink {
    error: TransportError,
    sends: AtomicUsize,
}

impl FailingSink {
    fn new(error: TransportError) -> Self {
        Self {
            error,
            sends: AtomicUsize::new(0),
        }
    }
}

impl LinkSink for FailingSink {
    fn send_record<'a>(&'a self, _record: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Err(self.error) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

struct EmptySource;

impl LinkSource for EmptySource {
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { Ok(None) })
    }
}

#[tokio::test]
async fn sink_failing_on_first_record_returns_error_unchanged_with_no_peer_record() {
    let pair = common::Pair::new();
    let initiator = pair.initiator();
    let expected_error = TransportError::Rejected;
    let failing_sink = FailingSink::new(expected_error);
    let mut source = EmptySource;

    let result = handshake_as_initiator(initiator, &failing_sink, &mut source).await;
    assert_eq!(result.err(), Some(expected_error));
    assert_eq!(failing_sink.sends.load(Ordering::SeqCst), 1);
}

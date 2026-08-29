//! Proves `SecureChannel` is dyn compatible and its futures are `Send`
//! (rule B5), driven to completion with no async runtime and no real
//! transport. See ADR-0013 and docs/03's "A transport delivers an
//! already-secure channel".

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tradr_core::{
    DEVICE_ID_LEN, DeviceId, RecvStream, SecureChannel, SendStream, TransportError, TransportId,
};

/// An in-memory double, real enough for `open_bi` to prove the trait is
/// usable; the accept side and `open_uni` are fixed rejections, since
/// nothing here drives them.
struct FakeChannel {
    peer: DeviceId,
    /// Both ends of the one bidirectional stream this double can open
    /// share this buffer, so a write on one side is visible to a read on
    /// the other.
    loopback: Arc<Mutex<VecDeque<u8>>>,
}

/// The `SendStream` half of `FakeChannel::open_bi`.
struct FakeSendStream {
    loopback: Arc<Mutex<VecDeque<u8>>>,
}

/// The `RecvStream` half of `FakeChannel::open_bi`.
struct FakeRecvStream {
    loopback: Arc<Mutex<VecDeque<u8>>>,
}

impl SendStream for FakeSendStream {
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> tradr_core::BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.loopback
                .lock()
                .expect("test-only mutex is never poisoned")
                .extend(buf.iter().copied());
            Ok(())
        })
    }

    fn finish<'a>(&'a mut self) -> tradr_core::BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

impl RecvStream for FakeRecvStream {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> tradr_core::BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            let mut queue = self
                .loopback
                .lock()
                .expect("test-only mutex is never poisoned");
            let n = queue.len().min(buf.len());
            for slot in buf.iter_mut().take(n) {
                *slot = queue.pop_front().expect("n was bounded by queue.len()");
            }
            Ok(n)
        })
    }
}

impl SecureChannel for FakeChannel {
    fn peer(&self) -> DeviceId {
        self.peer
    }

    fn transport(&self) -> TransportId {
        TransportId::new("fake")
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(10)
    }

    fn max_frame_size(&self) -> u32 {
        1024 * 1024
    }

    fn open_bi(
        &self,
    ) -> tradr_core::BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>>
    {
        let loopback = Arc::clone(&self.loopback);
        Box::pin(async move {
            Ok((
                Box::new(FakeSendStream {
                    loopback: Arc::clone(&loopback),
                }) as Box<dyn SendStream>,
                Box::new(FakeRecvStream { loopback }) as Box<dyn RecvStream>,
            ))
        })
    }

    fn open_uni(&self) -> tradr_core::BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Closed) })
    }

    fn accept_bi(
        &self,
    ) -> tradr_core::BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>>
    {
        Box::pin(async move { Err(TransportError::Closed) })
    }

    fn accept_uni(&self) -> tradr_core::BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Closed) })
    }

    fn close(&self) -> tradr_core::BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

// Compiles only if the future `F` produces is `Send`, the bound a
// multi-threaded executor needs (ADR-0013).
fn assert_send<F: Future + Send>(_: F) {}

#[test]
fn secure_channel_is_dyn_compatible_and_its_futures_run_to_completion_without_a_runtime() {
    let peer = DeviceId::from_bytes(&[7u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    let channel: Box<dyn SecureChannel> = Box::new(FakeChannel {
        peer,
        loopback: Arc::new(Mutex::new(VecDeque::new())),
    });

    assert_send(channel.open_bi());

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let mut opening = channel.open_bi();
    let (mut send, mut recv) = match opening.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(pair)) => pair,
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake channel must complete on the first poll"),
    };
    drop(opening);

    let mut writing = send.write_all(b"hello");
    match writing.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake channel must complete on the first poll"),
    }
    drop(writing);

    let mut buf = [0u8; 5];
    let mut reading = recv.read(&mut buf);
    let n = match reading.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => n,
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake channel must complete on the first poll"),
    };
    drop(reading);

    assert_eq!(&buf[..n], b"hello");
    assert_eq!(channel.peer(), peer);
}

#[test]
fn transport_id_is_usable_as_a_hashmap_key_and_equal_from_the_same_str() {
    let mut weights: HashMap<TransportId, u32> = HashMap::new();
    weights.insert(TransportId::new("direct-quic"), 100);
    weights.insert(TransportId::new("relay"), 20);

    assert_eq!(weights.get(&TransportId::new("direct-quic")), Some(&100));
    assert_eq!(weights.get(&TransportId::new("relay")), Some(&20));
    assert_eq!(
        TransportId::new("direct-quic"),
        TransportId::new("direct-quic")
    );
}

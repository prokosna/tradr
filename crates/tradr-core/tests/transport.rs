//! Tests for `Candidate` validation and for `Transport`'s dyn
//! compatibility (docs/03, "Path selection" and "What the core knows
//! about a transport"). See tests/channel.rs, the direct model for the
//! transport double below.

use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tradr_core::{
    Candidate, CandidateError, DEVICE_ID_LEN, DeviceId, Incoming, PUBLIC_KEY_POINT_LEN,
    PeerExpectation, PublicIdentity, PublicKeyPoint, RecvStream, SecureChannel, SendStream,
    Transport, TransportError, TransportId,
};

// Every address here is a real shape one of docs/03's five transports
// produces; rejecting any of them would present as an unreachable peer.
const TRANSPORT_PRODUCED_ADDRESSES: &[&str] = &[
    "192.168.1.42:51820",
    "192.168.1.42",
    "[2001:db8::1]:443",
    "[fe80::1%25eth0]:51820",
    "desktop.tail9f3c.ts.net:51820",
    "relay://brokr.example/x",
    "relay://brokr.example:8443/abcdef?token=zz",
    "handle:0x0042",
    "wifi-direct:DIRECT-Ab-Android_1234",
    "xn--n3h.example:443",
    "ホスト.example:443",
    "host with space:443",
    "a",
];

#[test]
fn candidate_accepts_every_address_shape_a_transport_produces() {
    let transport = TransportId::new("direct-quic");
    for address in TRANSPORT_PRODUCED_ADDRESSES {
        assert!(
            Candidate::new(transport, address).is_ok(),
            "{address:?} is a real transport address and must be accepted"
        );
    }
}

#[test]
fn candidate_reports_the_transport_and_address_it_was_built_from() {
    let transport = TransportId::new("relay");
    let candidate = Candidate::new(transport, "relay://brokr.example/x").expect("valid address");
    assert_eq!(candidate.transport(), transport);
    assert_eq!(candidate.address(), "relay://brokr.example/x");
}

#[test]
fn candidate_rejects_the_empty_address() {
    let transport = TransportId::new("direct-quic");
    assert_eq!(Candidate::new(transport, ""), Err(CandidateError::Empty));
}

#[test]
fn candidate_rejects_every_control_character() {
    let transport = TransportId::new("direct-quic");

    for byte in 0u8..=0x1f {
        let c = byte as char;
        let address = format!("host{c}port");
        assert_eq!(
            Candidate::new(transport, &address),
            Err(CandidateError::ControlCharacter(c)),
            "byte {byte:#04x} should have been rejected"
        );
    }

    let del = 0x7fu8 as char;
    let address = format!("host{del}port");
    assert_eq!(
        Candidate::new(transport, &address),
        Err(CandidateError::ControlCharacter(del))
    );
}

#[test]
fn device_id_reflects_the_expectations_variant() {
    let id = DeviceId::from_bytes(&[1u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    assert_eq!(PeerExpectation::Unpinned.device_id(), None);
    assert_eq!(PeerExpectation::Device(id).device_id(), Some(id));

    let identity_pub =
        PublicKeyPoint::from_bytes(&[2u8; PUBLIC_KEY_POINT_LEN]).expect("65 bytes must construct");
    let agreement_pub =
        PublicKeyPoint::from_bytes(&[3u8; PUBLIC_KEY_POINT_LEN]).expect("65 bytes must construct");
    let identity = PublicIdentity::new(identity_pub, agreement_pub, id);
    assert_eq!(
        PeerExpectation::Identity(identity.clone()).device_id(),
        Some(identity.device_id())
    );
}

#[test]
fn peer_expectation_equality_distinguishes_variants_and_device_ids() {
    let a = DeviceId::from_bytes(&[1u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    let b = DeviceId::from_bytes(&[2u8; DEVICE_ID_LEN]).expect("16 bytes must construct");

    assert_ne!(PeerExpectation::Unpinned, PeerExpectation::Device(a));
    assert_ne!(PeerExpectation::Device(a), PeerExpectation::Device(b));
    assert_eq!(PeerExpectation::Device(a), PeerExpectation::Device(a));
}

/// A `SecureChannel` double carrying only what these tests inspect: which
/// transport produced it and which peer it names. Every stream method is
/// a fixed rejection, since nothing here drives a stream.
struct FakeChannel {
    peer: DeviceId,
    id: TransportId,
}

impl SecureChannel for FakeChannel {
    fn peer(&self) -> DeviceId {
        self.peer
    }

    fn transport(&self) -> TransportId {
        self.id
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(5)
    }

    fn max_frame_size(&self) -> u32 {
        1024 * 1024
    }

    fn open_bi(
        &self,
    ) -> tradr_core::BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>>
    {
        Box::pin(async move { Err(TransportError::Closed) })
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

/// An in-memory `Transport` double whose `connect` always succeeds,
/// handing back a `FakeChannel` naming this transport and a fixed peer.
struct SucceedingTransport {
    id: TransportId,
    peer: DeviceId,
}

impl Transport for SucceedingTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn connect<'a>(
        &'a self,
        _candidate: &'a Candidate,
        _expect: &'a PeerExpectation,
    ) -> tradr_core::BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        let peer = self.peer;
        let id = self.id;
        Box::pin(async move { Ok(Box::new(FakeChannel { peer, id }) as Box<dyn SecureChannel>) })
    }

    fn listen(&self) -> tradr_core::BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async move { Err(TransportError::Closed) })
    }
}

/// An in-memory `Transport` double whose `connect` always fails, standing
/// in for a candidate that could not be reached.
struct FailingTransport {
    id: TransportId,
}

impl Transport for FailingTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn connect<'a>(
        &'a self,
        _candidate: &'a Candidate,
        _expect: &'a PeerExpectation,
    ) -> tradr_core::BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move { Err(TransportError::Unreachable) })
    }

    fn listen(&self) -> tradr_core::BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async move { Err(TransportError::Closed) })
    }
}

/// An in-memory `Transport` double that honours `expect`, standing in for
/// docs/03's obligation on `connect`: it refuses with
/// `TransportError::AuthenticationFailed` when `expect.device_id()` is
/// `Some` and differs from the peer it would otherwise hand back, and
/// succeeds when the expectation is `None` or matches.
struct HonouringTransport {
    id: TransportId,
    peer: DeviceId,
}

impl Transport for HonouringTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn connect<'a>(
        &'a self,
        _candidate: &'a Candidate,
        expect: &'a PeerExpectation,
    ) -> tradr_core::BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        let peer = self.peer;
        let id = self.id;
        let mismatch = expect.device_id().is_some_and(|expected| expected != peer);
        Box::pin(async move {
            if mismatch {
                Err(TransportError::AuthenticationFailed)
            } else {
                Ok(Box::new(FakeChannel { peer, id }) as Box<dyn SecureChannel>)
            }
        })
    }

    fn listen(&self) -> tradr_core::BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async move { Err(TransportError::Closed) })
    }
}

// Compiles only if the future `F` produces is `Send`, the bound a
// multi-threaded executor needs (ADR-0013).
fn assert_send<F: Future + Send>(_: F) {}

#[test]
fn transport_is_dyn_compatible_and_connect_runs_to_completion_without_a_runtime() {
    let peer = DeviceId::from_bytes(&[9u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    let id = TransportId::new("fake");
    let transport: Box<dyn Transport> = Box::new(SucceedingTransport { id, peer });
    let candidate = Candidate::new(transport.id(), "handle:0x0042").expect("valid address");
    let expect = PeerExpectation::Unpinned;

    assert_send(transport.connect(&candidate, &expect));

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let mut connecting = transport.connect(&candidate, &expect);
    let channel = match connecting.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(channel)) => channel,
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake transport must complete on the first poll"),
    };
    drop(connecting);

    assert_eq!(channel.peer(), peer);
    assert_eq!(channel.transport(), id);
}

#[test]
fn a_heterogeneous_set_of_transports_races_and_adopts_the_successful_one() {
    let peer = DeviceId::from_bytes(&[3u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    let failing_id = TransportId::new("failing");
    let succeeding_id = TransportId::new("succeeding");

    let transports: Vec<Box<dyn Transport>> = vec![
        Box::new(FailingTransport { id: failing_id }),
        Box::new(SucceedingTransport {
            id: succeeding_id,
            peer,
        }),
    ];

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let expect = PeerExpectation::Unpinned;
    let mut adopted: Option<Box<dyn SecureChannel>> = None;
    for transport in &transports {
        let candidate = Candidate::new(transport.id(), "handle:0x0042").expect("valid address");
        let mut connecting = transport.connect(&candidate, &expect);
        if let Poll::Ready(Ok(channel)) = connecting.as_mut().poll(&mut cx) {
            adopted = Some(channel);
            break;
        }
    }

    let adopted = adopted.expect("the succeeding transport must have produced a channel");
    assert_eq!(adopted.transport(), succeeding_id);
    assert_eq!(adopted.peer(), peer);
}

#[test]
fn a_transport_that_honours_the_expectation_refuses_a_mismatch_and_accepts_the_rest() {
    let peer = DeviceId::from_bytes(&[4u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    let other = DeviceId::from_bytes(&[5u8; DEVICE_ID_LEN]).expect("16 bytes must construct");
    let id = TransportId::new("honouring");
    let transport: Box<dyn Transport> = Box::new(HonouringTransport { id, peer });
    let candidate = Candidate::new(transport.id(), "handle:0x0042").expect("valid address");

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    // Unpinned: no prior expectation, so the proven key is accepted.
    let mut connecting = transport.connect(&candidate, &PeerExpectation::Unpinned);
    match connecting.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(channel)) => assert_eq!(channel.peer(), peer),
        Poll::Ready(Err(e)) => panic!("Unpinned must accept the peer, got error: {e}"),
        Poll::Pending => panic!("a fake transport must complete on the first poll"),
    }

    // Device(peer): matches, so it is accepted.
    let matching = PeerExpectation::Device(peer);
    let mut connecting = transport.connect(&candidate, &matching);
    match connecting.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(channel)) => assert_eq!(channel.peer(), peer),
        Poll::Ready(Err(e)) => panic!("a matching expectation must accept the peer, got: {e}"),
        Poll::Pending => panic!("a fake transport must complete on the first poll"),
    }

    // Device(other): does not match, so it is refused.
    let mismatched = PeerExpectation::Device(other);
    let mut connecting = transport.connect(&candidate, &mismatched);
    match connecting.as_mut().poll(&mut cx) {
        Poll::Ready(Err(TransportError::AuthenticationFailed)) => {}
        Poll::Ready(Ok(_)) => panic!("a mismatched expectation must be refused"),
        Poll::Ready(Err(e)) => panic!("wrong error for a mismatch: {e}"),
        Poll::Pending => panic!("a fake transport must complete on the first poll"),
    }
}

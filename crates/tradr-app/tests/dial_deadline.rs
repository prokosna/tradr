//! WI-M8-082: candidate dials give up after three seconds (docs/03, DCR-192).

use std::sync::Arc;
use std::time::Duration;

use tradr_app::peers::{DIAL_DEADLINE, ResolvedPeer, connect_and_pin};
use tradr_core::{
    BoxFuture, Candidate, DeviceId, Incoming, PeerExpectation, RecvStream, SecureChannel,
    SendStream, Transport, TransportError, TransportId,
};
use tradr_discovery::StaticPeerRegistry;
use tradr_transport::set::TransportSet;

const DIRECT_QUIC: TransportId = TransportId::new("direct-quic");
const QUIC_ADDRESS: &str = "192.168.1.42:21820";

enum ConnectAction {
    NeverCompletes,
    RefuseImmediately(TransportError),
    SucceedAfter(Duration),
}

struct MinimalSecureChannel {
    peer_id: DeviceId,
    transport_id: TransportId,
}

impl SecureChannel for MinimalSecureChannel {
    fn peer(&self) -> DeviceId {
        self.peer_id
    }

    fn transport(&self) -> TransportId {
        self.transport_id
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(5)
    }

    fn max_frame_size(&self) -> u32 {
        65536
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async { Ok(()) })
    }
}

struct StubTransport {
    id: TransportId,
    action: ConnectAction,
    peer_id: DeviceId,
}

impl Transport for StubTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn connect<'a>(
        &'a self,
        _candidate: &'a Candidate,
        _expect: &'a PeerExpectation,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            match self.action {
                ConnectAction::NeverCompletes => {
                    std::future::pending::<Result<Box<dyn SecureChannel>, TransportError>>().await
                }
                ConnectAction::RefuseImmediately(err) => Err(err),
                ConnectAction::SucceedAfter(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(Box::new(MinimalSecureChannel {
                        peer_id: self.peer_id,
                        transport_id: self.id,
                    }) as Box<dyn SecureChannel>)
                }
            }
        })
    }

    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }
}

fn empty_registry(dir: &tempfile::TempDir) -> StaticPeerRegistry {
    let (registry, _source) = StaticPeerRegistry::load(&dir.path().join("static-peers.json"))
        .expect("load empty registry");
    registry
}

fn quic_candidate() -> Candidate {
    Candidate::new(DIRECT_QUIC, QUIC_ADDRESS).expect("valid quic candidate")
}

#[tokio::test(start_paused = true)]
async fn never_completing_dial_fails_with_deadline_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = tokio::sync::Mutex::new(empty_registry(&dir));
    let transport = Arc::new(StubTransport {
        id: DIRECT_QUIC,
        action: ConnectAction::NeverCompletes,
        peer_id: DeviceId::from_bytes(&[1u8; 16]).expect("valid device id"),
    });
    let transports = TransportSet::new(vec![transport]);
    let resolved = ResolvedPeer {
        candidate: quic_candidate(),
        expectation: PeerExpectation::Unpinned,
        pin_target: None,
    };

    let err = match connect_and_pin(&transports, &registry, resolved).await {
        Ok(_) => panic!("never-completing dial must fail on deadline"),
        Err(e) => e,
    };

    assert_eq!(DIAL_DEADLINE, Duration::from_secs(3));
    let expected =
        format!("failed to connect to peer at {QUIC_ADDRESS}: no answer within 3 seconds");
    assert_eq!(err, expected);
}

#[tokio::test(start_paused = true)]
async fn never_completing_dial_is_still_pending_before_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = tokio::sync::Mutex::new(empty_registry(&dir));
    let transport = Arc::new(StubTransport {
        id: DIRECT_QUIC,
        action: ConnectAction::NeverCompletes,
        peer_id: DeviceId::from_bytes(&[1u8; 16]).expect("valid device id"),
    });
    let transports = TransportSet::new(vec![transport]);
    let resolved = ResolvedPeer {
        candidate: quic_candidate(),
        expectation: PeerExpectation::Unpinned,
        pin_target: None,
    };

    let mut dial_future = std::pin::pin!(connect_and_pin(&transports, &registry, resolved));

    tokio::select! {
        biased;
        res = &mut dial_future => {
            let desc = match res {
                Ok(_) => "succeeded",
                Err(ref e) => e.as_str(),
            };
            panic!("dial completed prematurely before deadline: {desc}");
        }
        () = tokio::time::sleep(Duration::from_millis(2900)) => {}
    }

    let err = match dial_future.await {
        Ok(_) => panic!("dial unexpectedly succeeded at deadline"),
        Err(e) => e,
    };
    assert!(err.contains("no answer within 3 seconds"), "{err}");
}

#[tokio::test(start_paused = true)]
async fn immediate_refusal_returns_own_error_not_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = tokio::sync::Mutex::new(empty_registry(&dir));
    let transport = Arc::new(StubTransport {
        id: DIRECT_QUIC,
        action: ConnectAction::RefuseImmediately(TransportError::Rejected),
        peer_id: DeviceId::from_bytes(&[1u8; 16]).expect("valid device id"),
    });
    let transports = TransportSet::new(vec![transport]);
    let resolved = ResolvedPeer {
        candidate: quic_candidate(),
        expectation: PeerExpectation::Unpinned,
        pin_target: None,
    };

    let err = match connect_and_pin(&transports, &registry, resolved).await {
        Ok(_) => panic!("immediate refusal must fail"),
        Err(e) => e,
    };

    let expected = format!(
        "failed to connect to peer at {QUIC_ADDRESS}: {}",
        TransportError::Rejected
    );
    assert_eq!(err, expected);
    assert!(!err.contains("no answer within"), "{err}");
}

#[tokio::test(start_paused = true)]
async fn connection_succeeding_before_deadline_is_not_cut_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = tokio::sync::Mutex::new(empty_registry(&dir));
    let peer_id = DeviceId::from_bytes(&[2u8; 16]).expect("valid device id");
    let transport = Arc::new(StubTransport {
        id: DIRECT_QUIC,
        action: ConnectAction::SucceedAfter(Duration::from_secs(2)),
        peer_id,
    });
    let transports = TransportSet::new(vec![transport]);
    let resolved = ResolvedPeer {
        candidate: quic_candidate(),
        expectation: PeerExpectation::Unpinned,
        pin_target: None,
    };

    let channel = match connect_and_pin(&transports, &registry, resolved).await {
        Ok(c) => c,
        Err(e) => panic!("dial should succeed before deadline: {e}"),
    };

    assert_eq!(channel.peer(), peer_id);
    assert_eq!(channel.transport(), DIRECT_QUIC);
}

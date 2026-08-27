//! Integration tests for `perform_handshake` driving the 4-step Hello exchange
//! over connected SendStream and RecvStream pairs.

use std::cell::Cell;
use std::time::Instant;

use tauri_plugin_tradr::handshake::{HandshakeError, HandshakeParams, perform_handshake};
use tradr_core::{
    BoxFuture, Capabilities, Clock, DeviceId, DomainTag, KeyBinding, KeyStore, Monotonic,
    PublicIdentity, RecvStream, Rng, RngError, SendStream, TransportError, TrustTier, UnixTime,
    VersionRange,
};
use tradr_identity::SoftwareKeyStore;
use tradr_identity::hello::HelloRefused;
use tradr_proto::framing::encode_frame;
use tradr_proto::hello::HelloFrameError;
use tradr_proto::message_type::MessageType;

// ---- Test doubles --------------------------------------------------------

struct SeededRng {
    state: Cell<u64>,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self {
            state: Cell::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
        }
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        for slot in buf.iter_mut() {
            let mut x = self.state.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state.set(x);
            *slot = (x >> 24) as u8;
        }
        Ok(())
    }
}

struct FakeClock {
    now: UnixTime,
}

impl Clock for FakeClock {
    fn now(&self) -> UnixTime {
        self.now
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(Instant::now())
    }
}

struct MemorySendStream {
    sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl SendStream for MemorySendStream {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let sender = self.sender.as_ref().ok_or(TransportError::Closed)?;
            sender
                .send(buf.to_vec())
                .await
                .map_err(|_| TransportError::Closed)?;
            Ok(())
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.sender = None;
            Ok(())
        })
    }
}

struct MemoryRecvStream {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buffered: Vec<u8>,
}

impl RecvStream for MemoryRecvStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            if self.buffered.is_empty() {
                match self.receiver.recv().await {
                    Some(chunk) => self.buffered = chunk,
                    None => return Ok(0),
                }
            }
            let to_read = self.buffered.len().min(buf.len());
            buf[..to_read].copy_from_slice(&self.buffered[..to_read]);
            self.buffered.drain(..to_read);
            Ok(to_read)
        })
    }
}

fn memory_stream_pair() -> (
    (MemorySendStream, MemoryRecvStream),
    (MemorySendStream, MemoryRecvStream),
) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(32);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(32);
    let peer_a = (
        MemorySendStream {
            sender: Some(tx_a_to_b),
        },
        MemoryRecvStream {
            receiver: rx_b_to_a,
            buffered: Vec::new(),
        },
    );
    let peer_b = (
        MemorySendStream {
            sender: Some(tx_b_to_a),
        },
        MemoryRecvStream {
            receiver: rx_a_to_b,
            buffered: Vec::new(),
        },
    );
    (peer_a, peer_b)
}

const NOW: i64 = 1_800_000_000;
const LATER: i64 = NOW + 86_400;

fn device(seed: u64) -> SoftwareKeyStore {
    SoftwareKeyStore::generate(&SeededRng::new(seed)).expect("a seeded generate must succeed")
}

fn identity_of(store: &SoftwareKeyStore) -> PublicIdentity {
    store.public_identity().expect("a generated store has one")
}

fn binding_for(store: &SoftwareKeyStore, not_after: i64) -> KeyBinding {
    let id = identity_of(store);
    let signature = store
        .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
        .expect("signing under KeyBind must succeed");
    KeyBinding::new(
        id.agreement_pub().clone(),
        signature,
        UnixTime::from_secs(not_after),
    )
}

// ---- Integration Tests ---------------------------------------------------

#[tokio::test]
async fn two_peers_complete_handshake_over_connected_streams() {
    let dev_a = device(1);
    let dev_b = device(2);
    let id_a = identity_of(&dev_a);
    let id_b = identity_of(&dev_b);
    let dev_id_a = id_a.device_id();
    let dev_id_b = id_b.device_id();

    let ((mut send_a, mut recv_a), (mut send_b, mut recv_b)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng_a = SeededRng::new(10);
    let rng_b = SeededRng::new(20);

    let params_a = HandshakeParams {
        authenticated_peer: dev_id_b,
        our_channel_max_frame_size: 65536,
        our_identity: &id_a,
        our_attestation_token: "token_a".to_string(),
        our_key_binding: binding_for(&dev_a, LATER),
        our_versions: VersionRange::new(1, 2).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let params_b = HandshakeParams {
        authenticated_peer: dev_id_a,
        our_channel_max_frame_size: 65536,
        our_identity: &id_b,
        our_attestation_token: "token_b".to_string(),
        our_key_binding: binding_for(&dev_b, LATER),
        our_versions: VersionRange::new(1, 3).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let handshake_a = perform_handshake(
        &mut send_a,
        &mut recv_a,
        params_a,
        &dev_a,
        &rng_a,
        &clock,
        |_| async { Ok(TrustTier::Linked) },
    );

    let handshake_b = perform_handshake(
        &mut send_b,
        &mut recv_b,
        params_b,
        &dev_b,
        &rng_b,
        &clock,
        |_| async { Ok(TrustTier::SameAccount) },
    );

    let (res_a, res_b) = tokio::join!(handshake_a, handshake_b);
    let session_a = res_a.expect("peer A handshake must succeed");
    let session_b = res_b.expect("peer B handshake must succeed");

    assert_eq!(session_a.peer(), dev_id_b);
    assert_eq!(session_b.peer(), dev_id_a);
    assert_eq!(session_a.tier(), TrustTier::Linked);
    assert_eq!(session_b.tier(), TrustTier::SameAccount);
    assert_eq!(session_a.negotiated_version(), 2);
    assert_eq!(session_b.negotiated_version(), 2);
    assert_eq!(session_a.peer_max_frame_size(), 65536);
    assert_eq!(session_b.peer_max_frame_size(), 65536);
}

#[tokio::test]
async fn version_mismatch_fails_handshake() {
    let dev_a = device(1);
    let dev_b = device(2);
    let id_a = identity_of(&dev_a);
    let id_b = identity_of(&dev_b);
    let dev_id_a = id_a.device_id();
    let dev_id_b = id_b.device_id();

    let ((mut send_a, mut recv_a), (mut send_b, mut recv_b)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng_a = SeededRng::new(10);
    let rng_b = SeededRng::new(20);

    let params_a = HandshakeParams {
        authenticated_peer: dev_id_b,
        our_channel_max_frame_size: 65536,
        our_identity: &id_a,
        our_attestation_token: "token_a".to_string(),
        our_key_binding: binding_for(&dev_a, LATER),
        our_versions: VersionRange::new(1, 2).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let params_b = HandshakeParams {
        authenticated_peer: dev_id_a,
        our_channel_max_frame_size: 65536,
        our_identity: &id_b,
        our_attestation_token: "token_b".to_string(),
        our_key_binding: binding_for(&dev_b, LATER),
        our_versions: VersionRange::new(3, 4).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let handshake_a = perform_handshake(
        &mut send_a,
        &mut recv_a,
        params_a,
        &dev_a,
        &rng_a,
        &clock,
        |_| async { Ok(TrustTier::Linked) },
    );

    let handshake_b = perform_handshake(
        &mut send_b,
        &mut recv_b,
        params_b,
        &dev_b,
        &rng_b,
        &clock,
        |_| async { Ok(TrustTier::SameAccount) },
    );

    let (res_a, res_b) = tokio::join!(handshake_a, handshake_b);
    let err_a = res_a.expect_err("peer A must fail handshake");
    let err_b = res_b.expect_err("peer B must fail handshake");

    assert!(matches!(
        err_a,
        HandshakeError::Refused(HelloRefused::NoCommonVersion(_))
    ));
    assert!(matches!(
        err_b,
        HandshakeError::Refused(HelloRefused::NoCommonVersion(_))
    ));
}

#[tokio::test]
async fn key_join_mismatch_fails_handshake() {
    let dev_a = device(1);
    let dev_b = device(2);
    let dev_c = device(3);
    let id_a = identity_of(&dev_a);
    let id_b = identity_of(&dev_b);
    let id_c = identity_of(&dev_c);
    let dev_id_a = id_a.device_id();
    let dev_id_c = id_c.device_id();

    let ((mut send_a, mut recv_a), (mut send_b, mut recv_b)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng_a = SeededRng::new(10);
    let rng_b = SeededRng::new(20);

    // Peer A expects device C over the channel, but peer B connects and speaks with device B's key.
    let params_a = HandshakeParams {
        authenticated_peer: dev_id_c,
        our_channel_max_frame_size: 65536,
        our_identity: &id_a,
        our_attestation_token: "token_a".to_string(),
        our_key_binding: binding_for(&dev_a, LATER),
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let params_b = HandshakeParams {
        authenticated_peer: dev_id_a,
        our_channel_max_frame_size: 65536,
        our_identity: &id_b,
        our_attestation_token: "token_b".to_string(),
        our_key_binding: binding_for(&dev_b, LATER),
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let handshake_a = perform_handshake(
        &mut send_a,
        &mut recv_a,
        params_a,
        &dev_a,
        &rng_a,
        &clock,
        |_| async { Ok(TrustTier::Linked) },
    );

    let handshake_b = perform_handshake(
        &mut send_b,
        &mut recv_b,
        params_b,
        &dev_b,
        &rng_b,
        &clock,
        |_| async { Ok(TrustTier::SameAccount) },
    );

    let res = tokio::try_join!(handshake_a, handshake_b);
    let err_a = res.expect_err("peer A must refuse key join mismatch");

    match err_a {
        HandshakeError::Refused(HelloRefused::KeyDoesNotMatchChannel {
            authenticated,
            claimed,
        }) => {
            assert_eq!(authenticated, dev_id_c);
            assert_eq!(claimed, id_b.device_id());
        }
        other => panic!("expected KeyDoesNotMatchChannel, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_message_type_fails_handshake() {
    let dev_a = device(1);
    let id_a = identity_of(&dev_a);
    let dev_id_b = DeviceId::from_bytes(&[0x42; 16]).expect("valid device id");

    let ((mut send_a, mut recv_a), (mut send_b, _recv_b)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng_a = SeededRng::new(10);

    let non_hello_frame = encode_frame(MessageType::KeepAlive.code(), &[], 65536)
        .expect("framing raw bytes must succeed");
    send_b
        .write_all(&non_hello_frame)
        .await
        .expect("sending non-hello frame must succeed");

    let params_a = HandshakeParams {
        authenticated_peer: dev_id_b,
        our_channel_max_frame_size: 65536,
        our_identity: &id_a,
        our_attestation_token: "token_a".to_string(),
        our_key_binding: binding_for(&dev_a, LATER),
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let err = perform_handshake(
        &mut send_a,
        &mut recv_a,
        params_a,
        &dev_a,
        &rng_a,
        &clock,
        |_| async { Ok(TrustTier::Linked) },
    )
    .await
    .expect_err("handshake must fail on non-Hello frame");

    assert!(matches!(
        err,
        HandshakeError::Proto(HelloFrameError::WrongMessageType {
            expected: 0x01,
            got: 0x09,
        })
    ));
}

#[tokio::test]
async fn unexpected_eof_fails_handshake() {
    let dev_a = device(1);
    let id_a = identity_of(&dev_a);
    let dev_id_b = DeviceId::from_bytes(&[0x42; 16]).expect("valid device id");

    let ((mut send_a, mut recv_a), (mut send_b, _recv_b)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng_a = SeededRng::new(10);

    send_b.finish().await.expect("closing stream must succeed");

    let params_a = HandshakeParams {
        authenticated_peer: dev_id_b,
        our_channel_max_frame_size: 65536,
        our_identity: &id_a,
        our_attestation_token: "token_a".to_string(),
        our_key_binding: binding_for(&dev_a, LATER),
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let err = perform_handshake(
        &mut send_a,
        &mut recv_a,
        params_a,
        &dev_a,
        &rng_a,
        &clock,
        |_| async { Ok(TrustTier::Linked) },
    )
    .await
    .expect_err("handshake must fail when peer stream closes immediately");

    assert!(matches!(err, HandshakeError::UnexpectedEof));
}

#[tokio::test]
async fn attestation_verification_failure_fails_handshake() {
    let dev_a = device(1);
    let dev_b = device(2);
    let id_a = identity_of(&dev_a);
    let id_b = identity_of(&dev_b);
    let dev_id_a = id_a.device_id();
    let dev_id_b = id_b.device_id();

    let ((mut send_a, mut recv_a), (mut send_b, mut recv_b)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng_a = SeededRng::new(10);
    let rng_b = SeededRng::new(20);

    let params_a = HandshakeParams {
        authenticated_peer: dev_id_b,
        our_channel_max_frame_size: 65536,
        our_identity: &id_a,
        our_attestation_token: "token_a".to_string(),
        our_key_binding: binding_for(&dev_a, LATER),
        our_versions: VersionRange::new(1, 2).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let params_b = HandshakeParams {
        authenticated_peer: dev_id_a,
        our_channel_max_frame_size: 65536,
        our_identity: &id_b,
        our_attestation_token: "token_b".to_string(),
        our_key_binding: binding_for(&dev_b, LATER),
        our_versions: VersionRange::new(1, 2).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let handshake_a = perform_handshake(
        &mut send_a,
        &mut recv_a,
        params_a,
        &dev_a,
        &rng_a,
        &clock,
        |_| async { Err("invalid token signature".to_string()) },
    );

    let handshake_b = perform_handshake(
        &mut send_b,
        &mut recv_b,
        params_b,
        &dev_b,
        &rng_b,
        &clock,
        |_| async { Ok(TrustTier::SameAccount) },
    );

    let res = tokio::try_join!(handshake_a, handshake_b);
    let err_a = res.expect_err("peer A must fail verification");

    assert!(matches!(err_a, HandshakeError::Attestation(_)));
}

//! Tests for `send_link_reply`, the replier's half of the link exchange
//! (docs/11-account-linking.md), and for `listener.rs`'s branch on a
//! Control stream's first frame (docs/04-protocol.md, "Deciding which of
//! the two a stream is"). `tests/link_exchange.rs` is the Supervisor's and
//! covers the inviter's half; this file covers the rest.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tauri_plugin_tradr::handshake::{HandshakeParams, perform_handshake};
use tauri_plugin_tradr::link_exchange::{
    InviterParams, LinkAttestationRequest, LinkDecision, LinkExchangeError, LinkOutcome,
    LinkProposal, ReplierParams, send_link_reply, serve_link_reply,
};
use tauri_plugin_tradr::listener::{
    LinkStreamService, ListenerError, ListenerParams, handle_incoming_channel,
};
use tauri_plugin_tradr::peer_trust::OwnAttestation;
use tradr_core::{
    BoxFuture, Capabilities, Clock, DeviceId, DomainTag, HalfSecret, Invite, InviteId, KeyBinding,
    KeyStore, LinkApprove, LinkDecline, LinkDeclineReason, LinkId, LinkReply, LinkSecret,
    Monotonic, PublicIdentity, RecvStream, Rng, RngError, RootId, SecureChannel, SendStream,
    TransportError, TransportId, TrustTier, UnixTime, VersionRange,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{AccountId, Link, SoftwareKeyStore, derive_link_id, derive_link_secret};
use tradr_integrity::BaoVerifier;
use tradr_proto::framing::{Frame, FrameDecoder, encode_frame};
use tradr_proto::link::{
    decode_link_reply_frame, encode_link_approve_frame, encode_link_decline_frame,
    encode_link_reply_frame,
};
use tradr_proto::message_type::MessageType;
use tradr_vfs::NativeVfs;

// ---- Test doubles (mirrors tests/handshake.rs and tests/listener.rs) ----

struct SeededRng {
    state: AtomicU64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
        }
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        for slot in buf.iter_mut() {
            let mut x = self.state.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state.store(x, Ordering::Relaxed);
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

// Reads exactly one frame off a raw memory stream, the way a hand-driven
// script on the other end of the wire would.
async fn read_one_frame(recv: &mut MemoryRecvStream, max_frame_size: u32) -> Frame {
    let mut len_bytes = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = recv.read(&mut len_bytes[got..]).await.expect("read");
        assert!(n > 0, "stream closed before a full length prefix arrived");
        got += n;
    }
    let announced = u32::from_be_bytes(len_bytes);
    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    let mut got_payload = 0;
    while got_payload < announced as usize {
        let n = recv.read(&mut raw[4 + got_payload..]).await.expect("read");
        assert!(n > 0, "stream closed before the announced payload arrived");
        got_payload += n;
    }
    let mut decoder = FrameDecoder::new(max_frame_size);
    decoder.feed(&raw);
    decoder
        .next_frame()
        .expect("framing must decode")
        .expect("a whole frame was fed")
}

type StreamPair = (Box<dyn SendStream>, Box<dyn RecvStream>);

struct MockSecureChannel {
    peer_id: DeviceId,
    transport_id: TransportId,
    max_frame_size: u32,
    bi_tx: tokio::sync::mpsc::Sender<StreamPair>,
    bi_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<StreamPair>>,
}

impl SecureChannel for MockSecureChannel {
    fn peer(&self) -> DeviceId {
        self.peer_id
    }

    fn transport(&self) -> TransportId {
        self.transport_id
    }

    fn rtt(&self) -> std::time::Duration {
        std::time::Duration::from_millis(5)
    }

    fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    fn open_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        Box::pin(async move {
            let (peer_a, peer_b) = memory_stream_pair();
            let bi_b: StreamPair = (Box::new(peer_b.0), Box::new(peer_b.1));
            self.bi_tx
                .send(bi_b)
                .await
                .map_err(|_| TransportError::Closed)?;
            let bi_a: StreamPair = (Box::new(peer_a.0), Box::new(peer_a.1));
            Ok(bi_a)
        })
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        Box::pin(async move {
            let mut rx = self.bi_rx.lock().await;
            rx.recv().await.ok_or(TransportError::Closed)
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

fn mock_channel_pair(
    peer_a_id: DeviceId,
    peer_b_id: DeviceId,
    max_frame_size: u32,
) -> (MockSecureChannel, MockSecureChannel) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(16);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(16);

    let chan_a = MockSecureChannel {
        peer_id: peer_b_id,
        transport_id: TransportId::new("memory"),
        max_frame_size,
        bi_tx: tx_a_to_b,
        bi_rx: tokio::sync::Mutex::new(rx_b_to_a),
    };
    let chan_b = MockSecureChannel {
        peer_id: peer_a_id,
        transport_id: TransportId::new("memory"),
        max_frame_size,
        bi_tx: tx_b_to_a,
        bi_rx: tokio::sync::Mutex::new(rx_a_to_b),
    };
    (chan_a, chan_b)
}

// A fixed own-attestation for tests that never exercise sign-in itself.
struct FixedAttestation(String);

impl OwnAttestation for FixedAttestation {
    fn id_token(&self) -> Option<String> {
        Some(self.0.clone())
    }
}

// Records whether `serve` was reached at all, so the listener's dispatch
// can be checked without exercising the link exchange logic itself, which
// `tests/link_exchange.rs` and this file's own replier tests already do.
struct RecordingLinkService {
    reached: Arc<Mutex<bool>>,
}

impl LinkStreamService for RecordingLinkService {
    fn serve<'a>(
        &'a self,
        _send: &'a mut dyn SendStream,
        _reply: LinkReply,
        _authenticated_peer: DeviceId,
        _max_frame_size: u32,
    ) -> BoxFuture<'a, Result<LinkOutcome, LinkExchangeError>> {
        *self.reached.lock().expect("not poisoned") = true;
        Box::pin(async move {
            Ok(LinkOutcome::Declined {
                reason: None,
                detail: None,
            })
        })
    }
}

const NOW: i64 = 1_800_000_000;
const MAX_FRAME: u32 = 65536;

fn device(seed: u64) -> SoftwareKeyStore {
    SoftwareKeyStore::generate(&SeededRng::new(seed)).expect("a seeded generate must succeed")
}

fn identity_of(store: &SoftwareKeyStore) -> PublicIdentity {
    store.public_identity().expect("a generated store has one")
}

fn half(byte: u8) -> HalfSecret {
    HalfSecret::from_bytes(&[byte; 16]).expect("16 bytes always fit a HalfSecret")
}

fn invite_id(byte: u8) -> InviteId {
    InviteId::from_bytes(&[byte; 16]).expect("16 bytes always fit an InviteId")
}

fn open_invite(alice: &PublicIdentity, id: InviteId, expires_at: i64) -> Invite {
    Invite::new(
        id,
        alice.identity_pub().clone(),
        alice.agreement_pub().clone(),
        "alice_token".to_string(),
        half(0xa1),
        UnixTime::from_secs(expires_at),
    )
}

fn peer_account() -> AccountId {
    AccountId::new("https://accounts.google.com", "9273")
}

fn key_binding_for(
    store: &SoftwareKeyStore,
    identity: &PublicIdentity,
    not_after: i64,
) -> KeyBinding {
    let sig = store
        .sign(DomainTag::KeyBind, identity.agreement_pub().as_bytes())
        .expect("signing under KeyBind must succeed");
    KeyBinding::new(
        identity.agreement_pub().clone(),
        sig,
        UnixTime::from_secs(not_after),
    )
}

// ---- The replier's side: send_link_reply ----------------------------------

#[tokio::test]
async fn replier_completes_against_a_scripted_approve() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let recorded: Arc<Mutex<Option<(AccountId, LinkId)>>> = Arc::new(Mutex::new(None));
    let recorded_clone = Arc::clone(&recorded);

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        move |link: Link, _secret: LinkSecret| {
            *recorded_clone.lock().expect("not poisoned") =
                Some((link.peer_account().clone(), link.link_id()));
            Ok(())
        },
    );

    let inviter_task = async {
        let frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        let reply = decode_link_reply_frame(&frame).expect("bob's reply decodes");
        assert_eq!(reply.invite_id(), &id);
        let our_link_id = derive_link_id(&derive_link_secret(
            invite.half_secret(),
            reply.half_secret(),
        ));
        let approve = LinkApprove::new(id, our_link_id);
        let frame_bytes = encode_link_approve_frame(&approve, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
        our_link_id
    };

    let (outcome, expected_link_id) = tokio::join!(replier_task, inviter_task);
    let outcome = outcome.expect("a scripted approve completes");
    assert_eq!(outcome, LinkOutcome::Linked(expected_link_id));

    let (account, link_id) = recorded
        .lock()
        .expect("not poisoned")
        .clone()
        .expect("record was called");
    assert_eq!(account, peer_account());
    assert_eq!(link_id, expected_link_id);
}

#[tokio::test]
async fn replier_completes_against_a_scripted_decline() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let recorded = Arc::new(Mutex::new(false));
    let recorded_flag = Arc::clone(&recorded);

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        move |_link: Link, _secret: LinkSecret| {
            *recorded_flag.lock().expect("not poisoned") = true;
            Ok(())
        },
    );

    let inviter_task = async {
        let _frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        let decline = LinkDecline::new(id, Some(LinkDeclineReason::UserDeclined));
        let frame_bytes = encode_link_decline_frame(&decline, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    let outcome = outcome.expect("a scripted decline completes");
    assert_eq!(
        outcome,
        LinkOutcome::Declined {
            reason: Some(LinkDeclineReason::UserDeclined),
            detail: None,
        }
    );
    assert!(!*recorded.lock().expect("not poisoned"));
}

#[tokio::test]
async fn a_wrong_link_id_in_approve_is_refused_and_records_nothing() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let recorded = Arc::new(Mutex::new(false));
    let recorded_flag = Arc::clone(&recorded);

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        move |_link: Link, _secret: LinkSecret| {
            *recorded_flag.lock().expect("not poisoned") = true;
            Ok(())
        },
    );

    let inviter_task = async {
        let _frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        // A well-formed LinkId that is deliberately not the one either
        // side would derive from these two halves.
        let wrong_link_id = derive_link_id(&derive_link_secret(&half(0xff), &half(0xee)));
        let approve = LinkApprove::new(id, wrong_link_id);
        let frame_bytes = encode_link_approve_frame(&approve, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(matches!(outcome, Err(LinkExchangeError::LinkIdMismatch)));
    assert!(!*recorded.lock().expect("not poisoned"));
}

#[tokio::test]
async fn an_approve_naming_another_invite_is_refused() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    );

    let inviter_task = async {
        let frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        let reply = decode_link_reply_frame(&frame).expect("decodes");
        let our_link_id = derive_link_id(&derive_link_secret(
            invite.half_secret(),
            reply.half_secret(),
        ));
        let approve = LinkApprove::new(invite_id(0x02), our_link_id);
        let frame_bytes = encode_link_approve_frame(&approve, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(matches!(outcome, Err(LinkExchangeError::UnknownInvite)));
}

#[tokio::test]
async fn a_decline_naming_another_invite_is_refused() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    );

    let inviter_task = async {
        let _frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        let decline =
            LinkDecline::new(invite_id(0x02), Some(LinkDeclineReason::VerificationFailed));
        let frame_bytes = encode_link_decline_frame(&decline, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(matches!(outcome, Err(LinkExchangeError::UnknownInvite)));
}

#[tokio::test]
async fn a_non_approve_non_decline_frame_is_refused() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    );

    let inviter_task = async {
        let _frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        // A known Control code, but neither LinkApprove nor LinkDecline.
        let frame_bytes =
            encode_frame(MessageType::KeepAlive.code(), &[], MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(matches!(
        outcome,
        Err(LinkExchangeError::ProtocolViolation(_))
    ));
}

#[tokio::test]
async fn an_unassigned_control_code_is_refused() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    );

    let inviter_task = async {
        let _frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        // 0x0f sits in Control's range and is unassigned (docs/04).
        let frame_bytes = encode_frame(0x0f, &[], MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(matches!(
        outcome,
        Err(LinkExchangeError::ProtocolViolation(_))
    ));
}

#[tokio::test]
async fn an_expired_invite_refuses_before_anything_is_written() {
    // A regression here reads for the inviter's answer forever, since
    // nothing on this path ever sends one; a timeout turns that hang into
    // a failure rather than a wait on wall-clock time (rule E3).
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        run_expired_invite_refuses_test(),
    )
    .await
    .expect("test did not hang");
}

async fn run_expired_invite_refuses_test() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW - 1);

    let ((mut send_bob, mut recv_bob), (_send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let verify_called = Arc::new(Mutex::new(false));
    let verify_flag = Arc::clone(&verify_called);

    let outcome = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        move |_req: LinkAttestationRequest| {
            let flag = Arc::clone(&verify_flag);
            async move {
                *flag.lock().expect("not poisoned") = true;
                Ok(peer_account())
            }
        },
        |_link: Link, _secret: LinkSecret| Ok(()),
    )
    .await;

    assert!(matches!(outcome, Err(LinkExchangeError::InviteExpired)));
    assert!(!*verify_called.lock().expect("not poisoned"));
    assert!(
        matches!(
            recv_alice.receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "nothing reaches the wire before the expiry check runs"
    );
}

// ---- The replier's deadline: DCR-075 --------------------------------------
//
// The bound is `expires_at` plus the caller's own skew allowance, the
// same one step 1's expiry check already takes, so the replier stops
// strictly after the inviter -- never blocking on an answer nobody writes.

#[tokio::test(start_paused = true)]
async fn a_read_nobody_answers_reaches_the_deadline_and_declines_as_invite_expired() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (_send_alice, _recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 12,
    };

    let outcome = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    )
    .await;

    assert!(
        matches!(outcome, Err(LinkExchangeError::InviteExpired)),
        "a read nobody ever answers must not block forever"
    );
}

// Separates the invite's own deadline plus this caller's own allowance
// from any fixed timeout: a hard-coded duration would still pass the test
// above but could not land on this exact number for these inputs.
#[tokio::test(start_paused = true)]
async fn the_replier_wait_ends_at_this_invites_deadline_plus_its_own_skew_and_not_a_fixed_one() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 15);

    let ((mut send_bob, mut recv_bob), (_send_alice, _recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 20,
    };

    let started = tokio::time::Instant::now();
    let outcome = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    )
    .await;

    assert!(matches!(outcome, Err(LinkExchangeError::InviteExpired)));
    assert_eq!(
        tokio::time::Instant::now() - started,
        std::time::Duration::from_secs(35),
        "the budget is this invite's remaining window plus this caller's own skew, 15 + 20, and no other number"
    );
}

// The discrimination the two tests above need on their own: a bound that
// fired regardless of what arrived would still pass both, and this is
// what says it does not fire on a frame that is actually written.
#[tokio::test(start_paused = true)]
async fn a_frame_arriving_inside_the_window_is_still_read_and_handled() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_link: Link, _secret: LinkSecret| Ok(()),
    );

    let inviter_task = async {
        let frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        let reply = decode_link_reply_frame(&frame).expect("bob's reply decodes");
        let our_link_id = derive_link_id(&derive_link_secret(
            invite.half_secret(),
            reply.half_secret(),
        ));
        let approve = LinkApprove::new(id, our_link_id);
        let frame_bytes = encode_link_approve_frame(&approve, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(
        matches!(outcome, Ok(LinkOutcome::Linked(_))),
        "a deadline that had already fired would answer InviteExpired instead"
    );
}

// DCR-075's asymmetry: for one invite and one skew allowance, the
// replier's own budget exceeds the inviter's by exactly that allowance,
// which is what lets an approval written just inside the inviter's own
// window still be read on the replier's side.
#[tokio::test(start_paused = true)]
async fn the_replier_stops_strictly_after_the_inviter_by_the_skew_allowance() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 40);
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    const SKEW: u64 = 9;

    let inviter_started = tokio::time::Instant::now();
    let ((mut send_alice, _recv_alice_unused), (_send_bob_unused, _recv_bob_unused)) =
        memory_stream_pair();
    let bob_reply = LinkReply::new(
        id,
        bob.identity_pub().clone(),
        bob.agreement_pub().clone(),
        "bob_token".to_string(),
        half(0xb2),
    );
    let inviter_outcome = serve_link_reply(
        &mut send_alice,
        InviterParams {
            invite: &invite,
            reply: bob_reply,
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_p: LinkProposal| std::future::pending::<LinkDecision>(),
        |_l: Link, _s: LinkSecret| Ok(()),
    )
    .await
    .expect("a window that closes is a decline, not an error");
    let inviter_elapsed = tokio::time::Instant::now() - inviter_started;
    assert!(matches!(
        inviter_outcome,
        LinkOutcome::Declined {
            reason: Some(LinkDeclineReason::InviteExpired),
            ..
        }
    ));

    let ((mut send_bob, mut recv_bob), (_send_alice, _recv_alice)) = memory_stream_pair();
    let rng = SeededRng::new(77);
    let replier_started = tokio::time::Instant::now();
    let replier_outcome = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        ReplierParams {
            invite: &invite,
            our_identity: &bob,
            our_attestation_token: "bob_token".to_string(),
            our_display_name: None,
            authenticated_peer: alice.device_id(),
            max_frame_size: MAX_FRAME,
            invite_skew_secs: SKEW,
        },
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_l: Link, _s: LinkSecret| Ok(()),
    )
    .await;
    let replier_elapsed = tokio::time::Instant::now() - replier_started;
    assert!(matches!(
        replier_outcome,
        Err(LinkExchangeError::InviteExpired)
    ));

    assert_eq!(
        replier_elapsed,
        inviter_elapsed + std::time::Duration::from_secs(SKEW),
        "the replier's budget exceeds the inviter's by exactly this caller's own skew allowance"
    );
}

// DF-34: `send_link_reply` no longer derives the Link Secret once to check
// `LinkApprove` and again for `record`. What a caller can observe of that
// is that the value handed to `record` derives the very `link_id` the
// approved frame carried, which a second, disagreeing derivation would break.
#[tokio::test]
async fn the_secret_handed_to_record_derives_the_link_id_it_is_filed_under() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);

    let ((mut send_bob, mut recv_bob), (mut send_alice, mut recv_alice)) = memory_stream_pair();
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let rng = SeededRng::new(77);

    let params = ReplierParams {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob_token".to_string(),
        our_display_name: None,
        authenticated_peer: alice.device_id(),
        max_frame_size: MAX_FRAME,
        invite_skew_secs: 0,
    };

    let replier_task = send_link_reply(
        &mut send_bob,
        &mut recv_bob,
        params,
        &rng,
        &clock,
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        move |link: Link, secret: LinkSecret| {
            assert_eq!(
                derive_link_id(&secret),
                link.link_id(),
                "the recorded secret must derive the id the record is filed under"
            );
            Ok(())
        },
    );

    let inviter_task = async {
        let frame = read_one_frame(&mut recv_alice, MAX_FRAME).await;
        let reply = decode_link_reply_frame(&frame).expect("bob's reply decodes");
        let our_link_id = derive_link_id(&derive_link_secret(
            invite.half_secret(),
            reply.half_secret(),
        ));
        let approve = LinkApprove::new(id, our_link_id);
        let frame_bytes = encode_link_approve_frame(&approve, MAX_FRAME).expect("encodes");
        send_alice.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    assert!(matches!(outcome, Ok(LinkOutcome::Linked(_))));
}

// ---- The listener's branch on the first Control frame ---------------------

fn test_identities() -> (
    (SoftwareKeyStore, PublicIdentity, KeyBinding),
    (SoftwareKeyStore, PublicIdentity, KeyBinding),
) {
    let rng = SeededRng::new(555);
    let store_a = SoftwareKeyStore::generate(&rng).expect("generate a");
    let identity_a = store_a.public_identity().expect("id a");
    let binding_a = key_binding_for(&store_a, &identity_a, NOW + 86_400);

    let store_b = SoftwareKeyStore::generate(&rng).expect("generate b");
    let identity_b = store_b.public_identity().expect("id b");
    let binding_b = key_binding_for(&store_b, &identity_b, NOW + 86_400);

    (
        (store_a, identity_a, binding_a),
        (store_b, identity_b, binding_b),
    )
}

#[tokio::test]
async fn a_hello_first_frame_still_completes_the_ordinary_handshake() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = test_identities();
    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_rng = SeededRng::new(1);
    let listener_rng = SeededRng::new(2);

    let sender_task = async {
        let (mut s_send, mut s_recv) = sender_chan.open_bi().await.expect("open ctrl bi");
        let params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "sender-token".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).expect("valid range"),
            our_capabilities: Capabilities::empty(),
        };
        let session = perform_handshake(
            s_send.as_mut(),
            s_recv.as_mut(),
            params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("handshake completes");

        // Opens a second bi stream so the listener's select! resolves
        // through its browse fallback. `s_send` must not be dropped here:
        // that would close the control stream and race the two branches
        // against each other instead of leaving accept_bi() as the only
        // one that can ever resolve.
        let (mut d_send, _d_recv) = sender_chan.open_bi().await.expect("open second bi");
        d_send.finish().await.expect("finish");
        std::mem::forget(s_send);
        session
    };

    let vfs = NativeVfs::new();
    let listener_params = ListenerParams {
        root: RootId::new(1),
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("receiver-token".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };

    let hello_seen = Arc::new(Mutex::new(false));
    let hello_seen_flag = Arc::clone(&hello_seen);

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        move |_req: AttestationRequest| {
            let flag = Arc::clone(&hello_seen_flag);
            async move {
                *flag.lock().expect("not poisoned") = true;
                Ok(TrustTier::SameAccount)
            }
        },
        None,
        None,
    );

    let (sender_session, listener_res) = tokio::join!(sender_task, listener_task);
    assert!(*hello_seen.lock().expect("not poisoned"));
    assert!(listener_res.is_ok(), "{:?}", listener_res.err());
    assert_eq!(sender_session.tier(), TrustTier::SameAccount);
}

#[tokio::test]
async fn a_linkreply_first_frame_with_a_service_reaches_it() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, _sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = test_identities();
    let _ = sender_store; // only the identity's keys are needed on this side
    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_task = async {
        let (mut s_send, _s_recv) = sender_chan.open_bi().await.expect("open ctrl bi");
        let reply = LinkReply::new(
            invite_id(0x09),
            sender_id.identity_pub().clone(),
            sender_id.agreement_pub().clone(),
            "reply-token".to_string(),
            half(0xc3),
        );
        let frame_bytes = encode_link_reply_frame(&reply, MAX_FRAME).expect("encodes");
        s_send.write_all(&frame_bytes).await.expect("write");
    };

    let vfs = NativeVfs::new();
    let listener_params = ListenerParams {
        root: RootId::new(1),
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("receiver-token".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };
    let listener_rng = SeededRng::new(2);

    let reached = Arc::new(Mutex::new(false));
    let service = RecordingLinkService {
        reached: Arc::clone(&reached),
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_req: AttestationRequest| async { Ok(TrustTier::SameAccount) },
        None,
        Some(&service),
    );

    let (_, res) = tokio::join!(sender_task, listener_task);
    assert!(res.is_ok(), "{:?}", res.err());
    assert!(*reached.lock().expect("not poisoned"));
}

#[tokio::test]
async fn a_linkreply_first_frame_with_no_service_is_refused() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, _sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = test_identities();
    let _ = sender_store;
    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_task = async {
        let (mut s_send, _s_recv) = sender_chan.open_bi().await.expect("open ctrl bi");
        let reply = LinkReply::new(
            invite_id(0x09),
            sender_id.identity_pub().clone(),
            sender_id.agreement_pub().clone(),
            "reply-token".to_string(),
            half(0xc3),
        );
        let frame_bytes = encode_link_reply_frame(&reply, MAX_FRAME).expect("encodes");
        s_send.write_all(&frame_bytes).await.expect("write");
    };

    let vfs = NativeVfs::new();
    let listener_params = ListenerParams {
        root: RootId::new(1),
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("receiver-token".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };
    let listener_rng = SeededRng::new(2);

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_req: AttestationRequest| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (_, res) = tokio::join!(sender_task, listener_task);
    assert!(matches!(res, Err(ListenerError::ProtocolViolation(_))));
}

#[tokio::test]
async fn an_unassigned_control_code_as_the_first_frame_is_refused() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, _sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = test_identities();
    let _ = sender_store;
    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_task = async {
        let (mut s_send, _s_recv) = sender_chan.open_bi().await.expect("open ctrl bi");
        let frame_bytes = encode_frame(0x0f, &[], MAX_FRAME).expect("encodes");
        s_send.write_all(&frame_bytes).await.expect("write");
    };

    let vfs = NativeVfs::new();
    let listener_params = ListenerParams {
        root: RootId::new(1),
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("receiver-token".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).expect("valid range"),
        our_capabilities: Capabilities::empty(),
    };
    let listener_rng = SeededRng::new(2);

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_req: AttestationRequest| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (_, res) = tokio::join!(sender_task, listener_task);
    assert!(matches!(res, Err(ListenerError::ProtocolViolation(_))));
}

//! Integration tests for the listener half of the composition root (WI-M1-024).
//! Validates end-to-end file transfers, multi-item offers, chunk resumption,
//! selective acceptance filtering, and forward compatibility against a hand-driven sender.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::handshake::{HandshakeParams, perform_handshake};
use tradr_app::listener::{
    ChannelFailure, ChannelPhase, ListenerError, ListenerParams, ListenerServices,
    accept_and_handle_transfer, derive_item_resumption, handle_incoming_channel,
    listen_for_transfers, remove_partial_dir, run_listener,
};
use tradr_app::peer_trust::OwnAttestation;
use tradr_app::transfer::{SendRequest, SessionStreams, prepare_item, send_file};
use tradr_core::{
    BoxFuture, Capabilities, Clock, DeviceId, DomainTag, Incoming, ItemId, KeyBinding, KeyStore,
    Monotonic, OfferItem, PublicIdentity, RecvStream, RelPath, Rng, RngError, RootId,
    SecureChannel, SendStream, TransferId, TransferOffer, TransportError, TransportId, TrustTier,
    UnixTime, VersionRange, Vfs,
};
use tradr_identity::SoftwareKeyStore;
use tradr_integrity::{BaoVerifier, outboard};
use tradr_proto::control::{decode_transfer_accept_frame, encode_transfer_offer_frame};
use tradr_proto::framing::{Frame, FrameDecoder, encode_frame};
use tradr_proto::hello::{decode_hello_frame, encode_hello_frame};
use tradr_vfs::NativeVfs;
use tradr_vfs::sanitization::{partial_dir_rel_path, partial_file_rel_path};

const VALID_V7_A: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
const VALID_V7_B: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c073990";
const MAX_FRAME: u32 = 2 * 1024 * 1024;
const NOW: i64 = 1_800_000_000;
const LATER: i64 = NOW + 86_400;

fn sample_transfer(s: &str) -> TransferId {
    s.parse().expect("valid transfer id")
}

// A fixed own-attestation for tests that never exercise sign-in itself.
struct FixedAttestation(String);

impl OwnAttestation for FixedAttestation {
    fn id_token(&self) -> Option<String> {
        Some(self.0.clone())
    }
}

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

#[derive(Clone, Copy)]
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
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(64);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(64);
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

struct ChannelHandle {
    inner: Arc<MockSecureChannel>,
}

impl SecureChannel for ChannelHandle {
    fn peer(&self) -> DeviceId {
        self.inner.peer()
    }

    fn transport(&self) -> TransportId {
        self.inner.transport()
    }

    fn rtt(&self) -> std::time::Duration {
        self.inner.rtt()
    }

    fn max_frame_size(&self) -> u32 {
        self.inner.max_frame_size()
    }

    fn open_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        self.inner.open_bi()
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        self.inner.accept_bi()
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        self.inner.open_uni()
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        self.inner.accept_uni()
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        self.inner.close()
    }
}

fn mock_channel_pair(
    peer_a_id: DeviceId,
    peer_b_id: DeviceId,
    max_frame_size: u32,
) -> (ChannelHandle, ChannelHandle) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(16);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(16);

    let chan_a = Arc::new(MockSecureChannel {
        peer_id: peer_b_id,
        transport_id: TransportId::new("memory"),
        max_frame_size,
        bi_tx: tx_a_to_b,
        bi_rx: tokio::sync::Mutex::new(rx_b_to_a),
    });

    let chan_b = Arc::new(MockSecureChannel {
        peer_id: peer_a_id,
        transport_id: TransportId::new("memory"),
        max_frame_size,
        bi_tx: tx_b_to_a,
        bi_rx: tokio::sync::Mutex::new(rx_a_to_b),
    });

    (
        ChannelHandle { inner: chan_a },
        ChannelHandle { inner: chan_b },
    )
}

struct MockIncoming {
    channels: tokio::sync::mpsc::Receiver<Box<dyn SecureChannel>>,
}

impl Incoming for MockIncoming {
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move { self.channels.recv().await.ok_or(TransportError::Closed) })
    }
}

async fn read_frame_helper(
    recv: &mut dyn RecvStream,
    max_frame_size: u32,
) -> Result<Frame, TransportError> {
    let mut len_bytes = [0u8; 4];
    let mut read = 0;
    while read < 4 {
        let n = recv.read(&mut len_bytes[read..]).await?;
        if n == 0 {
            return Err(TransportError::Closed);
        }
        read += n;
    }
    let announced = u32::from_be_bytes(len_bytes);
    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);

    let mut read_payload = 0;
    while read_payload < announced as usize {
        let n = recv.read(&mut raw[4 + read_payload..]).await?;
        if n == 0 {
            return Err(TransportError::Closed);
        }
        read_payload += n;
    }

    let mut decoder = FrameDecoder::new(max_frame_size);
    decoder.feed(&raw);
    decoder
        .next_frame()
        .map_err(|_| TransportError::Closed)?
        .ok_or(TransportError::Closed)
}

fn create_test_identities() -> (
    (SoftwareKeyStore, PublicIdentity, KeyBinding),
    (SoftwareKeyStore, PublicIdentity, KeyBinding),
) {
    let rng = SeededRng::new(12345);
    let store_a = SoftwareKeyStore::generate(&rng).expect("generate store a");
    let identity_a = store_a.public_identity().expect("identity a");
    let keybind_sig_a = store_a
        .sign(DomainTag::KeyBind, identity_a.agreement_pub().as_bytes())
        .expect("sign keybind a");
    let binding_a = KeyBinding::new(
        identity_a.agreement_pub().clone(),
        keybind_sig_a,
        UnixTime::from_secs(LATER),
    );

    let store_b = SoftwareKeyStore::generate(&rng).expect("generate store b");
    let identity_b = store_b.public_identity().expect("identity b");
    let keybind_sig_b = store_b
        .sign(DomainTag::KeyBind, identity_b.agreement_pub().as_bytes())
        .expect("sign keybind b");
    let binding_b = KeyBinding::new(
        identity_b.agreement_pub().clone(),
        keybind_sig_b,
        UnixTime::from_secs(LATER),
    );

    (
        (store_a, identity_a, binding_a),
        (store_b, identity_b, binding_b),
    )
}

#[tokio::test]
async fn single_file_transfer_via_listener_end_to_end() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);
    let root_receiver = RootId::new(2);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let file_content = vec![0x42u8; 42 * 1024];
    std::fs::write(sender_dir.path().join("document.pdf"), &file_content).unwrap();
    let (_, hash) = outboard(&file_content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("doc_1").unwrap();
    let src_rel = RelPath::new("document.pdf").unwrap();
    let offer_item =
        OfferItem::new(item_id, src_rel.clone(), file_content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(999);
    let sender_rng = SeededRng::new(888);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            file_content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();
        assert_eq!(accept.items().len(), 1);
        assert!(accept.items()[0].accepted());
        assert_eq!(accept.items()[0].resume_chunk(), 0);

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        Ok::<(), ListenerError>(())
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "document.pdf");

    let received_bytes = std::fs::read(receiver_dir.path().join("document.pdf")).unwrap();
    assert_eq!(received_bytes, file_content);

    let partial_dir = receiver_dir.path().join(".tradr-partial").join(VALID_V7_A);
    assert!(
        !partial_dir.exists(),
        "partial directory must be removed after successful transfer"
    );
}

#[tokio::test]
async fn multiple_files_transfer_via_listener() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(10);
    let root_receiver = RootId::new(20);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content_1 = b"first file contents here";
    let content_2 = b"second file different data";
    std::fs::write(sender_dir.path().join("first.txt"), content_1).unwrap();
    std::fs::write(sender_dir.path().join("second.txt"), content_2).unwrap();

    let (_, hash_1) = outboard(content_1);
    let (_, hash_2) = outboard(content_2);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_1 = ItemId::new("item_1").unwrap();
    let item_2 = ItemId::new("item_2").unwrap();
    let rel_1 = RelPath::new("first.txt").unwrap();
    let rel_2 = RelPath::new("second.txt").unwrap();

    let offer_1 = OfferItem::new(item_1, rel_1.clone(), content_1.len() as u64, hash_1).unwrap();
    let offer_2 = OfferItem::new(item_2, rel_2.clone(), content_2.len() as u64, hash_2).unwrap();

    let total_bytes = (content_1.len() + content_2.len()) as u64;
    let offer =
        TransferOffer::new(transfer_id, vec![offer_1, offer_2], total_bytes, None, None).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(111);
    let sender_rng = SeededRng::new(222);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();
        assert_eq!(accept.items().len(), 2);

        // First item
        let (mut data_send_1, mut data_recv_1) = sender_chan.open_bi().await.unwrap();
        let prepared_1 = prepare_item(
            &sender_vfs,
            root_sender,
            &rel_1,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req_1 = SendRequest {
            root: root_sender,
            rel_path: &rel_1,
            transfer_id,
            item_id: item_1,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared_1,
        };
        let mut streams_1 = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send_1.as_mut(),
            data_recv: data_recv_1.as_mut(),
        };
        let send_res_1 = send_file(&sender_vfs, &send_req_1, &mut streams_1)
            .await
            .unwrap();
        assert!(send_res_1);

        // Second item
        let (mut data_send_2, mut data_recv_2) = sender_chan.open_bi().await.unwrap();
        let prepared_2 = prepare_item(
            &sender_vfs,
            root_sender,
            &rel_2,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req_2 = SendRequest {
            root: root_sender,
            rel_path: &rel_2,
            transfer_id,
            item_id: item_2,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared_2,
        };
        let mut streams_2 = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send_2.as_mut(),
            data_recv: data_recv_2.as_mut(),
        };
        let send_res_2 = send_file(&sender_vfs, &send_req_2, &mut streams_2)
            .await
            .unwrap();
        assert!(send_res_2);

        Ok::<(), ListenerError>(())
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 2);
    assert_eq!(placed[0].as_str(), "first.txt");
    assert_eq!(placed[1].as_str(), "second.txt");

    assert_eq!(
        std::fs::read(receiver_dir.path().join("first.txt")).unwrap(),
        content_1
    );
    assert_eq!(
        std::fs::read(receiver_dir.path().join("second.txt")).unwrap(),
        content_2
    );
}

#[tokio::test]
async fn resumed_transfer_via_listener_skips_existing_chunks() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(100);
    let root_receiver = RootId::new(200);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    // 2.5 MiB file (3 reference chunks)
    let total_bytes = (2.5 * 1024.0 * 1024.0) as usize;
    let mut file_content = Vec::with_capacity(total_bytes);
    for i in 0..total_bytes {
        file_content.push((i % 251) as u8);
    }
    std::fs::write(sender_dir.path().join("video.mp4"), &file_content).unwrap();

    let (_, hash) = outboard(&file_content);
    let transfer_id = sample_transfer(VALID_V7_B);
    let item_id = ItemId::new("video_item").unwrap();
    let src_rel = RelPath::new("video.mp4").unwrap();
    let offer_item =
        OfferItem::new(item_id, src_rel.clone(), file_content.len() as u64, hash).unwrap();

    // Pre-populate receiver partial directory with chunk 0 (first 1 MiB)
    let partial_dir = partial_dir_rel_path(transfer_id);
    receiver_vfs
        .create_dir(root_receiver, &partial_dir)
        .await
        .unwrap();
    let partial_rel = partial_file_rel_path(transfer_id, &item_id);
    let mut partial_writer = receiver_vfs
        .open_write(root_receiver, &partial_rel)
        .await
        .unwrap();
    partial_writer
        .write_at(0, &file_content[..1024 * 1024])
        .await
        .unwrap();
    partial_writer.sync().await.unwrap();
    drop(partial_writer);

    // Verify derive_item_resumption inspects disk correctly
    let derived = derive_item_resumption(&receiver_vfs, root_receiver, transfer_id, &offer_item)
        .await
        .unwrap();
    assert_eq!(derived.next_chunk_request(1).unwrap().0.value(), 1);

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(333);
    let sender_rng = SeededRng::new(444);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            file_content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        // The listener must have announced resume_chunk = 1
        assert_eq!(accept.items().len(), 1);
        assert!(accept.items()[0].accepted());
        assert_eq!(accept.items()[0].resume_chunk(), 1);

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        Ok::<(), ListenerError>(())
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "video.mp4");

    let received_bytes = std::fs::read(receiver_dir.path().join("video.mp4")).unwrap();
    assert_eq!(received_bytes, file_content);
}

#[tokio::test]
async fn selective_item_acceptance_declines_filtered_items() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(1000);
    let root_receiver = RootId::new(2000);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content_keep = b"keep this file";
    let content_skip = b"skip this file";
    std::fs::write(sender_dir.path().join("keep.txt"), content_keep).unwrap();
    std::fs::write(sender_dir.path().join("skip.txt"), content_skip).unwrap();

    let (_, hash_keep) = outboard(content_keep);
    let (_, hash_skip) = outboard(content_skip);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_keep = ItemId::new("keep_id").unwrap();
    let item_skip = ItemId::new("skip_id").unwrap();
    let rel_keep = RelPath::new("keep.txt").unwrap();
    let rel_skip = RelPath::new("skip.txt").unwrap();

    let offer_keep = OfferItem::new(
        item_keep,
        rel_keep.clone(),
        content_keep.len() as u64,
        hash_keep,
    )
    .unwrap();
    let offer_skip = OfferItem::new(
        item_skip,
        rel_skip.clone(),
        content_skip.len() as u64,
        hash_skip,
    )
    .unwrap();

    let offer = TransferOffer::new(
        transfer_id,
        vec![offer_keep, offer_skip],
        (content_keep.len() + content_skip.len()) as u64,
        None,
        None,
    )
    .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(555);
    let sender_rng = SeededRng::new(666);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        // Only keep.txt was accepted
        assert_eq!(accept.items().len(), 1);
        assert_eq!(accept.items()[0].item_id(), &item_keep);

        // Transfer keep.txt
        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &rel_keep,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &rel_keep,
            transfer_id,
            item_id: item_keep,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        Ok::<(), ListenerError>(())
    };

    let item_filter = |item: &OfferItem| item.item_id() == &item_keep;

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        Some(&item_filter),
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "keep.txt");

    assert!(receiver_dir.path().join("keep.txt").exists());
    assert!(!receiver_dir.path().join("skip.txt").exists());
}

#[tokio::test]
async fn listener_refuses_when_peer_attestation_fails() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(300);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(777);
    let sender_rng = SeededRng::new(888);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "invalid-token".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let _ = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await;
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Err("attestation token is invalid".to_string()) },
        None,
        None,
    );

    let (_, listener_res) = tokio::join!(sender_task, listener_task);
    let failure = listener_res.expect_err("peer attestation failure must fail");
    assert_eq!(failure.peer, sender_id.device_id());
    assert_eq!(failure.phase, ChannelPhase::Handshake);
    assert!(matches!(failure.error, ListenerError::Handshake(_)));
}

#[tokio::test]
async fn unknown_control_plane_messages_ignored_before_offer() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(400);
    let root_receiver = RootId::new(500);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"data after unassigned frame";
    std::fs::write(sender_dir.path().join("file.bin"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("bin_item").unwrap();
    let src_rel = RelPath::new("file.bin").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(1212);
    let sender_rng = SeededRng::new(3434);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        // Send an unassigned control message (0x0f) before the TransferOffer
        let unassigned_frame = encode_frame(0x0f, b"future_field", MAX_FRAME).unwrap();
        sender_ctrl_send.write_all(&unassigned_frame).await.unwrap();

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        Ok::<(), ListenerError>(())
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "file.bin");

    assert_eq!(
        std::fs::read(receiver_dir.path().join("file.bin")).unwrap(),
        content
    );
}

#[tokio::test]
async fn accept_and_handle_transfer_from_mock_incoming() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };
    incoming_tx
        .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(600);
    let root_receiver = RootId::new(700);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"incoming test data";
    std::fs::write(sender_dir.path().join("test.txt"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("t_item").unwrap();
    let src_rel = RelPath::new("test.txt").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(5678);
    let sender_rng = SeededRng::new(1234);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        Ok::<(), ListenerError>(())
    };

    let listener_task = accept_and_handle_transfer(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "test.txt");

    assert_eq!(
        std::fs::read(receiver_dir.path().join("test.txt")).unwrap(),
        content
    );
}

#[tokio::test]
async fn listen_for_transfers_terminates_on_closed_incoming() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let ((_, _, _), (receiver_store, receiver_id, receiver_binding)) = create_test_identities();

    let (_incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };
    // Drop incoming_tx so incoming channel is closed immediately
    drop(_incoming_tx);

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(800);

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(9999);

    let res = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        None,
    )
    .await;

    assert!(res.is_ok());
}

#[tokio::test]
async fn listen_for_transfers_reads_capabilities_fresh_per_connection() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (_sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(2);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(801);

    let capabilities = Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC));

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::clone(&capabilities),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(9999);
    let sender_rng = SeededRng::new(8888);

    let (sender_chan_1, listener_chan_1) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);
    let (sender_chan_2, listener_chan_2) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let peer_task = async move {
        incoming_tx
            .send(Box::new(listener_chan_1))
            .await
            .expect("queue channel 1");
        let (mut peer_send_1, mut peer_recv_1) = sender_chan_1.open_bi().await.expect("open bi 1");
        let (_awaiting_1, peer_hello_1) = tradr_identity::hello::open(
            &sender_rng,
            VersionRange::new(1, 1).unwrap(),
            &sender_id,
            "mock-token-sender-1".to_string(),
            sender_binding.clone(),
            Capabilities::DIRECT_QUIC,
        )
        .expect("open hello 1");
        let frame_bytes_1 = encode_hello_frame(&peer_hello_1, MAX_FRAME).expect("encode hello 1");
        peer_send_1
            .write_all(&frame_bytes_1)
            .await
            .expect("write hello 1");
        let reply_frame_1 = read_frame_helper(&mut *peer_recv_1, MAX_FRAME)
            .await
            .expect("read reply frame 1");
        let listener_hello_1 = decode_hello_frame(&reply_frame_1).expect("decode hello 1");
        assert_eq!(listener_hello_1.capabilities().bits(), 1);
        drop(peer_send_1);
        drop(peer_recv_1);
        drop(sender_chan_1);

        capabilities.declare(Capabilities::BLE_GATT);

        incoming_tx
            .send(Box::new(listener_chan_2))
            .await
            .expect("queue channel 2");
        let (mut peer_send_2, mut peer_recv_2) = sender_chan_2.open_bi().await.expect("open bi 2");
        let (_awaiting_2, peer_hello_2) = tradr_identity::hello::open(
            &sender_rng,
            VersionRange::new(1, 1).unwrap(),
            &sender_id,
            "mock-token-sender-2".to_string(),
            sender_binding,
            Capabilities::DIRECT_QUIC,
        )
        .expect("open hello 2");
        let frame_bytes_2 = encode_hello_frame(&peer_hello_2, MAX_FRAME).expect("encode hello 2");
        peer_send_2
            .write_all(&frame_bytes_2)
            .await
            .expect("write hello 2");
        let reply_frame_2 = read_frame_helper(&mut *peer_recv_2, MAX_FRAME)
            .await
            .expect("read reply frame 2");
        let listener_hello_2 = decode_hello_frame(&reply_frame_2).expect("decode hello 2");
        assert_eq!(listener_hello_2.capabilities().bits(), 0b101);
        drop(peer_send_2);
        drop(peer_recv_2);
        drop(sender_chan_2);

        drop(incoming_tx);
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        None,
    );

    let (_, listener_res) = tokio::join!(peer_task, listener_task);
    assert!(listener_res.is_ok());
}

#[tokio::test]
async fn listen_for_transfers_reports_each_placed_path() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };
    incoming_tx
        .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(900);
    let root_receiver = RootId::new(901);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"incoming test data";
    std::fs::write(sender_dir.path().join("test.txt"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("t_item").unwrap();
    let src_rel = RelPath::new("test.txt").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(5678);
    let sender_rng = SeededRng::new(1234);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        drop(incoming_tx);
        Ok::<(), ListenerError>(())
    };

    let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded_cb = Arc::clone(&recorded);
    let callback = move |_from, paths: &[RelPath]| {
        let mut r = recorded_cb.lock().unwrap();
        for p in paths {
            r.push(p.as_str().to_string());
        }
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        Some(&callback),
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    listener_res.unwrap();
    let placed = recorded.lock().unwrap().clone();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "test.txt");

    assert_eq!(
        std::fs::read(receiver_dir.path().join("test.txt")).unwrap(),
        content
    );
}

#[tokio::test]
async fn listen_for_transfers_reports_sender_device_id_and_placed_paths() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };
    incoming_tx
        .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(910);
    let root_receiver = RootId::new(911);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"arrival hook test data";
    std::fs::write(sender_dir.path().join("arrival.txt"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("arr_item").unwrap();
    let src_rel = RelPath::new("arrival.txt").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(5678);
    let sender_rng = SeededRng::new(1234);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        drop(incoming_tx);
        Ok::<(), ListenerError>(())
    };

    let arrivals = Arc::new(Mutex::new(Vec::<(DeviceId, Vec<RelPath>)>::new()));
    let arrivals_cb = Arc::clone(&arrivals);
    let callback = move |from: DeviceId, paths: &[RelPath]| {
        arrivals_cb.lock().unwrap().push((from, paths.to_vec()));
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        Some(&callback),
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    listener_res.unwrap();

    let recorded = arrivals.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1, "hook must be called exactly once");
    assert_eq!(
        recorded[0].0,
        sender_id.device_id(),
        "hook must receive sender device id"
    );
    assert_eq!(
        recorded[0].1,
        vec![src_rel],
        "hook must receive placed paths"
    );
}

#[tokio::test]
async fn run_listener_reports_each_placed_path() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, _receiver_binding),
    ) = create_test_identities();

    let receiver_device_id = receiver_id.device_id();
    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_device_id, MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let incoming = MockIncoming {
        channels: incoming_rx,
    };
    incoming_tx
        .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(900);
    let root_receiver = RootId::new(901);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"incoming test data";
    std::fs::write(sender_dir.path().join("test.txt"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("t_item").unwrap();
    let src_rel = RelPath::new("test.txt").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_rng = SeededRng::new(5678);
    let sender_rng = SeededRng::new(1234);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_device_id,
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        drop(incoming_tx);
        Ok::<(), ListenerError>(())
    };

    let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded_cb = Arc::clone(&recorded);
    let callback = move |_from, paths: &[RelPath]| {
        let mut r = recorded_cb.lock().unwrap();
        for p in paths {
            r.push(p.as_str().to_string());
        }
    };

    let services = ListenerServices {
        rng: &listener_rng,
        clock: &clock,
        verifier: &BaoVerifier,
    };

    let listener_task = run_listener(
        Box::new(incoming) as Box<dyn Incoming>,
        Arc::new(receiver_vfs),
        Arc::new(receiver_store) as Arc<dyn KeyStore>,
        receiver_id,
        Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        root_receiver,
        Arc::new(LocalCapabilities::new(Capabilities::empty())),
        Arc::new(BrowseAccess::new()),
        services,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        Some(Arc::new(callback)),
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    listener_res.unwrap();
    let placed = recorded.lock().unwrap().clone();
    assert_eq!(placed, vec!["test.txt".to_string()]);

    assert_eq!(
        std::fs::read(receiver_dir.path().join("test.txt")).unwrap(),
        content
    );
}

#[tokio::test]
async fn listen_for_transfers_does_not_report_an_offer_with_every_item_declined() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(3000);
    let root_receiver = RootId::new(3001);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"declined file";
    std::fs::write(sender_dir.path().join("declined.txt"), content).unwrap();

    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("declined_id").unwrap();
    let rel_path = RelPath::new("declined.txt").unwrap();

    let offer_item = OfferItem::new(item_id, rel_path, content.len() as u64, hash).unwrap();

    let offer = TransferOffer::new(
        transfer_id,
        vec![offer_item],
        content.len() as u64,
        None,
        None,
    )
    .unwrap();

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(555);
    let sender_rng = SeededRng::new(666);

    let sender_task = async {
        incoming_tx
            .send(Box::new(listener_chan))
            .await
            .expect("queue listener channel");

        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        assert_eq!(accept.items().len(), 1);
        assert_eq!(accept.items()[0].item_id(), &item_id);
        assert!(!accept.items()[0].accepted());

        drop(sender_ctrl_send);
        drop(sender_ctrl_recv);
        drop(sender_chan);
        drop(incoming_tx);
        Ok::<(), ListenerError>(())
    };

    let item_filter = |_: &OfferItem| false;

    let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded_cb = Arc::clone(&recorded);
    let callback = move |_from, paths: &[RelPath]| {
        let mut r = recorded_cb.lock().unwrap();
        if paths.is_empty() {
            r.push("<empty>".to_string());
        }
        for p in paths {
            r.push(p.as_str().to_string());
        }
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        Some(&item_filter),
        None,
        Some(&callback),
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    assert!(listener_res.is_ok());
    assert!(recorded.lock().unwrap().is_empty());
}

#[tokio::test]
async fn non_empty_partial_directory_survives_removal() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, temp_dir.path().to_path_buf(), false)
        .expect("register root");

    let transfer_id = sample_transfer(VALID_V7_A);
    let dir_rel = partial_dir_rel_path(transfer_id);
    vfs.create_dir(root, &dir_rel).await.expect("create dir");

    let item_id = ItemId::new("item_0").expect("item id");
    let file_rel = partial_file_rel_path(transfer_id, &item_id);
    let mut handle = vfs.open_write(root, &file_rel).await.expect("open write");
    handle.write_at(0, b"partial data").await.expect("write");
    handle.sync().await.expect("sync");
    drop(handle);

    let res = remove_partial_dir(&vfs, root, transfer_id).await;
    assert!(
        res.is_ok(),
        "tolerates WrongKind when directory is non-empty"
    );

    assert!(vfs.stat(root, &dir_rel).await.is_ok());
    assert!(vfs.stat(root, &file_rel).await.is_ok());

    vfs.remove(root, &file_rel).await.expect("remove file");
    let res_empty = remove_partial_dir(&vfs, root, transfer_id).await;
    assert!(res_empty.is_ok(), "removes empty directory");
    assert!(matches!(
        vfs.stat(root, &dir_rel).await,
        Err(tradr_core::VfsError::NotFound)
    ));

    let res_absent = remove_partial_dir(&vfs, root, sample_transfer(VALID_V7_B)).await;
    assert!(res_absent.is_ok(), "tolerates absent directory");
}

#[tokio::test]
async fn failure_before_any_stream_names_the_peer() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (_sender_store, sender_id, _sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    drop(sender_chan);

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(10);
    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(123);
    let res = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    )
    .await;

    let failure = res.expect_err("dropped sender must produce ChannelFailure");
    assert_eq!(failure.peer, sender_id.device_id());
    assert_eq!(failure.phase, ChannelPhase::BeforeStream);
    assert!(matches!(
        failure.error,
        ListenerError::Transport(TransportError::Closed)
    ));
}

#[tokio::test]
async fn failure_after_the_handshake_is_in_the_offer_phase() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_rng = SeededRng::new(456);
    let listener_rng = SeededRng::new(789);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake completes");

        drop(sender_ctrl_send);
        drop(sender_ctrl_recv);
    };

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(20);
    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (_, listener_res) = tokio::join!(sender_task, listener_task);
    drop(sender_chan);
    let failure = listener_res.expect_err("dropping channel before offer must fail");
    assert_eq!(failure.peer, sender_id.device_id());
    assert_eq!(failure.phase, ChannelPhase::Offer);
    assert!(matches!(
        failure.error,
        ListenerError::Transport(TransportError::Closed)
    ));
}

#[tokio::test]
async fn a_peer_closing_after_the_handshake_fails_in_the_offer_phase() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    // Repeated because select! picks between ready arms at random.
    for iter in 0..32 {
        let (sender_chan, listener_chan) =
            mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

        let sender_rng = SeededRng::new(456 + iter);
        let listener_rng = SeededRng::new(789 + iter);

        let sender_task = async {
            let (mut sender_ctrl_send, mut sender_ctrl_recv) =
                sender_chan.open_bi().await.expect("open ctrl bi");
            let sender_params = HandshakeParams {
                authenticated_peer: receiver_id.device_id(),
                our_channel_max_frame_size: MAX_FRAME,
                our_identity: &sender_id,
                our_attestation_token: "mock-token-sender".to_string(),
                our_key_binding: sender_binding.clone(),
                our_versions: VersionRange::new(1, 1).unwrap(),
                our_capabilities: Capabilities::empty(),
            };
            perform_handshake(
                sender_ctrl_send.as_mut(),
                sender_ctrl_recv.as_mut(),
                sender_params,
                &sender_store,
                &sender_rng,
                &clock,
                |_| async { Ok(TrustTier::SameAccount) },
            )
            .await
            .expect("sender handshake completes");

            drop(sender_ctrl_send);
            drop(sender_ctrl_recv);
            drop(sender_chan);
        };

        let receiver_vfs = NativeVfs::new();
        let root_receiver = RootId::new(20);
        let listener_params = ListenerParams {
            root: root_receiver,
            our_identity: &receiver_id,
            our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
            our_key_binding: receiver_binding.clone(),
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
            browse_access: Arc::new(BrowseAccess::new()),
        };

        let listener_task = handle_incoming_channel(
            &listener_chan,
            &receiver_vfs,
            listener_params,
            &receiver_store,
            &listener_rng,
            &clock,
            &BaoVerifier,
            |_| async { Ok(TrustTier::SameAccount) },
            None,
            None,
        );

        let (_, listener_res) = tokio::join!(sender_task, listener_task);
        assert!(listener_res.is_err());
        let failure = listener_res.unwrap_err();
        assert_eq!(failure.peer, sender_id.device_id());
        assert_eq!(failure.phase, ChannelPhase::Offer);
        assert!(matches!(
            failure.error,
            ListenerError::Transport(TransportError::Closed)
        ));
    }
}

#[tokio::test]
async fn failure_between_items_names_the_item() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(30);
    let root_receiver = RootId::new(31);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content_1 = b"first file data";
    let content_2 = b"second file data";
    let content_3 = b"third file data";
    std::fs::write(sender_dir.path().join("first.txt"), content_1).unwrap();
    std::fs::write(sender_dir.path().join("second.txt"), content_2).unwrap();
    std::fs::write(sender_dir.path().join("third.txt"), content_3).unwrap();

    let (_, hash_1) = outboard(content_1);
    let (_, hash_2) = outboard(content_2);
    let (_, hash_3) = outboard(content_3);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_1 = ItemId::new("item_1").unwrap();
    let item_2 = ItemId::new("item_2").unwrap();
    let item_3 = ItemId::new("item_3").unwrap();
    let rel_1 = RelPath::new("first.txt").unwrap();
    let rel_2 = RelPath::new("second.txt").unwrap();
    let rel_3 = RelPath::new("third.txt").unwrap();

    let offer_1 = OfferItem::new(item_1, rel_1.clone(), content_1.len() as u64, hash_1).unwrap();
    let offer_2 = OfferItem::new(item_2, rel_2.clone(), content_2.len() as u64, hash_2).unwrap();
    let offer_3 = OfferItem::new(item_3, rel_3.clone(), content_3.len() as u64, hash_3).unwrap();

    let total_bytes = (content_1.len() + content_2.len() + content_3.len()) as u64;
    let offer = TransferOffer::new(
        transfer_id,
        vec![offer_1, offer_2, offer_3],
        total_bytes,
        None,
        None,
    )
    .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(111);
    let sender_rng = SeededRng::new(222);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();
        assert_eq!(accept.items().len(), 3);

        let (mut data_send_1, mut data_recv_1) = sender_chan.open_bi().await.unwrap();
        let prepared_1 = prepare_item(
            &sender_vfs,
            root_sender,
            &rel_1,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req_1 = SendRequest {
            root: root_sender,
            rel_path: &rel_1,
            transfer_id,
            item_id: item_1,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared_1,
        };
        let mut streams_1 = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send_1.as_mut(),
            data_recv: data_recv_1.as_mut(),
        };
        let send_res_1 = send_file(&sender_vfs, &send_req_1, &mut streams_1)
            .await
            .unwrap();
        assert!(send_res_1);

        drop(data_send_1);
        drop(data_recv_1);
        drop(sender_ctrl_send);
        drop(sender_ctrl_recv);
        drop(sender_chan);
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (_, listener_res) = tokio::join!(sender_task, listener_task);
    let failure = listener_res.expect_err("dropping channel between items must fail");
    assert_eq!(failure.peer, sender_id.device_id());
    assert_eq!(
        failure.phase,
        ChannelPhase::Item {
            ordinal: 2,
            count: 3
        }
    );
    assert!(matches!(
        failure.error,
        ListenerError::Transport(TransportError::Closed)
    ));
}

#[test]
fn channel_failure_display_is_the_printed_line() {
    let peer_bytes: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let peer = DeviceId::from_bytes(&peer_bytes).unwrap();
    let failure = ChannelFailure {
        peer,
        phase: ChannelPhase::Item {
            ordinal: 2,
            count: 3,
        },
        error: ListenerError::Transport(TransportError::Closed),
    };
    let formatted = failure.to_string();
    assert_eq!(
        formatted,
        "transfer from 000102030405060708090a0b0c0d0e0f failed during item 2 of 3: transport error: the channel or stream is already closed"
    );
}

#[test]
fn channel_phase_display() {
    assert_eq!(ChannelPhase::BeforeStream.to_string(), "before any stream");
    assert_eq!(ChannelPhase::Handshake.to_string(), "handshake");
    assert_eq!(ChannelPhase::Offer.to_string(), "offer");
    assert_eq!(
        ChannelPhase::Item {
            ordinal: 2,
            count: 3
        }
        .to_string(),
        "item 2 of 3"
    );
    assert_eq!(ChannelPhase::LinkExchange.to_string(), "link exchange");
}

#[tokio::test]
async fn run_listener_sweeps_a_stale_partial_directory_before_accepting() {
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let transfer_dir = receiver_dir.path().join(".tradr-partial").join(VALID_V7_A);
    std::fs::create_dir_all(&transfer_dir).expect("create partial transfer dir");
    let item_path = transfer_dir.join("item-1");
    std::fs::write(&item_path, b"partial-data").expect("write partial file");

    let t = std::fs::metadata(&item_path)
        .expect("metadata")
        .modified()
        .expect("modified")
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let clock = FakeClock {
        now: UnixTime::from_secs(t + 8 * 24 * 3600),
    };
    let (_sender, (receiver_store, receiver_id, _receiver_binding)) = create_test_identities();

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let incoming = MockIncoming {
        channels: incoming_rx,
    };
    drop(incoming_tx);

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(901);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register root");

    let listener_rng = SeededRng::new(5678);
    let services = ListenerServices {
        rng: &listener_rng,
        clock: &clock,
        verifier: &BaoVerifier,
    };

    let result = run_listener(
        Box::new(incoming) as Box<dyn Incoming>,
        Arc::new(receiver_vfs),
        Arc::new(receiver_store) as Arc<dyn KeyStore>,
        receiver_id,
        Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        root_receiver,
        Arc::new(LocalCapabilities::new(Capabilities::empty())),
        Arc::new(BrowseAccess::new()),
        services,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    )
    .await;

    assert!(result.is_ok());
    assert!(!transfer_dir.exists());
    assert!(receiver_dir.path().join(".tradr-partial").exists());
}

#[tokio::test]
async fn run_listener_keeps_a_fresh_partial_directory() {
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let transfer_dir = receiver_dir.path().join(".tradr-partial").join(VALID_V7_A);
    std::fs::create_dir_all(&transfer_dir).expect("create partial transfer dir");
    let item_path = transfer_dir.join("item-1");
    std::fs::write(&item_path, b"partial-data").expect("write partial file");

    let t = std::fs::metadata(&item_path)
        .expect("metadata")
        .modified()
        .expect("modified")
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let clock = FakeClock {
        now: UnixTime::from_secs(t + 24 * 3600),
    };
    let (_sender, (receiver_store, receiver_id, _receiver_binding)) = create_test_identities();

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let incoming = MockIncoming {
        channels: incoming_rx,
    };
    drop(incoming_tx);

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(901);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register root");

    let listener_rng = SeededRng::new(5678);
    let services = ListenerServices {
        rng: &listener_rng,
        clock: &clock,
        verifier: &BaoVerifier,
    };

    let result = run_listener(
        Box::new(incoming) as Box<dyn Incoming>,
        Arc::new(receiver_vfs),
        Arc::new(receiver_store) as Arc<dyn KeyStore>,
        receiver_id,
        Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        root_receiver,
        Arc::new(LocalCapabilities::new(Capabilities::empty())),
        Arc::new(BrowseAccess::new()),
        services,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    )
    .await;

    assert!(result.is_ok());
    assert!(item_path.exists());
    assert!(transfer_dir.exists());
    assert!(receiver_dir.path().join(".tradr-partial").exists());
}

#[tokio::test(start_paused = true)]
async fn browse_stream_with_unclosed_control_stream_times_out_and_succeeds() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_rng = SeededRng::new(333);
    let listener_rng = SeededRng::new(444);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake completes");

        let (mut browse_send, mut browse_recv) =
            sender_chan.open_bi().await.expect("open browse bi");
        browse_send.finish().await.expect("finish browse send");
        let mut buf = [0u8; 256];
        let n = browse_recv.read(&mut buf).await.expect("read refused");
        assert!(n > 0);
        std::mem::forget(sender_ctrl_send);
    };

    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(40);
    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (_, listener_res) = tokio::join!(sender_task, listener_task);
    assert!(
        listener_res.is_ok(),
        "listener must succeed despite unclosed control stream: {:?}",
        listener_res.err()
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_channel_does_not_hold_second_transfer() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store_1, sender_id_1, sender_binding_1),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_store_2, sender_id_2, sender_binding_2) = {
        let rng = SeededRng::new(54321);
        let store = SoftwareKeyStore::generate(&rng).expect("generate store 2");
        let id = store.public_identity().expect("id 2");
        let sig = store
            .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
            .expect("sign 2");
        let bind = KeyBinding::new(id.agreement_pub().clone(), sig, UnixTime::from_secs(LATER));
        (store, id, bind)
    };

    let (sender_chan_1, listener_chan_1) =
        mock_channel_pair(sender_id_1.device_id(), receiver_id.device_id(), MAX_FRAME);
    let (sender_chan_2, listener_chan_2) =
        mock_channel_pair(sender_id_2.device_id(), receiver_id.device_id(), MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(2);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };
    incoming_tx
        .send(Box::new(listener_chan_1) as Box<dyn SecureChannel>)
        .await
        .unwrap();
    incoming_tx
        .send(Box::new(listener_chan_2) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(10);
    let root_receiver = RootId::new(20);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"channel 2 payload";
    std::fs::write(sender_dir.path().join("ch2.txt"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("ch2_item").unwrap();
    let src_rel = RelPath::new("ch2.txt").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(1001);
    let sender_rng_1 = SeededRng::new(1002);
    let sender_rng_2 = SeededRng::new(1003);

    let (chan_1_handshaken_tx, chan_1_handshaken_rx) = tokio::sync::oneshot::channel::<()>();
    let (close_chan_1_tx, close_chan_1_rx) = tokio::sync::oneshot::channel::<()>();

    let sender_1_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan_1.open_bi().await.expect("open ctrl bi 1");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id_1,
            our_attestation_token: "mock-token-sender-1".to_string(),
            our_key_binding: sender_binding_1,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store_1,
            &sender_rng_1,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender 1 handshake");

        chan_1_handshaken_tx.send(()).unwrap();
        close_chan_1_rx.await.ok();
        drop(sender_ctrl_send);
        drop(sender_ctrl_recv);
        drop(sender_chan_1);
    };

    let sender_2_task = async {
        chan_1_handshaken_rx.await.unwrap();

        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan_2.open_bi().await.expect("open ctrl bi 2");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id_2,
            our_attestation_token: "mock-token-sender-2".to_string(),
            our_key_binding: sender_binding_2,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store_2,
            &sender_rng_2,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender 2 handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan_2.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan_2.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
    };

    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel::<Vec<String>>();
    let arrived_tx = Arc::new(Mutex::new(Some(arrived_tx)));
    let on_arrival = move |_from, paths: &[RelPath]| {
        let list: Vec<String> = paths.iter().map(|p| p.as_str().to_string()).collect();
        if let Some(tx) = arrived_tx.lock().unwrap().take() {
            tx.send(list).ok();
        }
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        Some(&on_arrival),
    );

    let ((), (), ()) = tokio::join!(
        sender_1_task,
        async {
            tokio::time::timeout(std::time::Duration::from_secs(2), sender_2_task)
                .await
                .expect("sender 2 must complete without being blocked by channel 1");
            let placed = tokio::time::timeout(std::time::Duration::from_secs(2), arrived_rx)
                .await
                .expect("on_arrival must be called within deadline")
                .expect("arrival received");
            assert_eq!(
                placed,
                vec!["ch2.txt"],
                "on_arrival must be called for channel 2 while channel 1 is open"
            );
            close_chan_1_tx.send(()).unwrap();
            drop(incoming_tx);
        },
        async {
            let res = listener_task.await;
            assert!(
                res.is_ok(),
                "listen_for_transfers must return Ok(()): {res:?}"
            );
        }
    );
}

#[tokio::test(start_paused = true)]
async fn concurrent_channel_bound_holds_at_eight() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (_sender_default, (receiver_store, receiver_id, receiver_binding)) =
        create_test_identities();

    let mut senders = Vec::new();
    for i in 0..9 {
        let rng = SeededRng::new(3000 + i as u64);
        let store = SoftwareKeyStore::generate(&rng).expect("generate store");
        let id = store.public_identity().expect("public identity");
        let sig = store
            .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
            .expect("sign keybind");
        let bind = KeyBinding::new(id.agreement_pub().clone(), sig, UnixTime::from_secs(LATER));
        senders.push((store, id, bind));
    }

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };

    let mut sender_chans = Vec::new();
    for (_, id, _) in &senders {
        let (sender_chan, listener_chan) =
            mock_channel_pair(id.device_id(), receiver_id.device_id(), MAX_FRAME);
        sender_chans.push(sender_chan);
        incoming_tx
            .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
            .await
            .unwrap();
    }

    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(50);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(7777);

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        None,
    );

    let receiver_peer = receiver_id.device_id();

    let handshaken_count = Arc::new(AtomicUsize::new(0));
    let (release_0_tx, release_0_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_rest_tx, release_rest_rx) = tokio::sync::watch::channel(false);

    let count_0 = Arc::clone(&handshaken_count);
    let (store_0, id_0, bind_0) = senders.remove(0);
    let chan_0 = sender_chans.remove(0);
    let rng_0 = SeededRng::new(4000);
    let sender_0_task = async move {
        let (mut ctrl_send, mut ctrl_recv) = chan_0.open_bi().await.unwrap();
        let params = HandshakeParams {
            authenticated_peer: receiver_peer,
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &id_0,
            our_attestation_token: "mock-token-0".to_string(),
            our_key_binding: bind_0,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        perform_handshake(
            ctrl_send.as_mut(),
            ctrl_recv.as_mut(),
            params,
            &store_0,
            &rng_0,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("handshake 0");

        count_0.fetch_add(1, Ordering::SeqCst);
        release_0_rx.await.ok();
        drop(ctrl_send);
        drop(ctrl_recv);
        drop(chan_0);
    };

    let mut other_tasks = Vec::new();
    for i in 1..8 {
        let (store_i, id_i, bind_i) = senders.remove(0);
        let chan_i = sender_chans.remove(0);
        let count_i = Arc::clone(&handshaken_count);
        let mut rx_i = release_rest_rx.clone();
        let rng_i = SeededRng::new(4000 + i as u64);
        other_tasks.push(async move {
            let (mut ctrl_send, mut ctrl_recv) = chan_i.open_bi().await.unwrap();
            let params = HandshakeParams {
                authenticated_peer: receiver_peer,
                our_channel_max_frame_size: MAX_FRAME,
                our_identity: &id_i,
                our_attestation_token: format!("mock-token-{i}"),
                our_key_binding: bind_i,
                our_versions: VersionRange::new(1, 1).unwrap(),
                our_capabilities: Capabilities::empty(),
            };
            perform_handshake(
                ctrl_send.as_mut(),
                ctrl_recv.as_mut(),
                params,
                &store_i,
                &rng_i,
                &clock,
                |_| async { Ok(TrustTier::SameAccount) },
            )
            .await
            .expect("handshake i");

            count_i.fetch_add(1, Ordering::SeqCst);
            let _ = rx_i.wait_for(|&released| released).await;
            drop(ctrl_send);
            drop(ctrl_recv);
            drop(chan_i);
        });
    }

    let (store_8, id_8, bind_8) = senders.remove(0);
    let chan_8 = sender_chans.remove(0);
    let rng_8 = SeededRng::new(4008);
    let (s9_handshaken_tx, s9_handshaken_rx) = tokio::sync::oneshot::channel::<()>();
    let mut rx_8 = release_rest_rx.clone();
    let sender_8_task = async move {
        let (mut ctrl_send, mut ctrl_recv) = chan_8.open_bi().await.unwrap();
        let params = HandshakeParams {
            authenticated_peer: receiver_peer,
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &id_8,
            our_attestation_token: "mock-token-8".to_string(),
            our_key_binding: bind_8,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        perform_handshake(
            ctrl_send.as_mut(),
            ctrl_recv.as_mut(),
            params,
            &store_8,
            &rng_8,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("handshake 8");

        s9_handshaken_tx.send(()).ok();
        let _ = rx_8.wait_for(|&released| released).await;
        drop(ctrl_send);
        drop(ctrl_recv);
        drop(chan_8);
    };

    let mut s9_handshaken_rx = s9_handshaken_rx;
    let controller_task = async move {
        while handshaken_count.load(Ordering::SeqCst) < 8 {
            tokio::task::yield_now().await;
        }

        let timeout_res =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut s9_handshaken_rx).await;
        assert!(
            timeout_res.is_err(),
            "the 9th channel must not complete handshake while 8 channels are in flight"
        );

        release_0_tx.send(()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), &mut s9_handshaken_rx)
            .await
            .expect("handshake 9 must complete after channel 0 closes")
            .expect("handshake 9 signal");

        release_rest_tx.send(true).unwrap();
        drop(incoming_tx);
    };

    let ((), _others, (), (), ()) = tokio::join!(
        sender_0_task,
        futures_util::future::join_all(other_tasks),
        sender_8_task,
        controller_task,
        async {
            let res = listener_task.await;
            assert!(
                res.is_ok(),
                "listen_for_transfers must return Ok(()): {res:?}"
            );
        }
    );
}

#[tokio::test]
async fn closing_incoming_queue_waits_for_in_flight_transfer() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(1);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };
    incoming_tx
        .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(10);
    let root_receiver = RootId::new(20);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"in-flight work payload";
    std::fs::write(sender_dir.path().join("inflight.txt"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("inf_item").unwrap();
    let src_rel = RelPath::new("inflight.txt").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(5001);
    let sender_rng = SeededRng::new(5002);

    let (offer_accepted_tx, offer_accepted_rx) = tokio::sync::oneshot::channel::<()>();
    let (incoming_closed_tx, incoming_closed_rx) = tokio::sync::oneshot::channel::<()>();

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        offer_accepted_tx.send(()).unwrap();
        incoming_closed_rx.await.unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        sender_ctrl_send.finish().await.unwrap();
    };

    let arrived = Arc::new(AtomicBool::new(false));
    let arrived_cb = Arc::clone(&arrived);
    let on_arrival = move |_from, paths: &[RelPath]| {
        if !paths.is_empty() {
            arrived_cb.store(true, Ordering::SeqCst);
        }
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        Some(&on_arrival),
    );

    let ((), (), ()) = tokio::join!(
        sender_task,
        async {
            offer_accepted_rx.await.unwrap();
            drop(incoming_tx);
            incoming_closed_tx.send(()).unwrap();
        },
        async {
            let res = listener_task.await;
            assert!(
                res.is_ok(),
                "listen_for_transfers must return Ok(()): {res:?}"
            );
            assert!(
                arrived.load(Ordering::SeqCst),
                "transfer must complete and reach on_arrival before listen_for_transfers returns"
            );
        }
    );
}

struct TestTransferConfig<'a> {
    sender_chan: &'a dyn SecureChannel,
    receiver_id: &'a PublicIdentity,
    sender_store: &'a SoftwareKeyStore,
    sender_id: &'a PublicIdentity,
    sender_binding: KeyBinding,
    sender_vfs: &'a NativeVfs,
    root_sender: RootId,
    clock: &'a FakeClock,
    rng: &'a SeededRng,
}

async fn run_test_transfer(
    cfg: &TestTransferConfig<'_>,
    transfer_id: TransferId,
    item_id: ItemId,
    src_rel: RelPath,
    content: &[u8],
) {
    let (mut sender_ctrl_send, mut sender_ctrl_recv) =
        cfg.sender_chan.open_bi().await.expect("open ctrl bi");
    let sender_params = HandshakeParams {
        authenticated_peer: cfg.receiver_id.device_id(),
        our_channel_max_frame_size: MAX_FRAME,
        our_identity: cfg.sender_id,
        our_attestation_token: "mock-token-sender".to_string(),
        our_key_binding: cfg.sender_binding.clone(),
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Capabilities::empty(),
    };
    let sender_session = perform_handshake(
        sender_ctrl_send.as_mut(),
        sender_ctrl_recv.as_mut(),
        sender_params,
        cfg.sender_store,
        cfg.rng,
        cfg.clock,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("sender handshake");

    let (_, hash) = outboard(content);
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();
    let offer = TransferOffer::new(
        transfer_id,
        vec![offer_item],
        content.len() as u64,
        None,
        None,
    )
    .unwrap();
    let offer_bytes =
        encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
    sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

    let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
        .await
        .unwrap();
    let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
    accept.for_offer(&offer).unwrap();

    let (mut data_send, mut data_recv) = cfg.sender_chan.open_bi().await.unwrap();
    let prepared = prepare_item(
        cfg.sender_vfs,
        cfg.root_sender,
        &src_rel,
        cfg.sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();
    let send_req = SendRequest {
        root: cfg.root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: sender_session
            .peer_max_frame_size()
            .min(cfg.sender_chan.max_frame_size()),
        item: &prepared,
    };
    let mut streams = SessionStreams {
        control_send: sender_ctrl_send.as_mut(),
        control_recv: sender_ctrl_recv.as_mut(),
        data_send: data_send.as_mut(),
        data_recv: data_recv.as_mut(),
    };
    let send_res = send_file(cfg.sender_vfs, &send_req, &mut streams)
        .await
        .unwrap();
    assert!(send_res);
}

struct AcceptDropGuard {
    completed: bool,
    counter: Arc<AtomicUsize>,
}

impl Drop for AcceptDropGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct AcceptTrackingIncoming {
    channels: tokio::sync::mpsc::Receiver<Box<dyn SecureChannel>>,
    handshake_notify: Arc<tokio::sync::Notify>,
    polled_notify: Arc<tokio::sync::Notify>,
    polled_count: Arc<AtomicUsize>,
    created_count: Arc<AtomicUsize>,
    dropped_count: Arc<AtomicUsize>,
}

impl Incoming for AcceptTrackingIncoming {
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>> {
        self.created_count.fetch_add(1, Ordering::SeqCst);
        let channels = &mut self.channels;
        let handshake_notify = Arc::clone(&self.handshake_notify);
        let polled_notify = Arc::clone(&self.polled_notify);
        let polled_count = Arc::clone(&self.polled_count);
        let dropped_count = Arc::clone(&self.dropped_count);

        Box::pin(async move {
            let mut guard = AcceptDropGuard {
                completed: false,
                counter: dropped_count,
            };
            polled_count.fetch_add(1, Ordering::SeqCst);
            polled_notify.notify_waiters();
            handshake_notify.notified().await;
            let chan = match channels.recv().await {
                Some(chan) => chan,
                None => {
                    guard.completed = true;
                    return Err(TransportError::Closed);
                }
            };
            guard.completed = true;
            Ok(chan)
        })
    }
}

#[tokio::test]
async fn pending_accept_is_not_dropped_when_in_flight_transfer_completes() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store_1, sender_id_1, sender_binding_1),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();
    let ((sender_store_2, sender_id_2, sender_binding_2), _) = create_test_identities();

    let (sender_chan_1, listener_chan_1) =
        mock_channel_pair(sender_id_1.device_id(), receiver_id.device_id(), MAX_FRAME);
    let (sender_chan_2, listener_chan_2) =
        mock_channel_pair(sender_id_2.device_id(), receiver_id.device_id(), MAX_FRAME);

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(2);
    let handshake_notify = Arc::new(tokio::sync::Notify::new());
    let polled_notify = Arc::new(tokio::sync::Notify::new());
    let polled_count = Arc::new(AtomicUsize::new(0));
    let created_count = Arc::new(AtomicUsize::new(0));
    let dropped_count = Arc::new(AtomicUsize::new(0));

    let mut incoming = AcceptTrackingIncoming {
        channels: incoming_rx,
        handshake_notify: Arc::clone(&handshake_notify),
        polled_notify: Arc::clone(&polled_notify),
        polled_count: Arc::clone(&polled_count),
        created_count: Arc::clone(&created_count),
        dropped_count: Arc::clone(&dropped_count),
    };

    incoming_tx
        .send(Box::new(listener_chan_1) as Box<dyn SecureChannel>)
        .await
        .unwrap();
    incoming_tx
        .send(Box::new(listener_chan_2) as Box<dyn SecureChannel>)
        .await
        .unwrap();

    let sender_dir_1 = tempfile::tempdir().expect("sender 1 tempdir");
    let sender_dir_2 = tempfile::tempdir().expect("sender 2 tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender_1 = RootId::new(101);
    let root_sender_2 = RootId::new(102);
    let root_receiver = RootId::new(201);
    sender_vfs
        .register_root(root_sender_1, sender_dir_1.path().to_path_buf(), false)
        .unwrap();
    sender_vfs
        .register_root(root_sender_2, sender_dir_2.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content_1 = b"first channel payload bytes";
    let content_2 = b"second channel payload bytes";
    std::fs::write(sender_dir_1.path().join("first.bin"), content_1).unwrap();
    std::fs::write(sender_dir_2.path().join("second.bin"), content_2).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(9001);
    let sender_rng_1 = SeededRng::new(9002);
    let sender_rng_2 = SeededRng::new(9003);

    let channel_1_arrived = Arc::new(tokio::sync::Notify::new());
    let channel_2_arrived = Arc::new(tokio::sync::Notify::new());
    let c1_arrived_signal = Arc::clone(&channel_1_arrived);
    let c2_arrived_signal = Arc::clone(&channel_2_arrived);

    let on_arrival = move |_from: DeviceId, paths: &[RelPath]| {
        for p in paths {
            if p.as_str() == "first.bin" {
                c1_arrived_signal.notify_waiters();
            } else if p.as_str() == "second.bin" {
                c2_arrived_signal.notify_waiters();
            }
        }
    };

    // Pre-seed permit for channel 1 so accept 1 returns immediately.
    handshake_notify.notify_one();

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        Some(&on_arrival),
    );

    let ((), ()) = tokio::join!(
        async {
            // Wait until accept 2 is created and has entered handshake_notify.notified().
            while polled_count.load(Ordering::SeqCst) < 2 {
                let notified = polled_notify.notified();
                if polled_count.load(Ordering::SeqCst) >= 2 {
                    break;
                }
                notified.await;
            }

            // Run channel 1 transfer to completion while accept 2 is pending.
            let cfg_1 = TestTransferConfig {
                sender_chan: &sender_chan_1,
                receiver_id: &receiver_id,
                sender_store: &sender_store_1,
                sender_id: &sender_id_1,
                sender_binding: sender_binding_1,
                sender_vfs: &sender_vfs,
                root_sender: root_sender_1,
                clock: &clock,
                rng: &sender_rng_1,
            };
            run_test_transfer(
                &cfg_1,
                sample_transfer(VALID_V7_A),
                ItemId::new("item_1").unwrap(),
                RelPath::new("first.bin").unwrap(),
                content_1,
            )
            .await;

            // Ensure channel 1 reached listener completion.
            channel_1_arrived.notified().await;

            // Release accept 2 from simulated handshake.
            handshake_notify.notify_one();

            // Run channel 2 transfer to completion.
            let cfg_2 = TestTransferConfig {
                sender_chan: &sender_chan_2,
                receiver_id: &receiver_id,
                sender_store: &sender_store_2,
                sender_id: &sender_id_2,
                sender_binding: sender_binding_2,
                sender_vfs: &sender_vfs,
                root_sender: root_sender_2,
                clock: &clock,
                rng: &sender_rng_2,
            };
            run_test_transfer(
                &cfg_2,
                sample_transfer(VALID_V7_B),
                ItemId::new("item_2").unwrap(),
                RelPath::new("second.bin").unwrap(),
                content_2,
            )
            .await;

            channel_2_arrived.notified().await;

            // Close incoming queue and allow final accept to terminate listener.
            drop(incoming_tx);
            handshake_notify.notify_one();
        },
        async {
            let res = listener_task.await;
            assert!(
                res.is_ok(),
                "listen_for_transfers must return Ok(()): {res:?}"
            );
        }
    );

    assert_eq!(
        std::fs::read(receiver_dir.path().join("first.bin")).unwrap(),
        content_1
    );
    assert_eq!(
        std::fs::read(receiver_dir.path().join("second.bin")).unwrap(),
        content_2
    );

    assert_eq!(
        dropped_count.load(Ordering::SeqCst),
        0,
        "no accept future was dropped before completing"
    );
}

#[tokio::test]
async fn sixteen_unassigned_control_frames_before_offer_are_accepted() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(410);
    let root_receiver = RootId::new(510);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"data after sixteen unassigned frames";
    std::fs::write(sender_dir.path().join("file.bin"), content).unwrap();
    let (_, hash) = outboard(content);

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("bin_item").unwrap();
    let src_rel = RelPath::new("file.bin").unwrap();
    let offer_item = OfferItem::new(item_id, src_rel.clone(), content.len() as u64, hash).unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(1212);
    let sender_rng = SeededRng::new(3434);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        // Send 16 unassigned control frames (0x0f) before the TransferOffer
        for _ in 0..16 {
            let unassigned_frame = encode_frame(0x0f, b"future_field", MAX_FRAME).unwrap();
            sender_ctrl_send.write_all(&unassigned_frame).await.unwrap();
        }

        let offer = TransferOffer::new(
            transfer_id,
            vec![offer_item],
            content.len() as u64,
            None,
            None,
        )
        .unwrap();
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &src_rel,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);
        Ok::<(), ListenerError>(())
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "file.bin");
    assert_eq!(
        std::fs::read(receiver_dir.path().join("file.bin")).unwrap(),
        content
    );
}

#[tokio::test]
async fn seventeen_unassigned_control_frames_before_offer_are_refused() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(511);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(1212);
    let sender_rng = SeededRng::new(3434);

    let sender_task = async {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_id.device_id(),
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store,
            &sender_rng,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender handshake");

        // Send 17 unassigned control frames (0x0f)
        for _ in 0..17 {
            let unassigned_frame = encode_frame(0x0f, b"future_field", MAX_FRAME).unwrap();
            sender_ctrl_send.write_all(&unassigned_frame).await.unwrap();
        }
    };

    let listener_task = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );

    let (_, listener_res) = tokio::join!(sender_task, listener_task);
    let failure = listener_res.expect_err("17 unassigned frames must be refused");
    assert_eq!(failure.phase, ChannelPhase::Offer);
    match failure.error {
        ListenerError::ProtocolViolation(msg) => {
            assert_eq!(msg, "more than 16 unassigned frames in a row");
        }
        other => panic!("expected ProtocolViolation, got {other:?}"),
    }
}

#[tokio::test]
async fn send_loop_resets_ignorable_count_on_assigned_frame() {
    use tradr_core::{ChunkIndex, ChunkRequest, ItemComplete};
    use tradr_proto::data::{
        decode_chunk_data_header_frame, encode_chunk_request_frame, encode_item_complete_frame,
    };

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(601);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"transfer loop reset test content";
    let src_rel = RelPath::new("file.bin").unwrap();
    std::fs::write(sender_dir.path().join("file.bin"), content).unwrap();

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("bin_item").unwrap();
    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: MAX_FRAME,
        item: &prepared,
    };

    let ((mut data_tx_send, mut data_tx_recv), (mut data_peer_send, mut data_peer_recv)) =
        memory_stream_pair();
    let ((mut ctrl_tx_send, mut ctrl_tx_recv), (mut ctrl_peer_send, _ctrl_peer_recv)) =
        memory_stream_pair();

    let peer_task = async move {
        // Ten unassigned frames followed by an assigned frame to test counter reset.
        for _ in 0..10 {
            let unassigned = encode_frame(0x24, b"future_data", MAX_FRAME).unwrap();
            data_peer_send.write_all(&unassigned).await.unwrap();
        }

        let flow_control = encode_frame(0x23, b"", MAX_FRAME).unwrap();
        data_peer_send.write_all(&flow_control).await.unwrap();

        for _ in 0..10 {
            let unassigned = encode_frame(0x24, b"future_data", MAX_FRAME).unwrap();
            data_peer_send.write_all(&unassigned).await.unwrap();
        }

        let req = ChunkRequest::new(transfer_id, item_id, ChunkIndex::new(0), 1);
        let req_frame = encode_chunk_request_frame(&req, MAX_FRAME).unwrap();
        data_peer_send.write_all(&req_frame).await.unwrap();
        data_peer_send.finish().await.unwrap();

        // Serving chunk 0 proves the assigned frame reset the ignorable counter.
        let header = loop {
            let frame = read_frame_helper(&mut data_peer_recv, MAX_FRAME)
                .await
                .expect("read frame");
            if let Ok(hdr) = decode_chunk_data_header_frame(&frame)
                && hdr.chunk_index().value() == 0
            {
                break hdr;
            }
        };
        let mut payload = vec![0u8; header.payload_len() as usize];
        let mut read_bytes = 0;
        while read_bytes < payload.len() {
            let n = data_peer_recv
                .read(&mut payload[read_bytes..])
                .await
                .expect("read chunk data payload");
            assert!(n > 0, "unexpected EOF while reading chunk data payload");
            read_bytes += n;
        }

        let item_complete = ItemComplete::new(transfer_id, item_id, true, None);
        let complete_frame = encode_item_complete_frame(&item_complete, MAX_FRAME).unwrap();
        ctrl_peer_send.write_all(&complete_frame).await.unwrap();
    };

    let sender_task = async {
        let mut streams = SessionStreams {
            control_send: &mut ctrl_tx_send,
            control_recv: &mut ctrl_tx_recv,
            data_send: &mut data_tx_send,
            data_recv: &mut data_tx_recv,
        };
        send_file(&sender_vfs, &send_req, &mut streams).await
    };

    let ((), send_res) = tokio::join!(peer_task, sender_task);
    assert!(send_res.expect("send_file must succeed after reset"));
}

#[tokio::test]
async fn send_loop_refuses_seventeen_unassigned_frames() {
    use tradr_app::transfer::TransferSessionError;

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(602);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();

    let content = b"transfer loop refusal test content";
    let src_rel = RelPath::new("file.bin").unwrap();
    std::fs::write(sender_dir.path().join("file.bin"), content).unwrap();

    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("bin_item").unwrap();
    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: MAX_FRAME,
        item: &prepared,
    };

    let ((mut data_tx_send, mut data_tx_recv), (mut data_peer_send, _data_peer_recv)) =
        memory_stream_pair();
    let ((mut ctrl_tx_send, mut ctrl_tx_recv), (_ctrl_peer_send, _ctrl_peer_recv)) =
        memory_stream_pair();

    let peer_task = async move {
        // 17 unassigned data plane frames (0x24)
        for _ in 0..17 {
            let unassigned = encode_frame(0x24, b"future_data", MAX_FRAME).unwrap();
            data_peer_send.write_all(&unassigned).await.unwrap();
        }
    };

    let sender_task = async {
        let mut streams = SessionStreams {
            control_send: &mut ctrl_tx_send,
            control_recv: &mut ctrl_tx_recv,
            data_send: &mut data_tx_send,
            data_recv: &mut data_tx_recv,
        };
        send_file(&sender_vfs, &send_req, &mut streams).await
    };

    let ((), send_res) = tokio::join!(peer_task, sender_task);
    let err = send_res.expect_err("17 unassigned data frames must be refused");
    match err {
        TransferSessionError::ProtocolViolation(msg) => {
            assert_eq!(msg, "more than 16 unassigned frames in a row");
        }
        other => panic!("expected ProtocolViolation, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn peer_that_opens_no_control_stream_times_out_before_stream() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (_sender_store, sender_id, _sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (_sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(20);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(111);

    let start = tokio::time::Instant::now();
    let res = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    )
    .await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_secs(20)
            && elapsed < std::time::Duration::from_secs(21),
        "expected elapsed time in [20s, 21s), got {elapsed:?}"
    );

    let failure = res.expect_err("peer opening no control stream must time out");
    assert_eq!(failure.peer, sender_id.device_id());
    assert_eq!(failure.phase, ChannelPhase::BeforeStream);
    assert!(
        matches!(
            failure.error,
            ListenerError::Transport(TransportError::TimedOut)
        ),
        "expected Transport(TimedOut), got {:?}",
        failure.error
    );
}

#[tokio::test(start_paused = true)]
async fn peer_that_sends_no_hello_times_out_during_handshake() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (_sender_store, sender_id, _sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(20);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(111);

    // Peer opens the control stream and sends nothing.
    let (_sender_ctrl_send, _sender_ctrl_recv) = sender_chan.open_bi().await.unwrap();

    let start = tokio::time::Instant::now();
    let res = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    )
    .await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_secs(20)
            && elapsed < std::time::Duration::from_secs(21),
        "expected elapsed time in [20s, 21s), got {elapsed:?}"
    );

    let failure = res.expect_err("peer sending nothing must time out");
    assert_eq!(failure.peer, sender_id.device_id());
    assert_eq!(failure.phase, ChannelPhase::Handshake);
    assert!(
        matches!(
            failure.error,
            ListenerError::Transport(TransportError::TimedOut)
        ),
        "expected Transport(TimedOut), got {:?}",
        failure.error
    );
}

#[tokio::test(start_paused = true)]
async fn peer_idle_after_handshake_is_not_timed_out() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (
        (sender_store, sender_id, sender_binding),
        (receiver_store, receiver_id, receiver_binding),
    ) = create_test_identities();

    let (sender_chan, listener_chan) =
        mock_channel_pair(sender_id.device_id(), receiver_id.device_id(), MAX_FRAME);

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();
    let root_sender = RootId::new(10);
    let root_receiver = RootId::new(20);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let file_content = b"content after handshake pause";
    std::fs::write(sender_dir.path().join("doc.txt"), file_content).unwrap();
    let (_, file_hash) = outboard(file_content);
    let transfer_id = sample_transfer(VALID_V7_A);
    let item_id = ItemId::new("doc_item").unwrap();
    let rel_path = RelPath::new("doc.txt").unwrap();
    let offer_item = OfferItem::new(
        item_id,
        rel_path.clone(),
        file_content.len() as u64,
        file_hash,
    )
    .unwrap();
    let offer = TransferOffer::new(
        transfer_id,
        vec![offer_item],
        file_content.len() as u64,
        None,
        None,
    )
    .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(111);
    let sender_rng = SeededRng::new(222);

    let (mut sender_ctrl_send, mut sender_ctrl_recv) = sender_chan.open_bi().await.unwrap();

    let sender_params = HandshakeParams {
        authenticated_peer: receiver_id.device_id(),
        our_channel_max_frame_size: MAX_FRAME,
        our_identity: &sender_id,
        our_attestation_token: "mock-token-sender".to_string(),
        our_key_binding: sender_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Capabilities::empty(),
    };

    let listener_fut = handle_incoming_channel(
        &listener_chan,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
    );
    tokio::pin!(listener_fut);

    let sender_handshake_fut = perform_handshake(
        sender_ctrl_send.as_mut(),
        sender_ctrl_recv.as_mut(),
        sender_params,
        &sender_store,
        &sender_rng,
        &clock,
        |_| async { Ok(TrustTier::SameAccount) },
    );

    let (sender_session, ()) = tokio::select! {
        res = sender_handshake_fut => (res.unwrap(), ()),
        res = &mut listener_fut => panic!("listener completed early: {res:?}"),
    };

    // The peer has completed the handshake and now sends no offer for 60 seconds of paused time.
    let timeout_res =
        tokio::time::timeout(std::time::Duration::from_secs(60), &mut listener_fut).await;
    assert!(
        timeout_res.is_err(),
        "handler must still be running after 60 seconds without offer"
    );

    let sender_transfer_task = async {
        let offer_bytes =
            encode_transfer_offer_frame(&offer, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer).unwrap();

        let (mut data_send, mut data_recv) = sender_chan.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs,
            root_sender,
            &rel_path,
            sender_vfs.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &rel_path,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);

        sender_ctrl_send.finish().await.unwrap();
        drop(sender_ctrl_send);
        drop(sender_ctrl_recv);
        drop(data_send);
        drop(data_recv);
    };

    let ((), placed) = tokio::join!(sender_transfer_task, async { listener_fut.await.unwrap() });

    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "doc.txt");
    let received = std::fs::read(receiver_dir.path().join("doc.txt")).unwrap();
    assert_eq!(received, file_content);
}

#[tokio::test(start_paused = true)]
async fn eight_stalled_peers_do_not_block_ninth_transfer_after_deadline() {
    let clock = FakeClock {
        now: UnixTime::from_secs(NOW),
    };
    let (_sender_default, (receiver_store, receiver_id, receiver_binding)) =
        create_test_identities();

    let mut senders = Vec::new();
    for i in 0..9 {
        let rng = SeededRng::new(5000 + i as u64);
        let store = SoftwareKeyStore::generate(&rng).expect("generate store");
        let id = store.public_identity().expect("public identity");
        let sig = store
            .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
            .expect("sign keybind");
        let bind = KeyBinding::new(id.agreement_pub().clone(), sig, UnixTime::from_secs(LATER));
        senders.push((store, id, bind));
    }

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
    let mut incoming = MockIncoming {
        channels: incoming_rx,
    };

    let mut sender_chans = Vec::new();
    for (_, id, _) in &senders {
        let (sender_chan, listener_chan) =
            mock_channel_pair(id.device_id(), receiver_id.device_id(), MAX_FRAME);
        sender_chans.push(sender_chan);
        incoming_tx
            .send(Box::new(listener_chan) as Box<dyn SecureChannel>)
            .await
            .unwrap();
    }

    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(60);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let listener_params = ListenerParams {
        root: root_receiver,
        our_identity: &receiver_id,
        our_attestation_token: Arc::new(FixedAttestation("mock-token-receiver".to_string())),
        our_key_binding: receiver_binding,
        our_versions: VersionRange::new(1, 1).unwrap(),
        our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::empty())),
        browse_access: Arc::new(BrowseAccess::new()),
    };

    let listener_rng = SeededRng::new(8888);

    // Eight peers open control stream and send no Hello.
    let mut stalled_streams = Vec::new();
    for chan in &sender_chans[..8] {
        let (ctrl_send, ctrl_recv) = chan.open_bi().await.unwrap();
        stalled_streams.push((ctrl_send, ctrl_recv));
    }

    // Ninth peer config for a real transfer.
    let (sender_store_9, sender_id_9, sender_binding_9) = senders.pop().unwrap();
    let sender_chan_9 = sender_chans.pop().unwrap();
    let sender_dir_9 = tempfile::tempdir().expect("sender tempdir");
    let sender_vfs_9 = NativeVfs::new();
    let root_sender_9 = RootId::new(70);
    sender_vfs_9
        .register_root(root_sender_9, sender_dir_9.path().to_path_buf(), false)
        .unwrap();

    let file_content = b"ninth transfer succeeds";
    std::fs::write(sender_dir_9.path().join("ninth.bin"), file_content).unwrap();
    let (_, file_hash) = outboard(file_content);
    let transfer_id_9 = sample_transfer(VALID_V7_B);
    let item_id_9 = ItemId::new("ninth_item").unwrap();
    let rel_9 = RelPath::new("ninth.bin").unwrap();
    let offer_item_9 = OfferItem::new(
        item_id_9,
        rel_9.clone(),
        file_content.len() as u64,
        file_hash,
    )
    .unwrap();
    let offer_9 = TransferOffer::new(
        transfer_id_9,
        vec![offer_item_9],
        file_content.len() as u64,
        None,
        None,
    )
    .unwrap();
    let sender_rng_9 = SeededRng::new(9999);

    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel::<Vec<RelPath>>();
    let arrived_tx = Arc::new(Mutex::new(Some(arrived_tx)));
    let on_arrival = move |_from, paths: &[RelPath]| {
        if let Some(tx) = arrived_tx.lock().unwrap().take() {
            tx.send(paths.to_vec()).ok();
        }
    };

    let listener_task = listen_for_transfers(
        &mut incoming,
        &receiver_vfs,
        listener_params,
        &receiver_store,
        &listener_rng,
        &clock,
        &BaoVerifier,
        |_| async { Ok(TrustTier::SameAccount) },
        None,
        None,
        Some(&on_arrival),
    );

    let receiver_peer = receiver_id.device_id();
    let sender_9_task = async move {
        let (mut sender_ctrl_send, mut sender_ctrl_recv) =
            sender_chan_9.open_bi().await.expect("open ctrl bi");
        let sender_params = HandshakeParams {
            authenticated_peer: receiver_peer,
            our_channel_max_frame_size: MAX_FRAME,
            our_identity: &sender_id_9,
            our_attestation_token: "mock-token-sender".to_string(),
            our_key_binding: sender_binding_9,
            our_versions: VersionRange::new(1, 1).unwrap(),
            our_capabilities: Capabilities::empty(),
        };
        let sender_session = perform_handshake(
            sender_ctrl_send.as_mut(),
            sender_ctrl_recv.as_mut(),
            sender_params,
            &sender_store_9,
            &sender_rng_9,
            &clock,
            |_| async { Ok(TrustTier::SameAccount) },
        )
        .await
        .expect("sender 9 handshake");

        let offer_bytes =
            encode_transfer_offer_frame(&offer_9, sender_session.peer_max_frame_size()).unwrap();
        sender_ctrl_send.write_all(&offer_bytes).await.unwrap();

        let accept_frame = read_frame_helper(sender_ctrl_recv.as_mut(), MAX_FRAME)
            .await
            .unwrap();
        let accept = decode_transfer_accept_frame(&accept_frame).unwrap();
        accept.for_offer(&offer_9).unwrap();

        let (mut data_send, mut data_recv) = sender_chan_9.open_bi().await.unwrap();
        let prepared = prepare_item(
            &sender_vfs_9,
            root_sender_9,
            &rel_9,
            sender_vfs_9.scratch_file().unwrap(),
        )
        .await
        .unwrap();
        let send_req = SendRequest {
            root: root_sender_9,
            rel_path: &rel_9,
            transfer_id: transfer_id_9,
            item_id: item_id_9,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan_9.max_frame_size()),
            item: &prepared,
        };
        let mut streams = SessionStreams {
            control_send: sender_ctrl_send.as_mut(),
            control_recv: sender_ctrl_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };
        let send_res = send_file(&sender_vfs_9, &send_req, &mut streams)
            .await
            .unwrap();
        assert!(send_res);

        sender_ctrl_send.finish().await.unwrap();
        drop(sender_ctrl_send);
        drop(sender_ctrl_recv);
        drop(data_send);
        drop(data_recv);
    };

    let (placed, _listener_res, ()) = tokio::join!(
        async {
            let placed = arrived_rx.await.expect("arrived rx");
            drop(incoming_tx);
            placed
        },
        async {
            listener_task
                .await
                .expect("listen_for_transfers must succeed")
        },
        sender_9_task,
    );

    assert_eq!(placed, vec![RelPath::new("ninth.bin").unwrap()]);
    let received = std::fs::read(receiver_dir.path().join("ninth.bin")).unwrap();
    assert_eq!(received, file_content);
    drop(stalled_streams);
}

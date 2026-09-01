//! Integration tests for the listener half of the composition root (WI-M1-024).
//! Validates end-to-end file transfers, multi-item offers, chunk resumption,
//! selective acceptance filtering, and forward compatibility against a hand-driven sender.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tauri_plugin_tradr::handshake::{HandshakeParams, perform_handshake};
use tauri_plugin_tradr::listener::{
    ListenerError, ListenerParams, accept_and_handle_transfer, derive_item_resumption,
    handle_incoming_channel, listen_for_transfers,
};
use tauri_plugin_tradr::peer_trust::OwnAttestation;
use tauri_plugin_tradr::transfer::{SendRequest, SessionStreams, send_file};
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
use tradr_vfs::NativeVfs;
use tradr_vfs::sanitization::partial_file_rel_path;

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
        our_capabilities: Capabilities::empty(),
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
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
    );

    let (sender_res, listener_res) = tokio::join!(sender_task, listener_task);
    sender_res.unwrap();
    let placed = listener_res.unwrap();
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].as_str(), "document.pdf");

    let received_bytes = std::fs::read(receiver_dir.path().join("document.pdf")).unwrap();
    assert_eq!(received_bytes, file_content);
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
        our_capabilities: Capabilities::empty(),
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
        let send_req_1 = SendRequest {
            root: root_sender,
            rel_path: &rel_1,
            transfer_id,
            item_id: item_1,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
        let send_req_2 = SendRequest {
            root: root_sender,
            rel_path: &rel_2,
            transfer_id,
            item_id: item_2,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
    let partial_dir = RelPath::new(&format!(".tradr-partial/{transfer_id}")).unwrap();
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
        our_capabilities: Capabilities::empty(),
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
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
        our_capabilities: Capabilities::empty(),
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
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &rel_keep,
            transfer_id,
            item_id: item_keep,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
        our_capabilities: Capabilities::empty(),
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
    );

    let (_, listener_res) = tokio::join!(sender_task, listener_task);
    assert!(matches!(listener_res, Err(ListenerError::Handshake(_))));
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
        our_capabilities: Capabilities::empty(),
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

        // Send an unassigned control message (0x0c) before the TransferOffer
        let unassigned_frame = encode_frame(0x0c, b"future_field", MAX_FRAME).unwrap();
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
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
        our_capabilities: Capabilities::empty(),
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
        let send_req = SendRequest {
            root: root_sender,
            rel_path: &src_rel,
            transfer_id,
            item_id,
            max_frame_size: sender_session
                .peer_max_frame_size()
                .min(sender_chan.max_frame_size()),
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
        our_capabilities: Capabilities::empty(),
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
    )
    .await;

    assert!(res.is_ok());
}

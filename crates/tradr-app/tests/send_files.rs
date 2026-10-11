//! Integration tests for the sending half and command pipeline (WI-M1-025).
//! Tests `execute_send_files` driving the full outgoing transfer lifecycle against
//! `handle_incoming_channel` over live QUIC loopback connections and memory channels.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::listener::{ListenerParams, handle_incoming_channel};
use tradr_app::peer_trust::OwnAttestation;
use tradr_app::send::{
    TransferProgressPayload, execute_send_files, execute_send_files_with_progress,
    resolve_send_items,
};
use tradr_core::{
    Candidate, Capabilities, Clock, DomainTag, KeyBinding, KeyStore, PeerExpectation,
    REFERENCE_CHUNK_SIZE_BYTES, RelPath, RootId, Transport, TransportId, TrustTier, UnixTime,
    VersionRange,
};
use tradr_identity::{OsRng, SoftwareKeyStore, SystemClock};
use tradr_integrity::BaoVerifier;
use tradr_secrets::FileStore;
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

fn setup_key_store(dir: &std::path::Path) -> Arc<SoftwareKeyStore> {
    let rung = FileStore::new(dir.join("keys"));
    let store = SoftwareKeyStore::open(&rung, "device-key", &OsRng).expect("open key store");
    Arc::new(store)
}

// A fixed own-attestation for tests that never exercise sign-in itself.
struct FixedAttestation(String);

impl OwnAttestation for FixedAttestation {
    fn id_token(&self) -> Option<String> {
        Some(self.0.clone())
    }
}

#[tokio::test]
async fn send_files_end_to_end_over_quic_loopback() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_store = setup_key_store(sender_dir.path());
    let receiver_store = setup_key_store(receiver_dir.path());

    let sender_id = sender_store.public_identity().expect("sender id");
    let receiver_id = receiver_store.public_identity().expect("receiver id");

    let file1_content = b"First test file for tradr loopback transfer.".to_vec();
    let file2_content = vec![0x42u8; 1024 * 1024 + 100];

    std::fs::write(sender_dir.path().join("file1.txt"), &file1_content).expect("write file1");
    std::fs::write(sender_dir.path().join("file2.bin"), &file2_content).expect("write file2");

    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .expect("register sender root");

    let receiver_vfs = Arc::new(NativeVfs::new());
    let root_receiver = RootId::new(2);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register receiver root");

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let receiver_transport =
        QuicTransport::new(receiver_store.clone(), bind_addr).expect("rx transport");
    let rx_addr = receiver_transport.local_addr().expect("rx local addr");

    let sender_transport =
        QuicTransport::new(sender_store.clone(), bind_addr).expect("tx transport");

    let mut incoming = receiver_transport.listen().await.expect("rx listen");

    let rx_identity = receiver_id.clone();
    let rx_store_clone = receiver_store.clone();
    let rx_vfs_clone = receiver_vfs.clone();

    let rx_handle = tokio::spawn(async move {
        let channel = incoming.accept().await.expect("accept channel");
        let clock = SystemClock;
        let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
        let keybind_sig = rx_store_clone
            .sign(DomainTag::KeyBind, rx_identity.agreement_pub().as_bytes())
            .expect("sign");
        let our_key_binding =
            KeyBinding::new(rx_identity.agreement_pub().clone(), keybind_sig, not_after);

        let params = ListenerParams {
            root: root_receiver,
            our_identity: &rx_identity,
            our_attestation_token: Arc::new(FixedAttestation(String::new())),
            our_key_binding,
            our_versions: VersionRange::new(1, 1).expect("version range"),
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: Arc::new(BrowseAccess::new()),
            known_devices: None,
        };

        let res = handle_incoming_channel(
            channel.as_ref(),
            rx_vfs_clone.as_ref(),
            params,
            rx_store_clone.as_ref(),
            &OsRng,
            &SystemClock,
            &BaoVerifier,
            |_| async { Ok(TrustTier::SameAccount) },
            None,
            None,
        )
        .await;
        (res, channel)
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = sender_transport
        .connect(
            &candidate,
            &PeerExpectation::Device(receiver_id.device_id()),
        )
        .await
        .expect("connect");

    let files_to_send = vec!["file1.txt".to_string(), "file2.bin".to_string()];
    let sent_result = execute_send_files(
        channel.as_ref(),
        &sender_vfs,
        root_sender,
        &files_to_send,
        &sender_id,
        sender_store.as_ref(),
        String::new(),
        Capabilities::DIRECT_QUIC,
        None,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await;
    drop(channel);
    let rx_outcome = rx_handle.await;

    let sent_result = sent_result.expect("execute_send_files");
    assert_eq!(sent_result, vec!["file1.txt", "file2.bin"]);

    let (rx_result, _rx_chan) = rx_outcome.expect("rx join");
    let rx_result = rx_result.expect("rx handle channel");
    assert_eq!(rx_result.len(), 2);

    let rx_file1 = std::fs::read(receiver_dir.path().join("file1.txt")).expect("read rx file1");
    let rx_file2 = std::fs::read(receiver_dir.path().join("file2.bin")).expect("read rx file2");

    assert_eq!(rx_file1, file1_content);
    assert_eq!(rx_file2, file2_content);

    let partial_base = receiver_dir.path().join(".tradr-partial");
    if partial_base.exists() {
        let entries: Vec<_> = std::fs::read_dir(&partial_base)
            .expect("read .tradr-partial")
            .filter_map(Result::ok)
            .collect();
        assert!(
            entries.is_empty(),
            "expected no transfer directory left in .tradr-partial, found: {entries:?}"
        );
    }
}

#[tokio::test]
async fn send_files_respects_receiver_item_filtering() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_store = setup_key_store(sender_dir.path());
    let receiver_store = setup_key_store(receiver_dir.path());

    let sender_id = sender_store.public_identity().expect("sender id");
    let receiver_id = receiver_store.public_identity().expect("receiver id");

    std::fs::write(sender_dir.path().join("accepted.txt"), b"Accept me").expect("write accepted");
    std::fs::write(sender_dir.path().join("rejected.txt"), b"Reject me").expect("write rejected");

    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .expect("register sender root");

    let receiver_vfs = Arc::new(NativeVfs::new());
    let root_receiver = RootId::new(2);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register receiver root");

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let receiver_transport =
        QuicTransport::new(receiver_store.clone(), bind_addr).expect("rx transport");
    let rx_addr = receiver_transport.local_addr().expect("rx local addr");
    let sender_transport =
        QuicTransport::new(sender_store.clone(), bind_addr).expect("tx transport");

    let mut incoming = receiver_transport.listen().await.expect("rx listen");

    let rx_identity = receiver_id.clone();
    let rx_store_clone = receiver_store.clone();
    let rx_vfs_clone = receiver_vfs.clone();

    let rx_handle = tokio::spawn(async move {
        let channel = incoming.accept().await.expect("accept channel");
        let clock = SystemClock;
        let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
        let keybind_sig = rx_store_clone
            .sign(DomainTag::KeyBind, rx_identity.agreement_pub().as_bytes())
            .expect("sign");
        let our_key_binding =
            KeyBinding::new(rx_identity.agreement_pub().clone(), keybind_sig, not_after);

        let params = ListenerParams {
            root: root_receiver,
            our_identity: &rx_identity,
            our_attestation_token: Arc::new(FixedAttestation(String::new())),
            our_key_binding,
            our_versions: VersionRange::new(1, 1).expect("version range"),
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: Arc::new(BrowseAccess::new()),
            known_devices: None,
        };

        let filter = |item: &tradr_core::OfferItem| item.rel_path().as_str() != "rejected.txt";

        let res = handle_incoming_channel(
            channel.as_ref(),
            rx_vfs_clone.as_ref(),
            params,
            rx_store_clone.as_ref(),
            &OsRng,
            &SystemClock,
            &BaoVerifier,
            |_| async { Ok(TrustTier::SameAccount) },
            Some(&filter),
            None,
        )
        .await;
        (res, channel)
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = sender_transport
        .connect(
            &candidate,
            &PeerExpectation::Device(receiver_id.device_id()),
        )
        .await
        .expect("connect");

    let files_to_send = vec!["accepted.txt".to_string(), "rejected.txt".to_string()];
    let (sent_result, rx_outcome) = tokio::join!(
        execute_send_files(
            channel.as_ref(),
            &sender_vfs,
            root_sender,
            &files_to_send,
            &sender_id,
            sender_store.as_ref(),
            String::new(),
            Capabilities::DIRECT_QUIC,
            None,
            |_| async { Ok(TrustTier::SameAccount) },
        ),
        rx_handle,
    );

    let sent_result = sent_result.expect("execute_send_files");
    assert_eq!(sent_result, vec!["accepted.txt"]);

    let (rx_result, _rx_chan) = rx_outcome.expect("rx join");
    let rx_result = rx_result.expect("rx handle channel");
    assert_eq!(
        rx_result,
        vec![RelPath::new("accepted.txt").expect("relpath")]
    );

    assert!(receiver_dir.path().join("accepted.txt").exists());
    assert!(!receiver_dir.path().join("rejected.txt").exists());
}

#[tokio::test]
async fn send_files_rejects_empty_file_list() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let sender_store = setup_key_store(sender_dir.path());
    let sender_id = sender_store.public_identity().expect("sender id");
    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);

    let result = execute_send_files(
        &MockEmptyChannel,
        &sender_vfs,
        root_sender,
        &[],
        &sender_id,
        sender_store.as_ref(),
        String::new(),
        Capabilities::DIRECT_QUIC,
        None,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "no files provided for transfer");
}

struct MockEmptyChannel;

impl tradr_core::SecureChannel for MockEmptyChannel {
    fn peer(&self) -> tradr_core::DeviceId {
        tradr_core::DeviceId::from_bytes(&[0u8; 16]).unwrap()
    }
    fn transport(&self) -> tradr_core::TransportId {
        tradr_core::TransportId::new("direct-quic")
    }
    fn rtt(&self) -> Duration {
        Duration::from_millis(1)
    }
    fn max_frame_size(&self) -> u32 {
        65536
    }
    fn open_bi(
        &self,
    ) -> tradr_core::BoxFuture<
        '_,
        Result<
            (
                Box<dyn tradr_core::SendStream>,
                Box<dyn tradr_core::RecvStream>,
            ),
            tradr_core::TransportError,
        >,
    > {
        Box::pin(async { Err(tradr_core::TransportError::Closed) })
    }
    fn open_uni(
        &self,
    ) -> tradr_core::BoxFuture<
        '_,
        Result<Box<dyn tradr_core::SendStream>, tradr_core::TransportError>,
    > {
        Box::pin(async { Err(tradr_core::TransportError::Closed) })
    }
    fn accept_bi(
        &self,
    ) -> tradr_core::BoxFuture<
        '_,
        Result<
            (
                Box<dyn tradr_core::SendStream>,
                Box<dyn tradr_core::RecvStream>,
            ),
            tradr_core::TransportError,
        >,
    > {
        Box::pin(async { Err(tradr_core::TransportError::Closed) })
    }
    fn accept_uni(
        &self,
    ) -> tradr_core::BoxFuture<
        '_,
        Result<Box<dyn tradr_core::RecvStream>, tradr_core::TransportError>,
    > {
        Box::pin(async { Err(tradr_core::TransportError::Closed) })
    }
    fn close(&self) -> tradr_core::BoxFuture<'_, Result<(), tradr_core::TransportError>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn send_files_emits_preparing_progress_before_starting() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_store = setup_key_store(sender_dir.path());
    let receiver_store = setup_key_store(receiver_dir.path());

    let sender_id = sender_store.public_identity().expect("sender id");
    let receiver_id = receiver_store.public_identity().expect("receiver id");

    let file_size = REFERENCE_CHUNK_SIZE_BYTES + 4096;
    let file_content = vec![0x5au8; file_size as usize];
    let file_name = "large_chunk_file.bin";
    std::fs::write(sender_dir.path().join(file_name), &file_content).expect("write large file");

    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .expect("register sender root");

    let receiver_vfs = Arc::new(NativeVfs::new());
    let root_receiver = RootId::new(2);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register receiver root");

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let receiver_transport =
        QuicTransport::new(receiver_store.clone(), bind_addr).expect("rx transport");
    let rx_addr = receiver_transport.local_addr().expect("rx local addr");

    let sender_transport =
        QuicTransport::new(sender_store.clone(), bind_addr).expect("tx transport");

    let mut incoming = receiver_transport.listen().await.expect("rx listen");

    let rx_identity = receiver_id.clone();
    let rx_store_clone = receiver_store.clone();
    let rx_vfs_clone = receiver_vfs.clone();

    let rx_handle = tokio::spawn(async move {
        let channel = incoming.accept().await.expect("accept channel");
        let clock = SystemClock;
        let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
        let keybind_sig = rx_store_clone
            .sign(DomainTag::KeyBind, rx_identity.agreement_pub().as_bytes())
            .expect("sign");
        let our_key_binding =
            KeyBinding::new(rx_identity.agreement_pub().clone(), keybind_sig, not_after);

        let params = ListenerParams {
            root: root_receiver,
            our_identity: &rx_identity,
            our_attestation_token: Arc::new(FixedAttestation(String::new())),
            our_key_binding,
            our_versions: VersionRange::new(1, 1).expect("version range"),
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: Arc::new(BrowseAccess::new()),
            known_devices: None,
        };

        let res = handle_incoming_channel(
            channel.as_ref(),
            rx_vfs_clone.as_ref(),
            params,
            rx_store_clone.as_ref(),
            &OsRng,
            &SystemClock,
            &BaoVerifier,
            |_| async { Ok(TrustTier::SameAccount) },
            None,
            None,
        )
        .await;
        (res, channel)
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = sender_transport
        .connect(
            &candidate,
            &PeerExpectation::Device(receiver_id.device_id()),
        )
        .await
        .expect("connect");

    let files_to_send = vec![file_name.to_string()];
    let items = resolve_send_items(&sender_vfs, root_sender, &files_to_send)
        .await
        .expect("resolve_send_items");

    let mut payloads: Vec<TransferProgressPayload> = Vec::new();
    let (sent_result, rx_outcome) = tokio::join!(
        execute_send_files_with_progress(
            channel.as_ref(),
            &sender_vfs,
            &items,
            &sender_id,
            sender_store.as_ref(),
            String::new(),
            Capabilities::DIRECT_QUIC,
            None,
            |_| async { Ok(TrustTier::SameAccount) },
            |payload| payloads.push(payload),
        ),
        rx_handle,
    );

    let sent_result = sent_result.expect("execute_send_files_with_progress");
    assert_eq!(sent_result, vec![file_name]);

    let (rx_result, _rx_chan) = rx_outcome.expect("rx join");
    let rx_result = rx_result.expect("rx handle channel");
    assert_eq!(rx_result.len(), 1);

    let first_starting_idx = payloads
        .iter()
        .position(|p| p.status == "starting")
        .expect("first starting payload");

    let preparing_before: Vec<_> = payloads[..first_starting_idx]
        .iter()
        .filter(|p| p.status == "preparing")
        .collect();
    assert!(
        !preparing_before.is_empty(),
        "at least one preparing payload must precede the first starting payload"
    );

    let preparing_after = payloads[first_starting_idx..]
        .iter()
        .any(|p| p.status == "preparing");
    assert!(
        !preparing_after,
        "no preparing payload may appear after the first starting payload"
    );

    let expected_item_id = &payloads[first_starting_idx].item_id;
    let expected_rel_path = &payloads[first_starting_idx].rel_path;
    assert_eq!(expected_rel_path, file_name);

    for p in &preparing_before {
        assert_eq!(p.total_bytes, file_size);
        assert_eq!(&p.item_id, expected_item_id);
        assert_eq!(&p.rel_path, expected_rel_path);
    }

    let last_preparing = preparing_before.last().expect("last preparing payload");
    assert_eq!(last_preparing.bytes_transferred, file_size);
}

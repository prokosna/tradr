//! Browse write plane integration tests over QUIC loopback (WI-M8-059b).

use std::net::SocketAddr;
use std::sync::Arc;

use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::handshake::{HandshakeParams, perform_handshake};
use tradr_app::listener::{ListenerParams, handle_incoming_channel};
use tradr_app::peer_trust::OwnAttestation;
use tradr_core::{
    Ack, BrowseCodec, BrowseMessage, Candidate, Capabilities, Clock, ContentHash, Delete,
    DomainTag, KeyBinding, KeyStore, ListDir, Mkdir, PeerExpectation, ReadFile, RecvStream,
    RefusalReason, Refused, RelPath, Rename, RootId, SecureChannel, SendStream, ShareId, Transport,
    TransportId, TrustTier, UnixTime, VersionRange, WriteFile, WriteMode,
};
use tradr_identity::{OsRng, SoftwareKeyStore, SystemClock};
use tradr_integrity::BaoVerifier;
use tradr_proto::browse::ProtoBrowseCodec;
use tradr_secrets::FileStore;
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

const TEST_SHARE_ID: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn setup_key_store(dir: &std::path::Path) -> Arc<SoftwareKeyStore> {
    let rung = FileStore::new(dir.join("keys"));
    let store = SoftwareKeyStore::open(&rung, "device-key", &OsRng).expect("open key store");
    Arc::new(store)
}

struct FixedAttestation(String);

impl OwnAttestation for FixedAttestation {
    fn id_token(&self) -> Option<String> {
        Some(self.0.clone())
    }
}

struct TestContext {
    server_dir: tempfile::TempDir,
    channel: Arc<dyn SecureChannel>,
    codec: ProtoBrowseCodec,
    share_id: ShareId,
    max_frame_size: u32,
    _control_send: Box<dyn SendStream>,
    _control_recv: Box<dyn RecvStream>,
    _server_task: tokio::task::JoinHandle<()>,
}

async fn setup_harness() -> TestContext {
    let server_dir = tempfile::tempdir().expect("server tempdir");
    let client_dir = tempfile::tempdir().expect("client tempdir");

    let server_store = setup_key_store(server_dir.path());
    let client_store = setup_key_store(client_dir.path());

    let server_id = server_store.public_identity().expect("server id");
    let client_id = client_store.public_identity().expect("client id");

    let server_vfs = Arc::new(NativeVfs::new());
    let root_server = RootId::new(10);
    server_vfs
        .register_root(root_server, server_dir.path().to_path_buf(), false)
        .expect("register server root");

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let server_transport =
        QuicTransport::new(server_store.clone(), bind_addr).expect("server transport");
    let rx_addr = server_transport.local_addr().expect("server local addr");

    let client_transport =
        QuicTransport::new(client_store.clone(), bind_addr).expect("client transport");

    let mut incoming = server_transport.listen().await.expect("server listen");

    let rx_identity = server_id.clone();
    let rx_store_clone = server_store.clone();
    let rx_vfs_clone = server_vfs.clone();

    let access = Arc::new(BrowseAccess::new());
    access.record(client_id.device_id(), true);

    let server_task = tokio::spawn(async move {
        let channel = incoming.accept().await.expect("accept channel");
        let clock = SystemClock;
        let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
        let keybind_sig = rx_store_clone
            .sign(DomainTag::KeyBind, rx_identity.agreement_pub().as_bytes())
            .expect("sign");
        let our_key_binding =
            KeyBinding::new(rx_identity.agreement_pub().clone(), keybind_sig, not_after);

        let params = ListenerParams {
            root: root_server,
            our_identity: &rx_identity,
            our_attestation_token: Arc::new(FixedAttestation(String::new())),
            our_key_binding,
            our_versions: VersionRange::new(1, 1).expect("version range"),
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: access,
        };

        let _res = handle_incoming_channel(
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
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = client_transport
        .connect(&candidate, &PeerExpectation::Device(server_id.device_id()))
        .await
        .expect("connect");

    let (mut control_send, mut control_recv) = channel.open_bi().await.expect("open control");
    let clock = SystemClock;
    let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
    let keybind_sig = client_store
        .sign(DomainTag::KeyBind, client_id.agreement_pub().as_bytes())
        .expect("sign");
    let our_key_binding =
        KeyBinding::new(client_id.agreement_pub().clone(), keybind_sig, not_after);

    let handshake_params = HandshakeParams {
        authenticated_peer: channel.peer(),
        our_channel_max_frame_size: channel.max_frame_size(),
        our_identity: &client_id,
        our_attestation_token: String::new(),
        our_key_binding,
        our_versions: VersionRange::new(1, 1).expect("version range"),
        our_capabilities: Capabilities::DIRECT_QUIC,
    };

    let session = perform_handshake(
        control_send.as_mut(),
        control_recv.as_mut(),
        handshake_params,
        client_store.as_ref(),
        &OsRng,
        &SystemClock,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("handshake");

    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());
    let codec = ProtoBrowseCodec::new(negotiated_frame_bound);
    let share_id: ShareId = TEST_SHARE_ID.parse().expect("share id");

    TestContext {
        server_dir,
        channel: channel.into(),
        codec,
        share_id,
        max_frame_size: negotiated_frame_bound,
        _control_send: control_send,
        _control_recv: control_recv,
        _server_task: server_task,
    }
}

async fn read_exact(recv: &mut dyn RecvStream, mut buf: &mut [u8]) -> Result<(), String> {
    while !buf.is_empty() {
        let n = recv
            .read(buf)
            .await
            .map_err(|e| format!("transport error: {e}"))?;
        if n == 0 {
            return Err("stream closed unexpectedly".to_string());
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

async fn read_ack(
    recv: &mut dyn RecvStream,
    codec: &ProtoBrowseCodec,
    max_frame_size: u32,
) -> Result<Ack, String> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    if announced == 0 {
        return Err("empty frame announced".to_string());
    }
    if announced > max_frame_size {
        return Err(format!("frame oversized: {announced} > {max_frame_size}"));
    }

    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    read_exact(recv, &mut raw[4..]).await?;

    match codec.decode_frame(&raw, max_frame_size) {
        Ok(Some((BrowseMessage::Ack(ack), consumed))) if consumed == raw.len() => Ok(ack),
        Ok(Some((other, _))) => Err(format!("expected Ack, received: {other:?}")),
        Ok(None) => Err("incomplete frame decoded".to_string()),
        Err(e) => Err(format!("decode error: {e}")),
    }
}

async fn read_refused(
    recv: &mut dyn RecvStream,
    codec: &ProtoBrowseCodec,
    max_frame_size: u32,
) -> Result<Refused, String> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    if announced == 0 {
        return Err("empty frame announced".to_string());
    }
    if announced > max_frame_size {
        return Err(format!("frame oversized: {announced} > {max_frame_size}"));
    }

    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    read_exact(recv, &mut raw[4..]).await?;

    match codec.decode_frame(&raw, max_frame_size) {
        Ok(Some((BrowseMessage::Refused(refused), consumed))) if consumed == raw.len() => {
            Ok(refused)
        }
        Ok(Some((other, _))) => Err(format!("expected Refused, received: {other:?}")),
        Ok(None) => Err("incomplete frame decoded".to_string()),
        Err(e) => Err(format!("decode error: {e}")),
    }
}

#[tokio::test]
async fn upload_3mib_plus_17_bytes_create_new_succeeds() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let size = 3 * 1024 * 1024 + 17;
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        data.push(((i * 31 + 7) ^ (i >> 8)) as u8);
    }

    let write_msg = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("sub/new.bin").expect("relpath"),
        size: size as u64,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::CreateNew,
    });

    let frame = ctx
        .codec
        .encode_frame(&write_msg, ctx.max_frame_size)
        .expect("encode frame");
    browse_send.write_all(&frame).await.expect("send frame");
    browse_send.write_all(&data).await.expect("send data");

    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read ack");
    assert_eq!(ack.request_id, "");

    let dest = ctx.server_dir.path().join("sub").join("new.bin");
    assert!(dest.exists(), "target file must exist");
    let written = std::fs::read(&dest).expect("read dest");
    assert_eq!(written.len(), size);
    assert_eq!(written, data);

    let partial_root = ctx.server_dir.path().join(".tradr-partial");
    if partial_root.exists() {
        let entries: Vec<_> = std::fs::read_dir(&partial_root)
            .expect("read partial root")
            .collect();
        assert!(
            entries.is_empty(),
            "expected .tradr-partial to be empty, found: {entries:?}"
        );
    }
}

#[tokio::test]
async fn create_new_onto_existing_file_refused_and_unchanged() {
    let ctx = setup_harness().await;
    let existing_path = ctx.server_dir.path().join("existing.txt");
    std::fs::write(&existing_path, b"original content").expect("write existing");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let write_msg = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("existing.txt").expect("relpath"),
        size: 9,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::CreateNew,
    });

    let frame = ctx
        .codec
        .encode_frame(&write_msg, ctx.max_frame_size)
        .expect("encode frame");
    browse_send.write_all(&frame).await.expect("send frame");
    browse_send
        .write_all(b"new bytes")
        .await
        .expect("send data");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::AlreadyExists);

    let content = std::fs::read(&existing_path).expect("read existing");
    assert_eq!(content, b"original content");
}

#[tokio::test]
async fn overwrite_replaces_existing_file_entirely_including_shorter() {
    let ctx = setup_harness().await;
    let file_path = ctx.server_dir.path().join("replace_me.txt");
    std::fs::write(&file_path, vec![0xFF; 256]).expect("write existing");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let new_data = b"much shorter replacement content";
    let write_msg = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("replace_me.txt").expect("relpath"),
        size: new_data.len() as u64,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::Overwrite,
    });

    let frame = ctx
        .codec
        .encode_frame(&write_msg, ctx.max_frame_size)
        .expect("encode frame");
    browse_send.write_all(&frame).await.expect("send frame");
    browse_send.write_all(new_data).await.expect("send data");

    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read ack");
    assert_eq!(ack.request_id, "");

    let content = std::fs::read(&file_path).expect("read replaced file");
    assert_eq!(content, new_data);
}

#[tokio::test]
async fn rename_if_exists_lands_beside_with_collision_rule() {
    let ctx = setup_harness().await;
    let original_path = ctx.server_dir.path().join("doc.txt");
    std::fs::write(&original_path, b"initial content").expect("write original");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let second_data = b"second content version";
    let write_msg = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("doc.txt").expect("relpath"),
        size: second_data.len() as u64,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::RenameIfExists,
    });

    let frame = ctx
        .codec
        .encode_frame(&write_msg, ctx.max_frame_size)
        .expect("encode frame");
    browse_send.write_all(&frame).await.expect("send frame");
    browse_send.write_all(second_data).await.expect("send data");

    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read ack");
    assert_eq!(ack.request_id, "");

    assert_eq!(
        std::fs::read(&original_path).expect("read original"),
        b"initial content"
    );
    let collision_path = ctx.server_dir.path().join("doc (2).txt");
    assert!(
        collision_path.exists(),
        "expected doc (2).txt to exist alongside doc.txt"
    );
    assert_eq!(
        std::fs::read(&collision_path).expect("read collision"),
        second_data
    );
}

#[tokio::test]
async fn two_uploads_pipelined_arrive_intact() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let data1 = b"Pipelined file one payload bytes";
    let data2 = b"Pipelined file two has completely different payload bytes";

    let write1 = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("piped1.dat").expect("relpath"),
        size: data1.len() as u64,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::CreateNew,
    });
    let write2 = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("piped2.dat").expect("relpath"),
        size: data2.len() as u64,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::CreateNew,
    });

    let frame1 = ctx
        .codec
        .encode_frame(&write1, ctx.max_frame_size)
        .expect("encode 1");
    let frame2 = ctx
        .codec
        .encode_frame(&write2, ctx.max_frame_size)
        .expect("encode 2");

    let mut combined = Vec::new();
    combined.extend_from_slice(&frame1);
    combined.extend_from_slice(data1);
    combined.extend_from_slice(&frame2);
    combined.extend_from_slice(data2);

    browse_send
        .write_all(&combined)
        .await
        .expect("send pipelined");

    let ack1 = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read ack 1");
    assert_eq!(ack1.request_id, "");

    let ack2 = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read ack 2");
    assert_eq!(ack2.request_id, "");

    let file1 = ctx.server_dir.path().join("piped1.dat");
    let file2 = ctx.server_dir.path().join("piped2.dat");
    assert_eq!(std::fs::read(&file1).expect("read file 1"), data1);
    assert_eq!(std::fs::read(&file2).expect("read file 2"), data2);
}

#[tokio::test]
async fn upload_early_stream_finish_cleans_up() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let write_msg = BrowseMessage::WriteFile(WriteFile {
        share_id: ctx.share_id,
        path: RelPath::new("unfinished.bin").expect("relpath"),
        size: 4096,
        content_hash: ContentHash::from_bytes([0u8; 32]),
        mode: WriteMode::CreateNew,
    });

    let frame = ctx
        .codec
        .encode_frame(&write_msg, ctx.max_frame_size)
        .expect("encode frame");
    browse_send.write_all(&frame).await.expect("send frame");
    browse_send
        .write_all(&[0x77; 256])
        .await
        .expect("send partial");
    browse_send.finish().await.expect("finish early");

    let ack_res = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size).await;
    assert!(ack_res.is_err(), "early finish must end without Ack");

    let target = ctx.server_dir.path().join("unfinished.bin");
    assert!(!target.exists(), "target file must not have been created");

    let partial_root = ctx.server_dir.path().join(".tradr-partial");
    if partial_root.exists() {
        let entries: Vec<_> = std::fs::read_dir(&partial_root)
            .expect("read partial root")
            .collect();
        assert!(entries.is_empty(), "staging directory must be cleaned up");
    }
}

#[tokio::test]
async fn mkdir_with_and_without_parents() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    // 1. With parents when parents do not exist -> succeeds
    let msg_parents_ok = BrowseMessage::Mkdir(Mkdir {
        share_id: ctx.share_id,
        path: RelPath::new("parent/child/folder").expect("relpath"),
        parents: true,
    });
    let frame = ctx
        .codec
        .encode_frame(&msg_parents_ok, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for mkdir with parents");
    assert_eq!(ack.request_id, "");
    assert!(ctx.server_dir.path().join("parent/child/folder").is_dir());

    // 2. Without parents when parent already exists -> succeeds
    let msg_no_parents_ok = BrowseMessage::Mkdir(Mkdir {
        share_id: ctx.share_id,
        path: RelPath::new("parent/child/sibling").expect("relpath"),
        parents: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&msg_no_parents_ok, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for mkdir without parents");
    assert_eq!(ack.request_id, "");
    assert!(ctx.server_dir.path().join("parent/child/sibling").is_dir());

    // 3. Directory already exists -> succeeds (idempotent)
    let msg_already_dir = BrowseMessage::Mkdir(Mkdir {
        share_id: ctx.share_id,
        path: RelPath::new("parent/child/folder").expect("relpath"),
        parents: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&msg_already_dir, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for existing directory");
    assert_eq!(ack.request_id, "");
}

#[tokio::test]
async fn mkdir_without_parents_missing_parent_refused() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let msg_no_parents_fail = BrowseMessage::Mkdir(Mkdir {
        share_id: ctx.share_id,
        path: RelPath::new("parent/child/folder").expect("relpath"),
        parents: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&msg_no_parents_fail, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::NotFound);
}

#[tokio::test]
async fn mkdir_onto_existing_file_refused() {
    let ctx = setup_harness().await;
    let file_path = ctx.server_dir.path().join("a_file.txt");
    std::fs::write(&file_path, b"file content").expect("write file");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let msg_file_exists = BrowseMessage::Mkdir(Mkdir {
        share_id: ctx.share_id,
        path: RelPath::new("a_file.txt").expect("relpath"),
        parents: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&msg_file_exists, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::AlreadyExists);
}

#[tokio::test]
async fn delete_file_and_empty_directory_succeeds() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    // 1. Delete a regular file -> succeeds
    let file_path = ctx.server_dir.path().join("del_file.txt");
    std::fs::write(&file_path, b"delete me").expect("write file");
    let del_file = BrowseMessage::Delete(Delete {
        share_id: ctx.share_id,
        path: RelPath::new("del_file.txt").expect("relpath"),
        recursive: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&del_file, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for delete file");
    assert_eq!(ack.request_id, "");
    assert!(!file_path.exists());

    // 2. Delete an empty directory -> succeeds
    let empty_dir = ctx.server_dir.path().join("empty_dir");
    std::fs::create_dir(&empty_dir).expect("create empty dir");
    let del_empty = BrowseMessage::Delete(Delete {
        share_id: ctx.share_id,
        path: RelPath::new("empty_dir").expect("relpath"),
        recursive: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&del_empty, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for delete empty dir");
    assert_eq!(ack.request_id, "");
    assert!(!empty_dir.exists());
}

#[tokio::test]
async fn delete_non_empty_directory_without_recursive_refused() {
    let ctx = setup_harness().await;
    let tree_dir = ctx.server_dir.path().join("tree");
    std::fs::create_dir_all(tree_dir.join("nested")).expect("create tree");
    std::fs::write(tree_dir.join("nested").join("item.txt"), b"item").expect("write item");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let del_nonempty_no_rec = BrowseMessage::Delete(Delete {
        share_id: ctx.share_id,
        path: RelPath::new("tree").expect("relpath"),
        recursive: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&del_nonempty_no_rec, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::WrongKind);
    assert!(
        tree_dir.join("nested").join("item.txt").exists(),
        "tree content must be untouched"
    );
}

#[tokio::test]
async fn delete_non_empty_directory_with_recursive_succeeds() {
    let ctx = setup_harness().await;
    let tree_dir = ctx.server_dir.path().join("tree");
    std::fs::create_dir_all(tree_dir.join("nested")).expect("create tree");
    std::fs::write(tree_dir.join("nested").join("item.txt"), b"item").expect("write item");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let del_nonempty_rec = BrowseMessage::Delete(Delete {
        share_id: ctx.share_id,
        path: RelPath::new("tree").expect("relpath"),
        recursive: true,
    });
    let frame = ctx
        .codec
        .encode_frame(&del_nonempty_rec, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for recursive delete");
    assert_eq!(ack.request_id, "");
    assert!(!tree_dir.exists(), "entire tree must be removed");
}

#[tokio::test]
async fn rename_file_succeeds() {
    let ctx = setup_harness().await;
    let src_path = ctx.server_dir.path().join("source.txt");
    let dst_path = ctx.server_dir.path().join("dest.txt");
    std::fs::write(&src_path, b"rename test data").expect("write source");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let rename_ok = BrowseMessage::Rename(Rename {
        share_id: ctx.share_id,
        from: RelPath::new("source.txt").expect("relpath"),
        to: RelPath::new("dest.txt").expect("relpath"),
    });
    let frame = ctx
        .codec
        .encode_frame(&rename_ok, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let ack = read_ack(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("ack for rename");
    assert_eq!(ack.request_id, "");
    assert!(!src_path.exists());
    assert_eq!(
        std::fs::read(&dst_path).expect("read dest"),
        b"rename test data"
    );
}

#[tokio::test]
async fn rename_onto_existing_target_refused() {
    let ctx = setup_harness().await;
    let src_path = ctx.server_dir.path().join("source.txt");
    let existing_path = ctx.server_dir.path().join("occupied.txt");
    std::fs::write(&src_path, b"source content").expect("write source");
    std::fs::write(&existing_path, b"already here").expect("write occupied");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let rename_occupied = BrowseMessage::Rename(Rename {
        share_id: ctx.share_id,
        from: RelPath::new("source.txt").expect("relpath"),
        to: RelPath::new("occupied.txt").expect("relpath"),
    });
    let frame = ctx
        .codec
        .encode_frame(&rename_occupied, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::AlreadyExists);
    assert_eq!(
        std::fs::read(&existing_path).expect("read occupied"),
        b"already here"
    );
    assert_eq!(
        std::fs::read(&src_path).expect("read source"),
        b"source content"
    );
}

#[tokio::test]
async fn rename_onto_target_created_after_request_sent_refused() {
    let ctx = setup_harness().await;
    let src_path = ctx.server_dir.path().join("source.txt");
    let dest_path = ctx.server_dir.path().join("occupied_later.txt");
    std::fs::write(&src_path, b"source content").expect("write source");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let rename_msg = BrowseMessage::Rename(Rename {
        share_id: ctx.share_id,
        from: RelPath::new("source.txt").expect("relpath"),
        to: RelPath::new("occupied_later.txt").expect("relpath"),
    });
    let frame = ctx
        .codec
        .encode_frame(&rename_msg, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    std::fs::write(&dest_path, b"created after request sent").expect("write dest");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::AlreadyExists);
    assert_eq!(
        std::fs::read(&dest_path).expect("read occupied later"),
        b"created after request sent"
    );
    assert_eq!(
        std::fs::read(&src_path).expect("read source"),
        b"source content"
    );
}

#[tokio::test]
async fn rename_into_self_refused() {
    let ctx = setup_harness().await;
    let folder_path = ctx.server_dir.path().join("folder");
    std::fs::create_dir(&folder_path).expect("create folder");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let rename_inside_self = BrowseMessage::Rename(Rename {
        share_id: ctx.share_id,
        from: RelPath::new("folder").expect("relpath"),
        to: RelPath::new("folder/nested").expect("relpath"),
    });
    let frame = ctx
        .codec
        .encode_frame(&rename_inside_self, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");
    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::NotAllowed);
}

#[tokio::test]
async fn rename_directory_into_itself_refused_and_content_unchanged() {
    let ctx = setup_harness().await;
    let dir_a = ctx.server_dir.path().join("a");
    std::fs::create_dir(&dir_a).expect("create dir a");
    let file_in_a = dir_a.join("file.txt");
    std::fs::write(&file_in_a, b"content inside a").expect("write file in a");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let rename_msg = BrowseMessage::Rename(Rename {
        share_id: ctx.share_id,
        from: RelPath::new("a").expect("relpath"),
        to: RelPath::new("a/b").expect("relpath"),
    });
    let frame = ctx
        .codec
        .encode_frame(&rename_msg, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::NotAllowed);

    assert!(dir_a.is_dir(), "directory a must still exist");
    assert_eq!(
        std::fs::read(&file_in_a).expect("read file in a"),
        b"content inside a",
        "content inside a must be unchanged"
    );
    assert!(
        !dir_a.join("b").exists(),
        "nested target a/b must not exist"
    );
}

#[tokio::test]
async fn list_dir_missing_path_refused_not_found() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let list_msg = BrowseMessage::ListDir(ListDir {
        share_id: ctx.share_id,
        path: RelPath::new("missing_folder").expect("relpath"),
        cursor: String::new(),
        limit: 100,
        with_hash: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&list_msg, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::NotFound);

    let mut end_buf = [0u8; 1];
    let n = browse_recv
        .read(&mut end_buf)
        .await
        .expect("read at stream end");
    assert_eq!(n, 0, "stream must be finished after refusal");
}

#[tokio::test]
async fn read_file_of_directory_refused_wrong_kind() {
    let ctx = setup_harness().await;
    let dir_path = ctx.server_dir.path().join("a_directory");
    std::fs::create_dir(&dir_path).expect("create dir");

    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let read_msg = BrowseMessage::ReadFile(ReadFile {
        share_id: ctx.share_id,
        path: RelPath::new("a_directory").expect("relpath"),
        offset: 0,
        length: 100,
    });
    let frame = ctx
        .codec
        .encode_frame(&read_msg, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::WrongKind);

    let mut end_buf = [0u8; 1];
    let n = browse_recv
        .read(&mut end_buf)
        .await
        .expect("read at stream end");
    assert_eq!(n, 0, "stream must be finished after refusal");
}

#[tokio::test]
async fn delete_missing_path_refused_not_found() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let del_msg = BrowseMessage::Delete(Delete {
        share_id: ctx.share_id,
        path: RelPath::new("does_not_exist.txt").expect("relpath"),
        recursive: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&del_msg, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::NotFound);

    let mut end_buf = [0u8; 1];
    let n = browse_recv
        .read(&mut end_buf)
        .await
        .expect("read at stream end");
    assert_eq!(n, 0, "stream must be finished after refusal");
}

#[tokio::test]
async fn after_refused_reading_browse_stream_reaches_end() {
    let ctx = setup_harness().await;
    let (mut browse_send, mut browse_recv) = ctx.channel.open_bi().await.expect("open browse");

    let del_msg = BrowseMessage::Delete(Delete {
        share_id: ctx.share_id,
        path: RelPath::new("non_existent").expect("relpath"),
        recursive: false,
    });
    let frame = ctx
        .codec
        .encode_frame(&del_msg, ctx.max_frame_size)
        .expect("encode");
    browse_send.write_all(&frame).await.expect("send");

    let refused = read_refused(browse_recv.as_mut(), &ctx.codec, ctx.max_frame_size)
        .await
        .expect("read refused");
    assert_eq!(refused.reason, RefusalReason::NotFound);

    let mut end_buf = [0u8; 16];
    let n = browse_recv
        .read(&mut end_buf)
        .await
        .expect("read after refusal");
    assert_eq!(
        n, 0,
        "reading browse stream after refusal must reach 0 bytes"
    );
}

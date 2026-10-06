//! Browse client write operations integration tests over QUIC loopback (WI-M8-060a).

use std::net::SocketAddr;
use std::sync::Arc;

use tradr_app::browse::{
    BrowseAuth, execute_delete_entry, execute_download_file, execute_list_peer_directory,
    execute_make_directory, execute_rename_entry, execute_upload_items,
};
use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::listener::{ListenerParams, handle_incoming_channel};
use tradr_app::peer_trust::OwnAttestation;
use tradr_app::send::resolve_send_items;
use tradr_core::{
    Candidate, Capabilities, Clock, DomainTag, KeyBinding, KeyStore, PeerExpectation,
    PublicIdentity, RelPath, RootId, SecureChannel, ShareId, Transport, TransportId, TrustTier,
    UnixTime, VersionRange,
};
use tradr_identity::{OsRng, SoftwareKeyStore, SystemClock};
use tradr_integrity::BaoVerifier;
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

struct TestHarness {
    server_dir: tempfile::TempDir,
    client_dir: tempfile::TempDir,
    client_vfs: Arc<NativeVfs>,
    root_client: RootId,
    client_store: Arc<SoftwareKeyStore>,
    client_id: PublicIdentity,
    client_transport: Arc<QuicTransport>,
    server_id: PublicIdentity,
    rx_addr: SocketAddr,
    share_id: ShareId,
    _server_task: tokio::task::JoinHandle<()>,
}

impl TestHarness {
    async fn connect(&self) -> Box<dyn SecureChannel> {
        let candidate = Candidate::new(TransportId::new("direct-quic"), &self.rx_addr.to_string())
            .expect("valid candidate");
        self.client_transport
            .connect(
                &candidate,
                &PeerExpectation::Device(self.server_id.device_id()),
            )
            .await
            .expect("connect")
    }

    fn auth(&self) -> BrowseAuth<'_> {
        BrowseAuth {
            identity: &self.client_id,
            key_store: self.client_store.as_ref(),
            attestation_token: String::new(),
            capabilities: Capabilities::DIRECT_QUIC,
            known_devices: None,
        }
    }
}

async fn setup_harness(allow_client: bool) -> TestHarness {
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

    let client_vfs = Arc::new(NativeVfs::new());
    let root_client = RootId::new(20);
    client_vfs
        .register_root(root_client, client_dir.path().to_path_buf(), false)
        .expect("register client root");

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let server_transport =
        QuicTransport::new(server_store.clone(), bind_addr).expect("server transport");
    let rx_addr = server_transport.local_addr().expect("server local addr");

    let client_transport =
        QuicTransport::new(client_store.clone(), bind_addr).expect("client transport");

    let mut incoming = server_transport.listen().await.expect("server listen");

    let access = Arc::new(BrowseAccess::new());
    if allow_client {
        access.record(client_id.device_id(), true);
    }

    let server_id_clone = server_id.clone();
    let server_store_clone = server_store.clone();
    let server_vfs_clone = server_vfs.clone();
    let access_clone = access.clone();

    let server_task = tokio::spawn(async move {
        while let Ok(channel) = incoming.accept().await {
            let rx_identity = server_id_clone.clone();
            let rx_store = server_store_clone.clone();
            let rx_vfs = server_vfs_clone.clone();
            let rx_access = access_clone.clone();

            tokio::spawn(async move {
                let clock = SystemClock;
                let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
                let keybind_sig = rx_store
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
                    browse_access: rx_access,
                    known_devices: None,
                };

                let res = handle_incoming_channel(
                    channel.as_ref(),
                    rx_vfs.as_ref(),
                    params,
                    rx_store.as_ref(),
                    &OsRng,
                    &SystemClock,
                    &BaoVerifier,
                    |_| async { Ok(TrustTier::SameAccount) },
                    None,
                    None,
                )
                .await;
                if let Err(e) = res {
                    eprintln!("handle_incoming_channel exited with error: {e}");
                }
                if let Ok((mut s, _r)) = channel.accept_bi().await
                    && let Err(e) = s.finish().await
                {
                    eprintln!("closing extra stream failed: {e}");
                }
            });
        }
    });

    let share_id: ShareId = TEST_SHARE_ID.parse().expect("share id");

    TestHarness {
        server_dir,
        client_dir,
        client_vfs,
        root_client,
        client_store,
        client_id,
        client_transport: Arc::new(client_transport),
        server_id,
        rx_addr,
        share_id,
        _server_task: server_task,
    }
}

#[tokio::test]
async fn upload_two_files_and_collision_succeeds() {
    let harness = setup_harness(true).await;

    let file1_content = b"Small payload bytes for file one";
    let file1_path = harness.client_dir.path().join("file1.bin");
    std::fs::write(&file1_path, file1_content).expect("write file1");

    let size2 = 3 * 1024 * 1024 + 17;
    let mut file2_content = Vec::with_capacity(size2);
    for i in 0..size2 {
        file2_content.push(((i * 31 + 7) ^ (i >> 8)) as u8);
    }
    let file2_path = harness.client_dir.path().join("file2.bin");
    std::fs::write(&file2_path, &file2_content).expect("write file2");

    let items = resolve_send_items(
        harness.client_vfs.as_ref(),
        harness.root_client,
        &["file1.bin".to_string(), "file2.bin".to_string()],
    )
    .await
    .expect("resolve send items");

    let channel = harness.connect().await;
    let auth = harness.auth();
    let uploaded = execute_upload_items(
        channel.as_ref(),
        harness.share_id,
        RelPath::new("inbox").expect("inbox relpath"),
        &items,
        harness.client_vfs.as_ref(),
        &auth,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("upload items");

    assert_eq!(uploaded, vec!["file1.bin", "file2.bin"]);

    let server_file1 = harness.server_dir.path().join("inbox").join("file1.bin");
    let server_file2 = harness.server_dir.path().join("inbox").join("file2.bin");
    assert_eq!(
        std::fs::read(&server_file1).expect("read server file1"),
        file1_content
    );
    assert_eq!(
        std::fs::read(&server_file2).expect("read server file2"),
        file2_content
    );

    let items_collision = resolve_send_items(
        harness.client_vfs.as_ref(),
        harness.root_client,
        &["file1.bin".to_string()],
    )
    .await
    .expect("resolve collision send item");

    let channel2 = harness.connect().await;
    let auth2 = harness.auth();
    let uploaded2 = execute_upload_items(
        channel2.as_ref(),
        harness.share_id,
        RelPath::new("inbox").expect("inbox relpath"),
        &items_collision,
        harness.client_vfs.as_ref(),
        &auth2,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("upload collision item");

    assert_eq!(uploaded2, vec!["file1.bin"]);

    let server_file1_collision = harness
        .server_dir
        .path()
        .join("inbox")
        .join("file1 (2).bin");
    assert!(
        server_file1_collision.exists(),
        "collision file must exist at inbox/file1 (2).bin"
    );
    assert_eq!(
        std::fs::read(&server_file1_collision).expect("read collision file"),
        file1_content
    );
    assert_eq!(
        std::fs::read(&server_file1).expect("read original server file1"),
        file1_content
    );
}

#[tokio::test]
async fn make_directory_rename_and_delete_take_effect() {
    let harness = setup_harness(true).await;

    let channel = harness.connect().await;
    let auth = harness.auth();
    execute_make_directory(
        channel.as_ref(),
        harness.share_id,
        RelPath::new("test_folder/nested").expect("relpath"),
        &auth,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("make directory");

    assert!(
        harness
            .server_dir
            .path()
            .join("test_folder")
            .join("nested")
            .is_dir()
    );

    let payload = b"nested file content";
    let file_path = harness
        .server_dir
        .path()
        .join("test_folder")
        .join("nested")
        .join("sample.txt");
    std::fs::write(&file_path, payload).expect("write sample");

    let channel2 = harness.connect().await;
    let auth2 = harness.auth();
    execute_rename_entry(
        channel2.as_ref(),
        harness.share_id,
        RelPath::new("test_folder/nested").expect("from relpath"),
        RelPath::new("test_folder/renamed").expect("to relpath"),
        &auth2,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("rename directory");

    assert!(
        !harness
            .server_dir
            .path()
            .join("test_folder")
            .join("nested")
            .exists()
    );
    let renamed_dir = harness
        .server_dir
        .path()
        .join("test_folder")
        .join("renamed");
    assert!(renamed_dir.is_dir());
    assert_eq!(
        std::fs::read(renamed_dir.join("sample.txt")).expect("read sample in renamed dir"),
        payload
    );

    let channel3 = harness.connect().await;
    let auth3 = harness.auth();
    execute_delete_entry(
        channel3.as_ref(),
        harness.share_id,
        RelPath::new("test_folder").expect("delete relpath"),
        true,
        &auth3,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("delete directory recursive");

    assert!(!harness.server_dir.path().join("test_folder").exists());
}

#[tokio::test]
async fn download_file_and_collision_succeeds() {
    let harness = setup_harness(true).await;

    let payload = b"content to download from server folder";
    let server_file = harness.server_dir.path().join("remote.txt");
    std::fs::write(&server_file, payload).expect("write remote file");

    let channel = harness.connect().await;
    let (bytes1, placed1) = execute_download_file(
        channel.as_ref(),
        harness.share_id,
        RelPath::new("remote.txt").expect("relpath"),
        harness.client_vfs.as_ref(),
        harness.root_client,
        RelPath::new("remote.txt").expect("dest relpath"),
        &harness.client_id,
        harness.client_store.as_ref(),
        String::new(),
        Capabilities::DIRECT_QUIC,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("first download");

    assert_eq!(bytes1, payload.len() as u64);
    assert_eq!(
        placed1,
        RelPath::new("remote.txt").expect("remote.txt relpath")
    );
    let client_file1 = harness.client_dir.path().join("remote.txt");
    assert_eq!(
        std::fs::read(&client_file1).expect("read client file1"),
        payload
    );

    let channel2 = harness.connect().await;
    let (bytes2, placed2) = execute_download_file(
        channel2.as_ref(),
        harness.share_id,
        RelPath::new("remote.txt").expect("relpath"),
        harness.client_vfs.as_ref(),
        harness.root_client,
        RelPath::new("remote.txt").expect("dest relpath"),
        &harness.client_id,
        harness.client_store.as_ref(),
        String::new(),
        Capabilities::DIRECT_QUIC,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("second download");

    assert_eq!(bytes2, payload.len() as u64);
    assert_eq!(
        placed2,
        RelPath::new("remote (2).txt").expect("remote (2).txt relpath")
    );
    let client_file2 = harness.client_dir.path().join("remote (2).txt");
    assert_eq!(
        std::fs::read(&client_file2).expect("read client file2"),
        payload
    );
    assert_eq!(
        std::fs::read(&client_file1).expect("read client file1 untouched"),
        payload
    );
}

#[tokio::test]
async fn unauthorized_client_upload_and_mkdir_fail_with_no_access() {
    let harness = setup_harness(false).await;

    let file_content = b"unauthorized upload attempt payload";
    let file_path = harness.client_dir.path().join("blocked.bin");
    std::fs::write(&file_path, file_content).expect("write blocked file");

    let items = resolve_send_items(
        harness.client_vfs.as_ref(),
        harness.root_client,
        &["blocked.bin".to_string()],
    )
    .await
    .expect("resolve send items");

    let channel = harness.connect().await;
    let auth = harness.auth();
    let upload_err = execute_upload_items(
        channel.as_ref(),
        harness.share_id,
        RelPath::root(),
        &items,
        harness.client_vfs.as_ref(),
        &auth,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect_err("upload must be refused");

    assert!(
        upload_err.contains("no access"),
        "upload error must contain 'no access', got: {upload_err}"
    );
    assert!(
        !harness.server_dir.path().join("blocked.bin").exists(),
        "nothing must appear on the serving side after refused upload"
    );

    let channel2 = harness.connect().await;
    let auth2 = harness.auth();
    let mkdir_err = execute_make_directory(
        channel2.as_ref(),
        harness.share_id,
        RelPath::new("forbidden_dir").expect("forbidden_dir relpath"),
        &auth2,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect_err("make directory must be refused");

    assert!(
        mkdir_err.contains("no access"),
        "mkdir error must contain 'no access', got: {mkdir_err}"
    );
    assert!(
        !harness.server_dir.path().join("forbidden_dir").exists(),
        "nothing must appear on the serving side after refused mkdir"
    );

    let size_large = 3 * 1024 * 1024 + 17;
    let mut large_content = Vec::with_capacity(size_large);
    for i in 0..size_large {
        large_content.push(((i * 31 + 7) ^ (i >> 8)) as u8);
    }
    let large_file_path = harness.client_dir.path().join("large_blocked.bin");
    std::fs::write(&large_file_path, &large_content).expect("write large blocked file");

    let large_items = resolve_send_items(
        harness.client_vfs.as_ref(),
        harness.root_client,
        &["large_blocked.bin".to_string()],
    )
    .await
    .expect("resolve large send items");

    let channel3 = harness.connect().await;
    let auth3 = harness.auth();
    let large_upload_err = execute_upload_items(
        channel3.as_ref(),
        harness.share_id,
        RelPath::root(),
        &large_items,
        harness.client_vfs.as_ref(),
        &auth3,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect_err("large upload must be refused");

    assert!(
        large_upload_err.contains("no access"),
        "large upload error must contain 'no access', got: {large_upload_err}"
    );
    assert!(
        !harness.server_dir.path().join("large_blocked.bin").exists(),
        "nothing must appear on the serving side after refused large upload"
    );
}

#[tokio::test]
async fn renaming_onto_existing_name_fails_with_already_taken() {
    let harness = setup_harness(true).await;

    let orig_payload = b"content of original file";
    let existing_payload = b"content of already existing target file";
    let orig_path = harness.server_dir.path().join("orig.txt");
    let existing_path = harness.server_dir.path().join("existing.txt");
    std::fs::write(&orig_path, orig_payload).expect("write orig");
    std::fs::write(&existing_path, existing_payload).expect("write existing");

    let channel = harness.connect().await;
    let auth = harness.auth();
    let err = execute_rename_entry(
        channel.as_ref(),
        harness.share_id,
        RelPath::new("orig.txt").expect("from relpath"),
        RelPath::new("existing.txt").expect("to relpath"),
        &auth,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect_err("rename onto existing name must fail");

    assert!(
        err.contains("already taken"),
        "rename error must contain 'already taken', got: {err}"
    );
    assert_eq!(
        std::fs::read(&orig_path).expect("read orig"),
        orig_payload,
        "original file must remain unchanged on server"
    );
    assert_eq!(
        std::fs::read(&existing_path).expect("read existing"),
        existing_payload,
        "existing file must remain unchanged on server"
    );
}

#[tokio::test]
async fn deleting_nonexistent_path_fails_with_does_not_exist() {
    let harness = setup_harness(true).await;

    let channel = harness.connect().await;
    let auth = harness.auth();
    let err = execute_delete_entry(
        channel.as_ref(),
        harness.share_id,
        RelPath::new("nonexistent.txt").expect("nonexistent relpath"),
        false,
        &auth,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect_err("delete nonexistent path must fail");

    assert!(
        err.contains("does not exist"),
        "delete error must contain 'does not exist', got: {err}"
    );
}

#[tokio::test]
async fn listing_nonexistent_directory_fails_with_does_not_exist() {
    let harness = setup_harness(true).await;

    let channel = harness.connect().await;
    let auth = harness.auth();
    let err = execute_list_peer_directory(
        channel.as_ref(),
        harness.share_id,
        RelPath::new("missing_dir").expect("missing_dir relpath"),
        String::new(),
        500,
        auth.identity,
        auth.key_store,
        auth.attestation_token,
        auth.capabilities,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect_err("list nonexistent directory must fail");

    assert!(
        err.contains("does not exist"),
        "list error must contain 'does not exist', got: {err}"
    );
}

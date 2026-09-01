//! Integration tests for the Browse plane listing (WI-M3-002).
//! Verifies `execute_list_peer_directory` interacting with `handle_incoming_channel` over QUIC loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use tauri_plugin_tradr::commands::{execute_download_file, execute_list_peer_directory};
use tauri_plugin_tradr::listener::{ListenerParams, handle_incoming_channel};
use tauri_plugin_tradr::peer_trust::OwnAttestation;
use tradr_core::{
    Candidate, Capabilities, Clock, DomainTag, KeyBinding, KeyStore, PeerExpectation, RelPath,
    RootId, ShareId, Transport, TransportId, TrustTier, UnixTime, VersionRange,
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
async fn list_peer_directory_succeeds_over_quic_loopback() {
    let server_dir = tempfile::tempdir().expect("server tempdir");
    let client_dir = tempfile::tempdir().expect("client tempdir");

    let server_store = setup_key_store(server_dir.path());
    let client_store = setup_key_store(client_dir.path());

    let server_id = server_store.public_identity().expect("server id");
    let client_id = client_store.public_identity().expect("client id");

    std::fs::write(server_dir.path().join("alpha.txt"), b"Alpha content").expect("write alpha");
    std::fs::write(server_dir.path().join("beta.md"), b"# Beta").expect("write beta");
    std::fs::create_dir_all(server_dir.path().join("photos")).expect("create photos dir");
    std::fs::write(
        server_dir.path().join("photos").join("photo1.jpg"),
        b"JPEG data",
    )
    .expect("write photo1");

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

    let server_handle = tokio::spawn(async move {
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
            our_capabilities: Capabilities::DIRECT_QUIC,
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
        )
        .await;
        (res, channel)
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = client_transport
        .connect(&candidate, &PeerExpectation::Device(server_id.device_id()))
        .await
        .expect("connect");

    let share_id: ShareId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("share_id");
    let root_path = RelPath::root();

    let (list_result, server_outcome) = tokio::join!(
        execute_list_peer_directory(
            channel.as_ref(),
            share_id,
            root_path,
            String::new(),
            500,
            &client_id,
            client_store.as_ref(),
            String::new(),
            |_| async { Ok(TrustTier::SameAccount) },
        ),
        server_handle,
    );

    let listing = list_result.expect("execute_list_peer_directory");
    let (server_res, _server_chan) = server_outcome.expect("server join");
    server_res.expect("server handle channel");

    let names: Vec<String> = listing.entries.iter().map(|e| e.name.clone()).collect();
    assert!(names.contains(&"alpha.txt".to_string()));
    assert!(names.contains(&"beta.md".to_string()));
    assert!(names.contains(&"photos".to_string()));

    let photos_entry = listing.entries.iter().find(|e| e.name == "photos").unwrap();
    assert_eq!(photos_entry.kind, "directory");
}

#[tokio::test]
async fn list_peer_nested_directory_succeeds() {
    let server_dir = tempfile::tempdir().expect("server tempdir");
    let client_dir = tempfile::tempdir().expect("client tempdir");

    let server_store = setup_key_store(server_dir.path());
    let client_store = setup_key_store(client_dir.path());

    let server_id = server_store.public_identity().expect("server id");
    let client_id = client_store.public_identity().expect("client id");

    std::fs::create_dir_all(server_dir.path().join("docs").join("nested")).expect("create dirs");
    std::fs::write(
        server_dir
            .path()
            .join("docs")
            .join("nested")
            .join("report.pdf"),
        b"PDF content",
    )
    .expect("write report");

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

    let server_handle = tokio::spawn(async move {
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
            our_capabilities: Capabilities::DIRECT_QUIC,
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
        )
        .await;
        (res, channel)
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = client_transport
        .connect(&candidate, &PeerExpectation::Device(server_id.device_id()))
        .await
        .expect("connect");

    let share_id: ShareId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("share_id");
    let nested_path = RelPath::new("docs/nested").expect("nested relpath");

    let (list_result, server_outcome) = tokio::join!(
        execute_list_peer_directory(
            channel.as_ref(),
            share_id,
            nested_path,
            String::new(),
            500,
            &client_id,
            client_store.as_ref(),
            String::new(),
            |_| async { Ok(TrustTier::SameAccount) },
        ),
        server_handle,
    );

    let listing = list_result.expect("execute_list_peer_directory");
    let (server_res, _server_chan) = server_outcome.expect("server join");
    server_res.expect("server handle channel");

    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].name, "report.pdf");
    assert_eq!(listing.entries[0].kind, "file");
    assert_eq!(listing.entries[0].size_bytes, 11);
}

#[tokio::test]
async fn download_file_succeeds_over_quic_loopback() {
    let server_dir = tempfile::tempdir().expect("server tempdir");
    let client_dir = tempfile::tempdir().expect("client tempdir");

    let server_store = setup_key_store(server_dir.path());
    let client_store = setup_key_store(client_dir.path());

    let server_id = server_store.public_identity().expect("server id");
    let client_id = client_store.public_identity().expect("client id");

    let test_content = b"Downloadable test content across browse plane!";
    std::fs::create_dir_all(server_dir.path().join("sub")).expect("create sub dir");
    std::fs::write(server_dir.path().join("sub").join("data.bin"), test_content)
        .expect("write test content");

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

    let server_handle = tokio::spawn(async move {
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
            our_capabilities: Capabilities::DIRECT_QUIC,
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
        )
        .await;
        (res, channel)
    });

    let candidate = Candidate::new(TransportId::new("direct-quic"), &rx_addr.to_string())
        .expect("valid candidate");
    let channel = client_transport
        .connect(&candidate, &PeerExpectation::Device(server_id.device_id()))
        .await
        .expect("connect");

    let share_id: ShareId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("share_id");
    let file_path = RelPath::new("sub/data.bin").expect("relpath");
    let dest_file_path = client_dir.path().join("downloads").join("data.bin");

    let (download_result, server_outcome) = tokio::join!(
        execute_download_file(
            channel.as_ref(),
            share_id,
            file_path,
            &dest_file_path,
            &client_id,
            client_store.as_ref(),
            String::new(),
            |_| async { Ok(TrustTier::SameAccount) },
        ),
        server_handle,
    );

    let bytes_written = download_result.expect("execute_download_file");
    let (server_res, _server_chan) = server_outcome.expect("server join");
    server_res.expect("server handle channel");

    assert_eq!(bytes_written, test_content.len() as u64);
    let downloaded_data = std::fs::read(&dest_file_path).expect("read downloaded file");
    assert_eq!(downloaded_data, test_content);
}

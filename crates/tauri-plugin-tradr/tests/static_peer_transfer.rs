//! WI-M5-003: a transfer reached through a Static Peer entry rather than
//! mDNS. The entry names the listener's own bound port, never a fixed
//! one (rule E3); the first connection dials under `Unpinned`, since the
//! entry starts out empty; and the registry holds the authenticated
//! `DeviceId` once the transfer completes (docs/03, "The pin").

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tauri_plugin_tradr::commands::{connect_and_pin, execute_send_files, resolve_peer};
use tauri_plugin_tradr::listener::{ListenerParams, handle_incoming_channel};
use tauri_plugin_tradr::peer_trust::OwnAttestation;
use tradr_core::{
    Capabilities, Clock, DeviceId, DiscoverySource, DomainTag, KeyBinding, KeyStore,
    PeerExpectation, PeerList, RootId, Transport, TrustTier, UnixTime, VersionRange,
};
use tradr_discovery::{STATIC_PEER_SOURCE_ID, StaticPeerRegistry};
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
async fn transfer_through_a_static_peer_pins_the_device_on_first_connection() {
    // One timeout around the whole body turns a hang into a failure
    // rather than a wait on wall-clock time (rule E3).
    tokio::time::timeout(Duration::from_secs(30), run_test())
        .await
        .expect("test did not hang");
}

async fn run_test() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let registry_dir = tempfile::tempdir().expect("registry tempdir");

    let sender_store = setup_key_store(sender_dir.path());
    let receiver_store = setup_key_store(receiver_dir.path());
    let sender_id = sender_store.public_identity().expect("sender id");
    let receiver_id = receiver_store.public_identity().expect("receiver id");

    let file_content = b"content carried over a static peer entry".to_vec();
    std::fs::write(sender_dir.path().join("file1.txt"), &file_content).expect("write file1");

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

    // The listener is constructed, and its port read back, before
    // anything dials it -- never a fixed port (rule E3).
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
            None,
        )
        .await;
        (res, channel)
    });

    // The registry starts empty; the entry names the listener's real
    // address, exactly what a user would type for an overlay network.
    let registry_path = registry_dir.path().join("static-peers.json");
    let (mut registry, mut source) =
        StaticPeerRegistry::load(&registry_path).expect("load empty registry");
    let static_id = registry
        .add(Some("test peer"), &[rx_addr.to_string()], &OsRng)
        .expect("add static peer entry");
    assert!(
        registry
            .entry(&static_id)
            .expect("entry present")
            .expect_device_id()
            .is_none(),
        "a freshly added entry pins nothing yet"
    );

    let mut list = PeerList::new();
    let event = source.next_event().await.expect("initial observed event");
    list.apply(STATIC_PEER_SOURCE_ID, event)
        .expect("apply static peer observation");

    // What `get_peers` would hand the frontend as `PeerInfo::key` for an
    // entry nothing has identified yet.
    let peer_id = list
        .peers()
        .into_iter()
        .find(|peer| peer.device_id().is_none())
        .expect("the static peer is present and unidentified")
        .observations()
        .first()
        .expect("one observation")
        .id()
        .to_string();

    let resolved = resolve_peer(&peer_id, &list, &registry).expect("resolve static peer");
    assert_eq!(resolved.expectation, PeerExpectation::Unpinned);

    let registry_mutex = tokio::sync::Mutex::new(registry);
    let channel = connect_and_pin(&sender_transport, &registry_mutex, resolved)
        .await
        .expect("connect and pin");

    let files_to_send = vec!["file1.txt".to_string()];
    let (sent_result, rx_outcome) = tokio::join!(
        execute_send_files(
            channel.as_ref(),
            &sender_vfs,
            root_sender,
            &files_to_send,
            &sender_id,
            sender_store.as_ref(),
            String::new(),
            |_| async { Ok(TrustTier::SameAccount) },
        ),
        rx_handle,
    );

    let sent_result = sent_result.expect("execute_send_files");
    assert_eq!(sent_result, vec!["file1.txt"]);

    let (rx_result, _rx_channel) = rx_outcome.expect("rx join");
    rx_result.expect("rx handle channel");

    let received = std::fs::read(receiver_dir.path().join("file1.txt")).expect("read rx file1");
    assert_eq!(received, file_content);

    let registry = registry_mutex.into_inner();
    assert_eq!(
        registry
            .entry(&static_id)
            .expect("entry present")
            .expect_device_id(),
        Some(receiver_id.device_id()),
        "the first connection's authenticated device id is written back"
    );
}

// The pin a Static Peer's source re-reports does not reach the peer list
// until the next `drain_peer_sources`. In that window `resolve_peer` must
// still refuse `Unpinned` -- the case docs/03's "The pin" and DCR-063
// exist for, where a stale read would authenticate a hijacked address to
// whatever key answers.
#[tokio::test]
async fn resolve_peer_uses_the_registrys_pin_before_the_peer_list_sees_it() {
    let registry_dir = tempfile::tempdir().expect("registry tempdir");
    let registry_path = registry_dir.path().join("static-peers.json");
    let (mut registry, mut source) =
        StaticPeerRegistry::load(&registry_path).expect("load empty registry");
    let static_id = registry
        .add(None, &["127.0.0.1:9".to_string()], &OsRng)
        .expect("add static peer entry");

    let mut list = PeerList::new();
    let event = source.next_event().await.expect("initial observed event");
    list.apply(STATIC_PEER_SOURCE_ID, event)
        .expect("apply static peer observation");

    let peer_id = list
        .peers()
        .into_iter()
        .find(|peer| peer.device_id().is_none())
        .expect("the static peer is present and unidentified")
        .observations()
        .first()
        .expect("one observation")
        .id()
        .to_string();

    // The pin is written directly, without draining the re-emitted
    // `Observed` event: the peer list still holds this observation as
    // unidentified, exactly the gap between `registry.pin` and the next
    // `drain_peer_sources` that a running command can be in.
    let pinned_device = DeviceId::from_bytes(&[7u8; 16]).expect("valid device id");
    registry
        .pin(&static_id, pinned_device)
        .expect("pin the static peer entry");

    let resolved = resolve_peer(&peer_id, &list, &registry).expect("resolve static peer");
    assert_eq!(resolved.expectation, PeerExpectation::Device(pinned_device));
    assert_eq!(
        resolved.pin_target, None,
        "an entry the registry already pins has nothing left to pin"
    );
}

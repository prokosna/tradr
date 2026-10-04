//! Known Devices recording after verified handshakes (WI-M9-006a).

use std::net::SocketAddr;
use std::sync::Arc;

use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::known_store::{KnownDeviceRecorder, KnownDevicesStore};
use tradr_app::listener::{ListenerParams, handle_incoming_channel};
use tradr_app::peer_trust::OwnAttestation;
use tradr_app::send::execute_send_files;
use tradr_core::{
    Candidate, Capabilities, Clock, DisplayName, DomainTag, KeyBinding, KeyStore, PeerExpectation,
    PublicIdentity, RootId, Transport, TransportId, TrustTier, UnixTime, VersionRange,
};
use tradr_identity::{KnownDevice, OsRng, SoftwareKeyStore, SystemClock};
use tradr_integrity::BaoVerifier;
use tradr_secrets::FileStore;
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

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

fn identity_of(device: &KnownDevice) -> &PublicIdentity {
    device.identity()
}

#[tokio::test]
async fn a_completed_send_records_each_side_on_the_other() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_keys = setup_key_store(sender_dir.path());
    let receiver_keys = setup_key_store(receiver_dir.path());
    let sender_id = sender_keys.public_identity().expect("sender id");
    let receiver_id = receiver_keys.public_identity().expect("receiver id");

    std::fs::write(sender_dir.path().join("a.txt"), b"hello").expect("write file");

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

    let sender_known = KnownDevicesStore::open(sender_dir.path().join("known.json"))
        .expect("open sender known devices");
    let receiver_known = Arc::new(
        KnownDevicesStore::open(receiver_dir.path().join("known.json"))
            .expect("open receiver known devices"),
    );

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let receiver_transport =
        QuicTransport::new(receiver_keys.clone(), bind_addr).expect("rx transport");
    let rx_addr = receiver_transport.local_addr().expect("rx local addr");
    let sender_transport =
        QuicTransport::new(sender_keys.clone(), bind_addr).expect("tx transport");
    let mut incoming = receiver_transport.listen().await.expect("rx listen");

    let rx_identity = receiver_id.clone();
    let rx_keys = receiver_keys.clone();
    let rx_vfs = receiver_vfs.clone();
    let rx_known = receiver_known.clone();
    let rx_handle = tokio::spawn(async move {
        let channel = incoming.accept().await.expect("accept channel");
        let not_after = UnixTime::from_secs(SystemClock.now().as_secs() + 30 * 24 * 3600);
        let sig = rx_keys
            .sign(DomainTag::KeyBind, rx_identity.agreement_pub().as_bytes())
            .expect("sign");
        let our_key_binding = KeyBinding::new(rx_identity.agreement_pub().clone(), sig, not_after);
        let params = ListenerParams {
            root: root_receiver,
            our_identity: &rx_identity,
            our_attestation_token: Arc::new(FixedAttestation(String::new())),
            our_key_binding,
            our_versions: VersionRange::new(1, 1).expect("version range"),
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: Arc::new(BrowseAccess::new()),
            known_devices: Some(rx_known.as_ref()),
        };
        let res = handle_incoming_channel(
            channel.as_ref(),
            rx_vfs.as_ref(),
            params,
            rx_keys.as_ref(),
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

    let sent = execute_send_files(
        channel.as_ref(),
        &sender_vfs,
        root_sender,
        &["a.txt".to_string()],
        &sender_id,
        sender_keys.as_ref(),
        String::new(),
        Capabilities::DIRECT_QUIC,
        Some(&sender_known),
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await;
    drop(channel);
    let rx_outcome = rx_handle.await;

    sent.expect("send");
    let (rx_result, _chan) = rx_outcome.expect("rx join");
    rx_result.expect("rx handle");

    let on_sender = sender_known.snapshot();
    assert_eq!(on_sender.len(), 1);
    assert_eq!(identity_of(&on_sender[0]), &receiver_id);
    assert_eq!(on_sender[0].tier(), TrustTier::SameAccount);

    let on_receiver = receiver_known.snapshot();
    assert_eq!(on_receiver.len(), 1);
    assert_eq!(identity_of(&on_receiver[0]), &sender_id);
    assert_eq!(on_receiver[0].tier(), TrustTier::SameAccount);
}

#[test]
fn a_nearby_ephemeral_peer_is_not_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = setup_key_store(dir.path());
    let identity = keys.public_identity().expect("identity");
    let store = KnownDevicesStore::open(dir.path().join("known.json")).expect("open");

    store.record(
        &identity,
        TrustTier::NearbyEphemeral,
        UnixTime::from_secs(10),
    );

    assert!(store.snapshot().is_empty());
}

#[test]
fn a_second_record_without_a_name_keeps_the_first_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = setup_key_store(dir.path());
    let identity = keys.public_identity().expect("identity");
    let store = KnownDevicesStore::open(dir.path().join("known.json")).expect("open");

    store.record(&identity, TrustTier::SameAccount, UnixTime::from_secs(10));
    let name = DisplayName::new("laptop").expect("name");
    let changed = store
        .set_display_name(&identity.device_id(), Some(name.clone()))
        .expect("set name");
    assert!(changed);

    store.record(&identity, TrustTier::SameAccount, UnixTime::from_secs(20));

    let all = store.snapshot();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].display_name(), Some(&name));
    assert_eq!(all[0].last_seen(), UnixTime::from_secs(20));
}

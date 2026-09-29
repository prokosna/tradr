mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use common::{
    AUD, CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, clock_at, device_store, document,
    profile, published_key, token,
};
use tradr_app::browse::execute_list_peer_directory;
use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::listener::{ListenerParams, handle_incoming_channel};
use tradr_app::peer_trust::{OwnAttestation, PeerTrust};
use tradr_app::sign_in::{SignInState, finish_sign_in, listener_peer_verifier};
use tradr_core::{
    Candidate, Capabilities, Clock, DomainTag, HelloNonce, KeyBinding, KeyStore, LinkSecret,
    PeerExpectation, PublicIdentity, RelPath, Rng, RngError, RootId, ShareId, Transport,
    TransportId, TrustTier, UnixTime, VersionRange,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{
    AccountId, Link, LinkRegistry, SoftwareKeyStore, SystemClock, derive_link_id, hello,
};
use tradr_integrity::BaoVerifier;
use tradr_secrets::FileStore;
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

const LINKED_SUB: &str = "linked-subject";
const STRANGER_SUB: &str = "stranger-subject";
const LATER: i64 = NOW + 86_400;

struct FixedRng;

impl Rng for FixedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(7);
        Ok(())
    }
}

struct FixedAttestation(String);

impl OwnAttestation for FixedAttestation {
    fn id_token(&self) -> Option<String> {
        Some(self.0.clone())
    }
}

fn identity_of(store: &SoftwareKeyStore) -> PublicIdentity {
    store.public_identity().expect("a generated store has one")
}

fn binding_for(store: &SoftwareKeyStore) -> KeyBinding {
    let id = identity_of(store);
    let signature = store
        .sign(DomainTag::KeyBind, id.agreement_pub().as_bytes())
        .expect("signing under KeyBind must succeed");
    KeyBinding::new(
        id.agreement_pub().clone(),
        signature,
        UnixTime::from_secs(LATER),
    )
}

fn request_from(
    us: &SoftwareKeyStore,
    peer: &SoftwareKeyStore,
    peer_token: &str,
) -> AttestationRequest {
    let our_id = identity_of(us);
    let peer_id = identity_of(peer);
    let versions = VersionRange::new(1, 2).expect("a valid range");

    let (state, _our_hello) = hello::open(
        &FixedRng,
        versions,
        &our_id,
        "our-token".to_string(),
        binding_for(us),
        Capabilities::empty(),
    )
    .expect("a fixed rng fills a nonce");

    let peer_hello = tradr_core::PeerHello::new(
        versions,
        peer_id.identity_pub().clone(),
        peer_id.agreement_pub().clone(),
        peer_token.to_string(),
        binding_for(peer),
        HelloNonce::from_bytes([9u8; 16]),
        Capabilities::empty(),
    );

    let (_awaiting, request) = state
        .on_peer_hello(peer_hello, peer_id.device_id(), &clock_at(NOW))
        .expect("checks 1 to 3 pass for a well-formed peer Hello");
    request
}

fn trust_holding_the_providers_key() -> Arc<PeerTrust> {
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    trust
        .install(JWKS_URI, &document(&[published_key(KID)]))
        .expect("a well-formed document");
    Arc::new(trust)
}

fn empty_registry(dir: &std::path::Path) -> Arc<Mutex<LinkRegistry>> {
    let registry = LinkRegistry::load(&dir.join("links.json")).expect("a missing file is empty");
    Arc::new(Mutex::new(registry))
}

fn link_to(registry: &Mutex<LinkRegistry>, sub: &str, dir: &std::path::Path) -> tradr_core::LinkId {
    let secret = LinkSecret::from_bytes(&[3u8; 32]).expect("32 bytes builds a link secret");
    let link_id = derive_link_id(&secret);
    let link = Link::new(link_id, AccountId::new(ISS, sub), UnixTime::from_secs(NOW));
    let secrets = FileStore::new(dir.join("secrets"));
    registry
        .lock()
        .expect("an uncontended registry")
        .add(link, &secret, &secrets)
        .expect("a fresh account and a matching secret");
    link_id
}

async fn sign_in_as(sub: &str, us: &SoftwareKeyStore, trust: &PeerTrust, state: &SignInState) {
    let our_id = identity_of(us);
    let id_token = token(KID, sub, AUD, &our_id, NOW);
    finish_sign_in(&profile(), &our_id, id_token, trust, state, &clock_at(NOW))
        .await
        .expect("a token this provider signed, bound to this device");
}

#[test]
fn browse_access_unknown_device_is_not_allowed_and_record_replaces() {
    let access = BrowseAccess::new();
    let us = device_store(1);
    let peer_id = identity_of(&us).device_id();

    assert!(!access.allowed(peer_id));

    access.record(peer_id, true);
    assert!(access.allowed(peer_id));

    access.record(peer_id, false);
    assert!(!access.allowed(peer_id));
}

#[tokio::test]
async fn own_account_peer_is_recorded_allowed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let peer_id = identity_of(&peer).device_id();
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;
    let links = empty_registry(dir.path());
    let access = Arc::new(BrowseAccess::new());

    let peer_token = token(KID, OWN_SUB, AUD, &identity_of(&peer), NOW);
    let verify = listener_peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
        access.clone(),
    );

    let outcome = verify(request_from(&us, &peer, &peer_token)).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
    assert!(access.allowed(peer_id));
}

#[tokio::test]
async fn linked_peer_is_recorded_not_allowed_until_full_access_granted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let peer_id = identity_of(&peer).device_id();
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;
    let links = empty_registry(dir.path());
    let link_id = link_to(&links, LINKED_SUB, dir.path());
    let access = Arc::new(BrowseAccess::new());

    let peer_token = token(KID, LINKED_SUB, AUD, &identity_of(&peer), NOW);

    // First call: full_access is false by default on a new Link.
    let verify1 = listener_peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
        access.clone(),
    );
    let outcome1 = verify1(request_from(&us, &peer, &peer_token)).await;
    assert_eq!(outcome1, Ok(TrustTier::Linked));
    assert!(!access.allowed(peer_id));

    // Grant full access.
    links
        .lock()
        .expect("uncontended registry")
        .set_full_access(&link_id, true)
        .expect("link exists");

    // Second call: full_access is now true.
    let verify2 = listener_peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
        access.clone(),
    );
    let outcome2 = verify2(request_from(&us, &peer, &peer_token)).await;
    assert_eq!(outcome2, Ok(TrustTier::Linked));
    assert!(access.allowed(peer_id));

    // Revoke full access.
    links
        .lock()
        .expect("uncontended registry")
        .set_full_access(&link_id, false)
        .expect("link exists");

    // Third call: full_access revoked, replaces the grant with false.
    let verify3 = listener_peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
        access.clone(),
    );
    let outcome3 = verify3(request_from(&us, &peer, &peer_token)).await;
    assert_eq!(outcome3, Ok(TrustTier::Linked));
    assert!(!access.allowed(peer_id));
}

#[tokio::test]
async fn stranger_request_is_refused_and_records_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let us = device_store(1);
    let peer = device_store(2);
    let peer_id = identity_of(&peer).device_id();
    let trust = trust_holding_the_providers_key();
    let sign_in = Arc::new(SignInState::empty());
    sign_in_as(OWN_SUB, &us, &trust, &sign_in).await;
    let links = empty_registry(dir.path());
    let access = Arc::new(BrowseAccess::new());

    let peer_token = token(KID, STRANGER_SUB, AUD, &identity_of(&peer), NOW);
    let verify = listener_peer_verifier(
        trust.clone(),
        sign_in.clone(),
        links.clone(),
        Arc::new(clock_at(NOW)),
        access.clone(),
    );

    let outcome = verify(request_from(&us, &peer, &peer_token)).await;
    assert!(outcome.is_err());
    assert!(!access.allowed(peer_id));
}

#[tokio::test]
async fn listener_gate_refuses_peer_without_access() {
    let server_dir = tempfile::tempdir().expect("server tempdir");
    let _client_dir = tempfile::tempdir().expect("client tempdir");

    let server_store = Arc::new(device_store(10));
    let client_store = Arc::new(device_store(11));

    let server_id = identity_of(&server_store);
    let client_id = identity_of(&client_store);

    std::fs::write(server_dir.path().join("file.txt"), b"Content").expect("write file");

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

    // Access table starts empty: client device is not allowed.
    let access = Arc::new(BrowseAccess::new());
    let access_clone = access.clone();

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
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: access_clone,
        };

        let res = handle_incoming_channel(
            channel.as_ref(),
            rx_vfs_clone.as_ref(),
            params,
            rx_store_clone.as_ref(),
            &FixedRng,
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

    let handshake_params = tradr_app::handshake::HandshakeParams {
        authenticated_peer: channel.peer(),
        our_channel_max_frame_size: channel.max_frame_size(),
        our_identity: &client_id,
        our_attestation_token: String::new(),
        our_key_binding,
        our_versions: VersionRange::new(1, 1).expect("version range"),
        our_capabilities: Capabilities::DIRECT_QUIC,
    };

    let session = tradr_app::handshake::perform_handshake(
        control_send.as_mut(),
        control_recv.as_mut(),
        handshake_params,
        client_store.as_ref(),
        &FixedRng,
        &SystemClock,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .expect("handshake");

    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());
    let (mut browse_send, mut browse_recv) = channel.open_bi().await.expect("open browse");

    let share_id: ShareId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("share_id");

    let list_dir_msg = tradr_core::ListDir {
        share_id,
        path: RelPath::root(),
        cursor: String::new(),
        limit: 500,
        with_hash: false,
    };

    let frame_bytes =
        tradr_proto::browse::encode_list_dir_frame(&list_dir_msg, negotiated_frame_bound)
            .expect("encode list dir frame");
    browse_send
        .write_all(&frame_bytes)
        .await
        .expect("send list dir frame");

    let mut len_bytes = [0u8; 4];
    let mut offset = 0;
    while offset < 4 {
        let n = browse_recv
            .read(&mut len_bytes[offset..])
            .await
            .expect("read len");
        assert!(n > 0, "stream closed before announced len");
        offset += n;
    }
    let announced = u32::from_be_bytes(len_bytes);
    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    let mut payload_offset = 4;
    while payload_offset < raw.len() {
        let n = browse_recv
            .read(&mut raw[payload_offset..])
            .await
            .expect("read payload");
        assert!(n > 0, "stream closed before payload complete");
        payload_offset += n;
    }

    let mut decoder = tradr_proto::framing::FrameDecoder::new(channel.max_frame_size());
    decoder.feed(&raw);
    let frame = decoder.next_frame().expect("decode").expect("frame");

    assert!(
        tradr_proto::browse::decode_dir_listing_frame(&frame).is_err(),
        "unauthorized peer must receive no DirListing response"
    );

    let refused = tradr_proto::browse::decode_refused_frame(&frame)
        .expect("unauthorized peer must receive Refused response");
    assert_eq!(refused.reason, tradr_core::RefusalReason::NoAccess);

    drop(browse_recv);
    drop(browse_send);
    control_send.finish().await.expect("finish control send");

    let (server_res, _server_chan) = server_handle.await.expect("server join");
    assert!(server_res.is_ok());
}

#[tokio::test]
async fn listener_gate_serves_listing_to_peer_with_access() {
    let server_dir = tempfile::tempdir().expect("server tempdir");
    let _client_dir = tempfile::tempdir().expect("client tempdir");

    let server_store = Arc::new(device_store(20));
    let client_store = Arc::new(device_store(21));

    let server_id = identity_of(&server_store);
    let client_id = identity_of(&client_store);

    std::fs::write(server_dir.path().join("file.txt"), b"Content").expect("write file");

    let server_vfs = Arc::new(NativeVfs::new());
    let root_server = RootId::new(20);
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

    // Client device is recorded allowed.
    let access = Arc::new(BrowseAccess::new());
    access.record(client_id.device_id(), true);
    let access_clone = access.clone();

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
            our_capabilities: Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC)),
            browse_access: access_clone,
        };

        let res = handle_incoming_channel(
            channel.as_ref(),
            rx_vfs_clone.as_ref(),
            params,
            rx_store_clone.as_ref(),
            &FixedRng,
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
    let channel = client_transport
        .connect(&candidate, &PeerExpectation::Device(server_id.device_id()))
        .await
        .expect("connect");

    let share_id: ShareId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("share_id");

    let (list_result, server_outcome) = tokio::join!(
        execute_list_peer_directory(
            channel.as_ref(),
            share_id,
            RelPath::root(),
            String::new(),
            500,
            &client_id,
            client_store.as_ref(),
            String::new(),
            Capabilities::DIRECT_QUIC,
            |_| async { Ok(TrustTier::SameAccount) },
        ),
        server_handle,
    );

    let listing = list_result.expect("execute_list_peer_directory must succeed when allowed");
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].name, "file.txt");
    let (server_res, _server_chan) = server_outcome.expect("server join");
    assert!(server_res.is_ok());
}

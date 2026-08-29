//! `QuicTransport`, `QuicIncoming` and `QuicChannel` over loopback (WI-M1-004d).
//! Everything here goes through `tradr_core`'s public traits: stream-wrapper
//! and error-mapping tests live in `src/quic/`'s `#[cfg(test)]` modules, where
//! `pub(crate)` items are nameable and these are not.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use tradr_core::{
    Backing, Candidate, DeviceId, DomainTag, KeyStore, KeyStoreError, PeerExpectation,
    PublicIdentity, PublicKeyPoint, SecureChannel, SharedSecret, Signature, SoftwareReason,
    Transport, TransportError,
};
use tradr_transport::quic::QuicTransport;

// Copied from `tests/mutual_tls.rs` (a Supervisor-authored Critical
// Module file this Work Item may not edit): a `KeyStore` over fixed
// P-256 scalars, so a transport can be built without `tradr-identity`,
// which `ci/layer-deps.sh` forbids this crate to depend on.
#[derive(Debug)]
struct TestKeyStore {
    identity_key: SigningKey,
    agreement_key: SecretKey,
}

impl TestKeyStore {
    fn with_scalars(identity: [u8; 32], agreement: [u8; 32]) -> Self {
        Self {
            identity_key: SigningKey::from_slice(&identity).expect("a fixed valid P-256 scalar"),
            agreement_key: SecretKey::from_slice(&agreement).expect("a fixed valid P-256 scalar"),
        }
    }

    fn identity_point(&self) -> PublicKeyPoint {
        let point = self.identity_key.verifying_key().to_encoded_point(false);
        PublicKeyPoint::from_bytes(point.as_bytes()).expect("p256 writes 65 bytes uncompressed")
    }

    fn device_id(&self) -> DeviceId {
        DeviceId::from_identity_digest(blake3::hash(self.identity_point().as_bytes()).as_bytes())
    }
}

impl KeyStore for TestKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        let agreement_point = self.agreement_key.public_key().to_encoded_point(false);
        let agreement_pub = PublicKeyPoint::from_bytes(agreement_point.as_bytes())
            .expect("p256 writes 65 bytes uncompressed");
        Ok(PublicIdentity::new(
            self.identity_point(),
            agreement_pub,
            self.device_id(),
        ))
    }

    fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError> {
        use p256::ecdsa::signature::Signer;
        let payload = domain
            .payload(message)
            .map_err(KeyStoreError::DomainSeparation)?;
        let raw: p256::ecdsa::Signature = self
            .identity_key
            .try_sign(payload.as_ref())
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let normalized = raw.normalize_s().unwrap_or(raw);
        Ok(Signature::from_bytes(normalized.to_bytes().to_vec()))
    }

    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        let peer = PublicKey::from_sec1_bytes(peer_public.as_bytes())
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let shared =
            p256::ecdh::diffie_hellman(self.agreement_key.to_nonzero_scalar(), peer.as_affine());
        Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
    }

    fn backing(&self) -> Backing {
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    }
}

fn device(seed: u8) -> Arc<TestKeyStore> {
    Arc::new(TestKeyStore::with_scalars(
        [seed; 32],
        [seed.wrapping_add(0x40); 32],
    ))
}

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

// Drives a full loopback dial-and-accept to completion, pinned in both
// directions. Binds and starts listening before any dial is attempted
// (rule E3: "construct the listener and read its address before spawning
// the dialling task"), so "not listening yet" is impossible by
// construction.
async fn connected_channels(
    dialler_store: Arc<TestKeyStore>,
    listener_store: Arc<TestKeyStore>,
) -> (Box<dyn SecureChannel>, Box<dyn SecureChannel>) {
    let listener = QuicTransport::new(listener_store.clone(), loopback()).expect("loopback binds");
    let listener_addr = listener
        .local_addr()
        .expect("a bound endpoint reports its address");
    let dialler = QuicTransport::new(dialler_store, loopback()).expect("loopback binds");

    let mut incoming = listener.listen().await.expect("listening starts");
    let candidate = Candidate::new(dialler.id(), &listener_addr.to_string())
        .expect("a socket address is valid candidate syntax");

    let expect = PeerExpectation::Device(listener_store.device_id());
    let dial = dialler.connect(&candidate, &expect);
    let accept = incoming.accept();

    let (dial_result, accept_result) = tokio::join!(dial, accept);
    (
        dial_result.expect("a pinned dial to the right device completes"),
        accept_result.expect("the dial arrives"),
    )
}

#[tokio::test]
async fn two_transports_over_loopback_each_see_the_others_device_id_and_not_their_own() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let dialler_store = device(0x11);
        let listener_store = device(0x22);

        let (dialler_channel, listener_channel) =
            connected_channels(dialler_store.clone(), listener_store.clone()).await;

        assert_eq!(dialler_channel.peer(), listener_store.device_id());
        assert_eq!(listener_channel.peer(), dialler_store.device_id());
        assert_ne!(dialler_channel.peer(), listener_channel.peer());
    })
    .await
    .expect("a loopback handshake completes well inside the bound");
}

#[tokio::test]
async fn a_bidirectional_stream_carries_bytes_both_ways_through_secure_channel() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (dialler_channel, listener_channel) =
            connected_channels(device(0x11), device(0x22)).await;

        let (mut client_send, mut client_recv) = dialler_channel
            .open_bi()
            .await
            .expect("credit is available up front");
        client_send
            .write_all(b"ping")
            .await
            .expect("the peer is listening");

        let (mut server_send, mut server_recv) = listener_channel
            .accept_bi()
            .await
            .expect("the client opened one");

        let mut received = [0u8; 4];
        let mut read = 0;
        while read < received.len() {
            let n = server_recv
                .read(&mut received[read..])
                .await
                .expect("the client is still writing");
            assert_ne!(n, 0, "the client closed before sending everything");
            read += n;
        }
        assert_eq!(&received, b"ping");

        server_send
            .write_all(b"pong")
            .await
            .expect("the client is still reading");

        let mut received = [0u8; 4];
        let mut read = 0;
        while read < received.len() {
            let n = client_recv
                .read(&mut received[read..])
                .await
                .expect("the server is still writing");
            assert_ne!(n, 0, "the server closed before sending everything");
            read += n;
        }
        assert_eq!(&received, b"pong");
    })
    .await
    .expect("a loopback handshake completes well inside the bound");
}

#[tokio::test]
async fn max_frame_size_is_one_mebibyte_and_not_the_connections_datagram_size() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (dialler_channel, listener_channel) =
            connected_channels(device(0x11), device(0x22)).await;

        // docs/04-protocol.md's "Framing" default. `quinn::Connection::
        // max_datagram_size()` reports about 1288 on loopback -- a wholly
        // different, path-MTU-bound quantity this must not be confused with.
        const EXPECTED: u32 = 1024 * 1024;
        assert_eq!(dialler_channel.max_frame_size(), EXPECTED);
        assert_eq!(listener_channel.max_frame_size(), EXPECTED);
        assert_ne!(dialler_channel.max_frame_size(), 1288);
    })
    .await
    .expect("a loopback handshake completes well inside the bound");
}

#[tokio::test]
async fn a_dialler_pinning_the_wrong_device_id_is_refused_as_authentication_failed() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let dialler_store = device(0x11);
        let listener_store = device(0x22);
        let someone_else = device(0x33);

        let listener =
            QuicTransport::new(listener_store.clone(), loopback()).expect("loopback binds");
        let listener_addr = listener
            .local_addr()
            .expect("a bound endpoint reports its address");
        let dialler = QuicTransport::new(dialler_store, loopback()).expect("loopback binds");

        let mut incoming = listener.listen().await.expect("listening starts");
        let candidate = Candidate::new(dialler.id(), &listener_addr.to_string())
            .expect("a socket address is valid candidate syntax");

        let expect = PeerExpectation::Device(someone_else.device_id());
        let dial = dialler.connect(&candidate, &expect);
        let accept = incoming.accept();
        let (dial_result, accept_result) = tokio::join!(dial, accept);

        assert_eq!(
            dial_result.err(),
            Some(TransportError::AuthenticationFailed),
            "a pin mismatch must be reported as authentication failure, not rejection or a timeout"
        );
        assert!(
            accept_result.is_err(),
            "the listener also observes the same crypto-range close"
        );
    })
    .await
    .expect("a refusal is decided well inside the bound");
}

#[tokio::test]
async fn connect_with_an_unparseable_address_is_unreachable_without_a_socket() {
    // No listener anywhere in this test: an address that fails to parse
    // must be refused before any socket operation is attempted.
    let dialler = QuicTransport::new(device(0x11), loopback()).expect("loopback binds");
    let candidate = Candidate::new(dialler.id(), "not-a-socket-address")
        .expect("non-empty and free of control characters is valid candidate syntax");

    let result = dialler
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await;

    assert_eq!(result.err(), Some(TransportError::Unreachable));
}

#[tokio::test]
async fn an_unpinned_dialler_connects_and_reports_the_device_id_it_learned() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let dialler_store = device(0x11);
        let listener_store = device(0x22);

        let listener =
            QuicTransport::new(listener_store.clone(), loopback()).expect("loopback binds");
        let listener_addr = listener
            .local_addr()
            .expect("a bound endpoint reports its address");
        let dialler = QuicTransport::new(dialler_store, loopback()).expect("loopback binds");

        let mut incoming = listener.listen().await.expect("listening starts");
        let candidate = Candidate::new(dialler.id(), &listener_addr.to_string())
            .expect("a socket address is valid candidate syntax");

        let dial = dialler.connect(&candidate, &PeerExpectation::Unpinned);
        let accept = incoming.accept();
        let (dial_result, accept_result) = tokio::join!(dial, accept);

        let channel = dial_result.expect("an unpinned dial still authenticates the peer's key");
        accept_result.expect("the dial arrives");
        assert_eq!(channel.peer(), listener_store.device_id());
    })
    .await
    .expect("a loopback handshake completes well inside the bound");
}

#[tokio::test]
async fn transport_is_dyn_compatible_through_a_boxed_trait_object() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let dialler_store = device(0x11);
        let listener_store = device(0x22);

        let listener_concrete =
            QuicTransport::new(listener_store.clone(), loopback()).expect("loopback binds");
        let listener_addr = listener_concrete
            .local_addr()
            .expect("a bound endpoint reports its address");
        let listener: Box<dyn Transport> = Box::new(listener_concrete);
        let dialler: Box<dyn Transport> =
            Box::new(QuicTransport::new(dialler_store, loopback()).expect("loopback binds"));

        let mut incoming = listener.listen().await.expect("listening starts");
        let candidate = Candidate::new(dialler.id(), &listener_addr.to_string())
            .expect("a socket address is valid candidate syntax");

        let expect = PeerExpectation::Device(listener_store.device_id());
        let dial = dialler.connect(&candidate, &expect);
        let accept = incoming.accept();
        let (dial_result, accept_result) = tokio::join!(dial, accept);

        assert_eq!(
            dial_result
                .expect("a pinned dial through a trait object still completes")
                .peer(),
            listener_store.device_id()
        );
        accept_result.expect("the dial arrives");
    })
    .await
    .expect("a loopback handshake completes well inside the bound");
}

//! A real loopback QUIC handshake via `tls::client_config` and
//! `tls::server_config`, over actual UDP rather than the in-memory
//! buffers `tests/mutual_tls.rs` uses. The stream-wrapper and
//! `TransportError`-mapping tests live in `src/quic/`'s own
//! `#[cfg(test)]` modules: `pub(crate)` items are not nameable here.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tradr_core::{
    Backing, DeviceId, DomainTag, KeyStore, KeyStoreError, PeerExpectation, PublicIdentity,
    PublicKeyPoint, SharedSecret, Signature, SoftwareReason,
};
use tradr_transport::tls::{client_config, server_config};

// Copied from `tests/mutual_tls.rs` (a Supervisor-authored Critical
// Module file this Work Item may not edit): a `KeyStore` over fixed
// P-256 scalars, so a config can be built without `tradr-identity`,
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
            DeviceId::from_identity_digest(
                blake3::hash(self.identity_point().as_bytes()).as_bytes(),
            ),
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
const SERVER_NAME: &str = "tradr.invalid";

// Binds and configures a listening endpoint before any dial is
// attempted, so "not listening yet" is impossible by construction.
fn server_endpoint(key_store: Arc<dyn KeyStore>) -> (quinn::Endpoint, SocketAddr) {
    let rustls_config = server_config(key_store).expect("a working store configures");
    let quic_crypto =
        QuicServerConfig::try_from(rustls_config).expect("TLS 1.3 only is compatible");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let endpoint = quinn::Endpoint::server(server_config, bind).expect("loopback binds");
    let addr = endpoint
        .local_addr()
        .expect("a bound endpoint reports its address");
    (endpoint, addr)
}

fn client_endpoint() -> quinn::Endpoint {
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    quinn::Endpoint::client(bind).expect("loopback binds")
}

#[tokio::test]
async fn a_pinned_handshake_completes_over_a_real_socket_and_carries_a_stream() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let dialler = device(0x11);
        let listener = device(0x22);

        let (server, addr) = server_endpoint(listener.clone());
        let client = client_endpoint();

        let rustls_client = client_config(dialler, PeerExpectation::Device(listener.device_id()))
            .expect("a working store configures");
        let quic_client_crypto =
            QuicClientConfig::try_from(rustls_client).expect("TLS 1.3 only is compatible");
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));

        let connecting = client
            .connect_with(client_config, addr, SERVER_NAME)
            .expect("a valid config dials");

        let dial = async { connecting.await.expect("handshake completes") };
        let accept = async {
            let incoming = server.accept().await.expect("the dial arrives");
            incoming
                .accept()
                .expect("a well-formed Initial")
                .await
                .expect("handshake completes")
        };

        let (client_conn, server_conn) = tokio::join!(dial, accept);

        let (mut send, mut recv) = client_conn.open_bi().await.expect("credit is available");
        send.write_all(b"hello over a real socket")
            .await
            .expect("the peer is listening");
        send.finish().expect("closing the send half succeeds");

        let (mut server_send, mut server_recv) = server_conn
            .accept_bi()
            .await
            .expect("the client opened one");
        let received = server_recv
            .read_to_end(64)
            .await
            .expect("the client sent a bounded message and then finished");
        assert_eq!(received, b"hello over a real socket");

        // A live send half kept open would leave the client's read below
        // pending forever instead of seeing a clean end of stream.
        server_send
            .finish()
            .expect("closing the send half succeeds");

        let after_end = recv
            .read(&mut [0u8; 1])
            .await
            .expect("a clean end is not an error");
        assert_eq!(after_end, None, "the client never wrote a reply");
    })
    .await
    .expect("a loopback handshake completes well inside the bound");
}

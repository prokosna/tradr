//! `QuicTransport::connect` resolving a candidate that is a name rather
//! than a literal address (WI-M5-001, docs/03-discovery-and-transport.md,
//! "How `direct-quic` turns a candidate into an address").

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use tradr_core::{
    Backing, Candidate, DeviceId, DomainTag, KeyStore, KeyStoreError, PeerExpectation,
    PublicIdentity, PublicKeyPoint, SharedSecret, Signature, SoftwareReason, Transport,
    TransportError,
};
use tradr_transport::quic::QuicTransport;

// Copied from `tests/quic_transport.rs` (a Supervisor-authored Critical
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

#[tokio::test]
async fn a_name_that_resolves_to_loopback_connects_through_the_resolver() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let dialler_store = device(0x11);
        let listener_store = device(0x22);

        // Bound and listening before the dialling task starts (rule E3):
        // "not listening yet" is impossible by construction.
        let listener =
            QuicTransport::new(listener_store.clone(), loopback()).expect("loopback binds");
        let listener_addr = listener
            .local_addr()
            .expect("a bound endpoint reports its address");
        let dialler = QuicTransport::new(dialler_store, loopback()).expect("loopback binds");

        let mut incoming = listener.listen().await.expect("listening starts");

        // "localhost" fails `str::parse::<SocketAddr>()`, so this exercises
        // the resolver path rather than the literal one.
        let name_candidate = format!("localhost:{}", listener_addr.port());
        let candidate = Candidate::new(dialler.id(), &name_candidate)
            .expect("non-empty and free of control characters is valid candidate syntax");

        let expect = PeerExpectation::Device(listener_store.device_id());
        let dial = dialler.connect(&candidate, &expect);
        let accept = incoming.accept();
        let (dial_result, accept_result) = tokio::join!(dial, accept);

        let channel = dial_result.expect("a name resolving to the listener's address connects");
        accept_result.expect("the dial arrives");
        assert_eq!(channel.peer(), listener_store.device_id());
    })
    .await
    .expect("a resolved loopback handshake completes well inside the bound");
}

#[tokio::test]
async fn a_name_that_cannot_resolve_is_unreachable() {
    // No listener anywhere in this test: RFC 6761 guarantees `.invalid`
    // never resolves, so this must fail before any dial is attempted.
    let dialler = QuicTransport::new(device(0x11), loopback()).expect("loopback binds");
    let candidate = Candidate::new(dialler.id(), "this-name-does-not-exist.invalid:51820")
        .expect("non-empty and free of control characters is valid candidate syntax");

    let result = dialler
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await;

    assert_eq!(result.err(), Some(TransportError::Unreachable));
}

#[tokio::test]
async fn an_address_carrying_no_port_is_unreachable() {
    // Fails `SocketAddr::parse` first, then `lookup_host` fails with
    // `InvalidInput` rather than resolving the bare host (background,
    // established by probe on 2026-08-31).
    let dialler = QuicTransport::new(device(0x11), loopback()).expect("loopback binds");
    let candidate = Candidate::new(dialler.id(), "127.0.0.1")
        .expect("non-empty and free of control characters is valid candidate syntax");

    let result = dialler
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await;

    assert_eq!(result.err(), Some(TransportError::Unreachable));
}

//! Supervisor-authored tests for WI-M1-003, written before the
//! implementation. This is where a peer's key stops being a value that
//! parses and starts being a key it must prove it holds. Critical Module:
//! a verifier that accepts a certificate without that proof authenticates
//! anyone who ever saw a copy of it.

use std::io::Cursor;
use std::sync::Arc;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, Connection, ServerConnection};
use tradr_core::{
    Backing, DeviceId, DomainTag, KeyStore, KeyStoreError, PeerExpectation, PublicIdentity,
    PublicKeyPoint, SharedSecret, Signature, SoftwareReason,
};
use tradr_transport::certificate::identity_point;
use tradr_transport::tls::{TlsError, client_config, peer_device_id, server_config};

/// A `KeyStore` over fixed P-256 scalars, carried here rather than taken
/// from `tradr-identity`, which `ci/layer-deps.sh` forbids this crate to
/// dev-depend on. `Send + Sync` because DCR-041 makes that part of what a
/// `KeyStore` is, and a signer rustls holds could not exist otherwise.
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

// The name a QUIC dialler has to supply and this design never reads:
// identity lives in the SubjectPublicKeyInfo (DCR-038), so the verifier
// ignores it and nothing may depend on its value.
const UNUSED_SERVER_NAME: &str = "tradr.invalid";

// Enough rounds for a TLS 1.3 handshake with client authentication,
// which the probe completes in two. A bound rather than a loop until
// idle, so a handshake that will never finish fails instead of hanging.
const MAX_ROUNDS: usize = 12;

/// What running a handshake produced: both ends once it completed, or
/// the error whichever side rejected first reported.
type Outcome = Result<(Connection, Connection), rustls::Error>;

// Drives both ends against each other over in-memory buffers. No socket,
// no executor and no clock, so the result is the protocol's and nothing
// else's (rules E2 and E3).
fn run(mut client: Connection, mut server: Connection) -> Outcome {
    for _ in 0..MAX_ROUNDS {
        pump(&mut client, &mut server)?;
        pump(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    Err(rustls::Error::General(format!(
        "no side completed or refused within {MAX_ROUNDS} rounds"
    )))
}

fn expect_completed(outcome: Outcome) -> (Connection, Connection) {
    match outcome {
        Ok(pair) => pair,
        Err(e) => panic!("handshake was refused: {e}"),
    }
}

fn expect_refused(outcome: Outcome) -> rustls::Error {
    match outcome {
        Err(e) => e,
        Ok(_) => panic!("handshake completed when it had to be refused"),
    }
}

fn pump(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
    }
    if wire.is_empty() {
        return Ok(());
    }
    let mut cursor = Cursor::new(wire);
    while (cursor.position() as usize) < cursor.get_ref().len() {
        to.read_tls(&mut cursor)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        to.process_new_packets()?;
    }
    Ok(())
}

// A dialler carrying `expect` against a listener holding `listener`.
fn handshake(
    dialler: &Arc<TestKeyStore>,
    listener: &Arc<TestKeyStore>,
    expect: PeerExpectation,
) -> Outcome {
    run_pair(
        client_config(dialler.clone(), expect).expect("a working store configures"),
        server_config(listener.clone()).expect("a working store configures"),
    )
}

// Reads as the old bare-DeviceId helper did, so a test about pinning is
// not also a test about how an expectation is spelled.
fn pinning(target: &Arc<TestKeyStore>) -> PeerExpectation {
    PeerExpectation::Device(target.device_id())
}

fn run_pair(client: rustls::ClientConfig, server: rustls::ServerConfig) -> Outcome {
    let name = ServerName::try_from(UNUSED_SERVER_NAME).expect("a literal name parses");
    let client = ClientConnection::new(Arc::new(client), name).expect("a valid config connects");
    let server = ServerConnection::new(Arc::new(server)).expect("a valid config listens");
    run(Connection::Client(client), Connection::Server(server))
}

fn only_certificate(side: &Connection) -> CertificateDer<'static> {
    let certs = side.peer_certificates().expect("a peer presented one");
    assert_eq!(certs.len(), 1, "no chain is ever presented");
    certs[0].clone().into_owned()
}

#[test]
fn two_devices_that_expect_each_other_complete_a_mutual_handshake() {
    let dialler = device(0x11);
    let listener = device(0x22);

    let (client, server) = expect_completed(handshake(&dialler, &listener, pinning(&listener)));

    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert!(
        server.peer_certificates().is_some(),
        "the listener requested a certificate and got one"
    );
}

#[test]
fn each_side_sees_the_other_device_id_and_not_its_own() {
    // The join every later plane depends on: `SecureChannel::peer` has to
    // name the device at the other end, and a verifier that reported its
    // own would make every peer look like this device.
    let dialler = device(0x11);
    let listener = device(0x22);

    let (client, server) = expect_completed(handshake(&dialler, &listener, pinning(&listener)));

    let seen_by_dialler = peer_device_id(&only_certificate(&client)).expect("a valid certificate");
    let seen_by_listener = peer_device_id(&only_certificate(&server)).expect("a valid certificate");

    assert_eq!(seen_by_dialler, listener.device_id());
    assert_eq!(seen_by_listener, dialler.device_id());
    assert_ne!(seen_by_dialler, seen_by_listener);
}

#[test]
fn a_dialler_expecting_another_device_is_refused() {
    // The pinning check itself. The listener is perfectly valid and holds
    // a real key; it is simply not the device that was dialled.
    let dialler = device(0x11);
    let listener = device(0x22);
    let someone_else = device(0x33);

    let error = expect_refused(handshake(&dialler, &listener, pinning(&someone_else)));

    assert!(
        matches!(
            error,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            )
        ),
        "a pinning refusal is this crate's own verdict, not rustls's: {error}"
    );
}

#[test]
fn a_listener_accepts_a_device_it_has_never_met() {
    // DCR-040: a listener has no expectation to compare against, because
    // it does not know who is dialling until they arrive. Whether that
    // device is welcome is the Attestation exchange's question.
    let stranger = device(0x55);
    let listener = device(0x22);

    let (_, server) = expect_completed(handshake(&stranger, &listener, pinning(&listener)));

    assert_eq!(
        peer_device_id(&only_certificate(&server)).expect("a valid certificate"),
        stranger.device_id()
    );
}

#[test]
fn presenting_another_devices_certificate_without_its_key_is_refused() {
    // The attack the whole Work Item exists to stop, and the one a
    // verifier that only compared the SubjectPublicKeyInfo would pass. A
    // certificate is public: anyone who has connected to a device holds a
    // copy. What they cannot produce is the CertificateVerify under it.
    let listener = device(0x11);
    let impostor = ImpostorKeyStore {
        certificate_of: device(0x22),
        signing_as: device(0x77),
    };

    let error = expect_refused(run_pair(
        client_config(Arc::new(impostor), pinning(&listener)).expect("configures"),
        server_config(listener.clone()).expect("configures"),
    ));

    // The dialler pins the listener correctly, so this cannot be the
    // pinning verdict. It has to be the signature under the certificate,
    // which is the check a stolen certificate has no answer to.
    assert!(
        !matches!(
            error,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            )
        ),
        "refused by pinning, so the impostor was never tested: {error}"
    );
}

/// Presents one device's public identity while signing with another's.
/// Impossible for a real `KeyStore`, which is the point: it is the only
/// way to put a stolen certificate on the wire and see what happens.
#[derive(Debug)]
struct ImpostorKeyStore {
    certificate_of: Arc<TestKeyStore>,
    signing_as: Arc<TestKeyStore>,
}

impl KeyStore for ImpostorKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        self.certificate_of.public_identity()
    }

    fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError> {
        self.signing_as.sign(domain, message)
    }

    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        self.signing_as.agree(peer_public)
    }

    fn backing(&self) -> Backing {
        self.signing_as.backing()
    }
}

#[test]
fn a_listener_presenting_a_certificate_it_lacks_the_key_for_is_refused() {
    // The mirror of the test above, and it needs saying separately: the
    // two directions run different verifiers, so a check that is right on
    // one side proves nothing about the other. Here the pin succeeds --
    // the certificate really is the device that was meant -- so only the
    // CertificateVerify stands between them.
    let victim = device(0x22);
    let impostor = ImpostorKeyStore {
        certificate_of: device(0x22),
        signing_as: device(0x77),
    };

    let error = expect_refused(run_pair(
        client_config(device(0x11), pinning(&victim)).expect("configures"),
        server_config(Arc::new(impostor)).expect("configures"),
    ));

    assert!(
        !matches!(
            error,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            )
        ),
        "refused by pinning, so the impostor was never tested: {error}"
    );
}

#[test]
fn a_dialler_that_presents_no_certificate_is_refused() {
    // docs/05's "certificates are requested in both directions" is the
    // whole of mutual TLS, and a listener that merely *offers* client
    // authentication without requiring it accepts an anonymous peer
    // while every test using this crate's own dialler still passes.
    let listener = device(0x11);
    let anonymous = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is supported")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
    .with_no_client_auth();

    let error = expect_refused(run_pair(
        anonymous,
        server_config(listener).expect("configures"),
    ));

    assert!(!format!("{error}").is_empty(), "a refusal carries a reason");
}

/// A dialler that checks nothing, so the listener's own requirements are
/// the only thing the handshake can fail on. Not this crate's verifier:
/// the peer being modelled is one that is not this code.
#[derive(Debug)]
struct AcceptAnyServer;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

#[test]
fn the_signer_refuses_a_message_that_is_not_a_certificate_verify() {
    // DCR-037's separation, reached through the trait rather than argued
    // about. `TlsCertificateVerify` requires RFC 8446's preamble and
    // prepends nothing, so a Brokr handing over an opaque challenge
    // cannot collect a signature this context would honour.
    let store = device(0x11);

    let result = store.sign(DomainTag::TlsCertificateVerify, b"not a CertificateVerify");

    assert!(matches!(result, Err(KeyStoreError::DomainSeparation(_))));
}

#[test]
fn the_certificate_a_handshake_presents_is_the_one_build_self_signed_makes() {
    // Ties this Work Item to WI-M1-002b: the bytes on the wire are that
    // module's output, not a certificate assembled a second time here.
    let dialler = device(0x11);
    let listener = device(0x22);

    let (client, _) = expect_completed(handshake(&dialler, &listener, pinning(&listener)));

    let presented = only_certificate(&client);
    assert_eq!(
        identity_point(presented.as_ref()).expect("a valid certificate"),
        listener.identity_point()
    );
}

#[test]
fn a_config_reports_a_key_store_that_cannot_report_its_identity() {
    // The one failure a caller can actually hit, and it must not be a
    // panic inside a handshake later.
    let result = server_config(Arc::new(BrokenKeyStore));

    assert!(matches!(result, Err(TlsError::KeyStore(_))));
}

/// A `KeyStore` whose every operation fails, for the construction path.
#[derive(Debug)]
struct BrokenKeyStore;

impl KeyStore for BrokenKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        Err(KeyStoreError::Backend("this store is broken".into()))
    }

    fn sign(&self, _domain: DomainTag, _message: &[u8]) -> Result<Signature, KeyStoreError> {
        Err(KeyStoreError::Backend("this store is broken".into()))
    }

    fn agree(&self, _peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        Err(KeyStoreError::Backend("this store is broken".into()))
    }

    fn backing(&self) -> Backing {
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    }
}

#[test]
fn an_unpinned_dialler_accepts_a_device_it_has_never_met() {
    // docs/03's Static Peer fills its entry in *on* the first connection,
    // so at that one moment there is nothing to compare against. The
    // DeviceId the dialler learns here is what the caller then stores.
    let dialler = device(0x11);
    let listener = device(0x22);

    let (client, _) = expect_completed(handshake(&dialler, &listener, PeerExpectation::Unpinned));

    assert_eq!(
        peer_device_id(&only_certificate(&client)).expect("a valid certificate"),
        listener.device_id()
    );
}

#[test]
fn an_unpinned_dialler_still_refuses_a_certificate_its_holder_cannot_sign_under() {
    // The failure this Work Item exists to prevent: `Unpinned` collapsing
    // into "accept anything". Dropping the comparison must not drop the
    // CertificateVerify check, and no other test in this file would
    // notice, because every one of them pins.
    let impostor = ImpostorKeyStore {
        certificate_of: device(0x22),
        signing_as: device(0x77),
    };

    let error = expect_refused(run_pair(
        client_config(device(0x11), PeerExpectation::Unpinned).expect("configures"),
        server_config(Arc::new(impostor)).expect("configures"),
    ));

    assert!(
        !matches!(
            error,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            )
        ),
        "an unpinned dialler has no pin to refuse on, so this must be the signature: {error}"
    );
}

#[test]
fn an_identity_expectation_accepts_the_device_it_names() {
    // `Identity` is `Device` plus the agreement key, and the mistake a
    // `#[non_exhaustive]` enum invites is a wildcard arm folding it in
    // with `Unpinned`. This direction catches the fold that accepts.
    let dialler = device(0x11);
    let listener = device(0x22);
    let identity = listener
        .public_identity()
        .expect("a working store reports its identity");

    let (client, _) = expect_completed(handshake(
        &dialler,
        &listener,
        PeerExpectation::Identity(identity),
    ));

    assert_eq!(
        peer_device_id(&only_certificate(&client)).expect("a valid certificate"),
        listener.device_id()
    );
}

#[test]
fn an_identity_expectation_naming_another_device_is_refused() {
    // And this direction catches the fold that lets an impostor through:
    // an `Identity` treated as `Unpinned` would complete this handshake.
    let dialler = device(0x11);
    let listener = device(0x22);
    let someone_else = device(0x33)
        .public_identity()
        .expect("a working store reports its identity");

    let error = expect_refused(handshake(
        &dialler,
        &listener,
        PeerExpectation::Identity(someone_else),
    ));

    assert!(
        matches!(
            error,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            )
        ),
        "an Identity expectation must pin exactly as Device does: {error}"
    );
}

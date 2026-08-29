//! `rustls` against `KeyStore`: the external signer and the pinning
//! verifiers (docs/05-security.md, "Why there are two encryption
//! layers"; DCR-040, DCR-041). Every private key operation crosses the
//! `KeyStore` boundary; nothing here ever holds key material.

use std::fmt;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use tradr_core::{DeviceId, KeyStore, KeyStoreError, PeerExpectation};

use crate::certificate::{self, CertificateError};

mod signer;
mod verifier;

use signer::KeyStoreSigningKey;
use verifier::{AnyDeviceClientCertVerifier, ExpectedDeviceServerCertVerifier};

/// An error building a TLS config or reading a peer's `DeviceId`. Never
/// names the bytes it refused (rule F4): every variant wraps another
/// layer's own error, which already withholds them.
#[derive(Debug)]
pub enum TlsError {
    /// The `KeyStore` failed to report the device's identity or to sign.
    KeyStore(KeyStoreError),
    /// The certificate could not be built or parsed.
    Certificate(CertificateError),
    /// rustls refused the configuration itself, independent of any
    /// `KeyStore` or certificate content.
    Rustls(rustls::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyStore(e) => write!(f, "key store error: {e}"),
            Self::Certificate(e) => write!(f, "certificate error: {e}"),
            Self::Rustls(e) => write!(f, "rustls error: {e}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyStore(e) => Some(e),
            Self::Certificate(e) => Some(e),
            Self::Rustls(e) => Some(e),
        }
    }
}

// `build_self_signed`'s own `CertificateError::KeyStore` is unwrapped
// here so a `KeyStore` failure is reported as `TlsError::KeyStore`
// regardless of which caller hit it, rather than as a certificate error
// that merely wraps one.
fn from_certificate_error(error: CertificateError) -> TlsError {
    match error {
        CertificateError::KeyStore(e) => TlsError::KeyStore(e),
        other => TlsError::Certificate(other),
    }
}

// Builds the self-signed device certificate and pairs it with the
// external signer both configs present it under. Shared by
// `client_config` and `server_config`, which differ only in which
// verifier they install.
fn certified_key(key_store: Arc<dyn KeyStore>) -> Result<CertifiedKey, TlsError> {
    let cert =
        certificate::build_self_signed(key_store.as_ref()).map_err(from_certificate_error)?;
    let signing_key: Arc<dyn SigningKey> = Arc::new(KeyStoreSigningKey::new(key_store));
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(cert)],
        signing_key,
    ))
}

/// The dialling side. Where `expect.device_id()` is `Some`, the peer must
/// present a certificate whose identity key derives that `DeviceId`.
/// `Unpinned` (docs/05-security.md, "one case with nothing to pin
/// against") makes no such comparison, but the peer still proves
/// possession of the key it presents.
pub fn client_config(
    key_store: Arc<dyn KeyStore>,
    expect: PeerExpectation,
) -> Result<rustls::ClientConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(ExpectedDeviceServerCertVerifier::new(
        expect.device_id(),
        &provider,
    ));
    let key = certified_key(key_store)?;

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TlsError::Rustls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    Ok(config)
}

/// The listening side. Requests a client certificate and accepts any
/// well-formed one, see DCR-040.
pub fn server_config(key_store: Arc<dyn KeyStore>) -> Result<rustls::ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier = Arc::new(AnyDeviceClientCertVerifier::new(&provider));
    let key = certified_key(key_store)?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TlsError::Rustls)?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    Ok(config)
}

/// The `DeviceId` a peer's certificate names. The one place a `DeviceId`
/// is derived from a certificate (WI-M1-002a): the dialling verifier
/// calls this rather than deriving one of its own. The listening side
/// needs no `DeviceId` at all (DCR-040), so it does not call it.
pub fn peer_device_id(certificate: &CertificateDer<'_>) -> Result<DeviceId, TlsError> {
    let point =
        certificate::identity_point(certificate.as_ref()).map_err(from_certificate_error)?;
    Ok(DeviceId::from_identity_digest(
        blake3::hash(point.as_bytes()).as_bytes(),
    ))
}

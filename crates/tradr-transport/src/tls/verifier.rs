//! The two verifiers docs/05-security.md's "Why there are two encryption
//! layers" describes. The dialling side compares the peer's certificate
//! against the `DeviceId` it expected, or against nothing when it has no
//! expectation yet; the listening side never has one and defers welcome
//! to the Attestation exchange (DCR-040).

use std::fmt;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, PeerIncompatible,
    SignatureScheme,
};
use tradr_core::DeviceId;

use crate::certificate::identity_point;
use crate::tls::peer_device_id;

/// The one scheme both verifiers accept (ADR-0012).
const SCHEMES: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP256_SHA256];

/// The dialling side (docs/05-security.md, "Only the dialling side
/// pins"). Compares the peer's certificate against `expected` when there
/// is one to compare against.
pub(crate) struct ExpectedDeviceServerCertVerifier {
    expected: Option<DeviceId>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ExpectedDeviceServerCertVerifier {
    pub(crate) fn new(expected: Option<DeviceId>, provider: &CryptoProvider) -> Self {
        Self {
            expected,
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for ExpectedDeviceServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpectedDeviceServerCertVerifier")
            .field("expected", &self.expected)
            .finish()
    }
}

impl ServerCertVerifier for ExpectedDeviceServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // No chain and no CA (docs/05-security.md): a non-empty
        // intermediates list is a peer presenting something this design
        // has no rule for.
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }

        // The one place a DeviceId is derived from a certificate
        // (WI-M1-002a): the pinning check compares against it rather
        // than deriving one of its own.
        let seen = peer_device_id(end_entity)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        // `None` arises only from `PeerExpectation::Unpinned` and means no
        // comparison is made, never that any peer is accepted: `seen`
        // above already had to parse, and the signature checks below
        // still run.
        if let Some(expected) = self.expected
            && seen != expected
        {
            // This crate's own verdict, not one rustls reached itself,
            // distinguished from a signature failure below.
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // This deployment is TLS 1.3 only.
        Err(PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // What an impostor holding only a copy of the certificate cannot
        // produce: the CertificateVerify signature under it.
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }
}

/// The listening side (DCR-040). It has no expectation to compare
/// against, since it does not know who is dialling until they arrive;
/// whether that device is welcome is the Attestation exchange's question.
pub(crate) struct AnyDeviceClientCertVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AnyDeviceClientCertVerifier {
    pub(crate) fn new(provider: &CryptoProvider) -> Self {
        Self {
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for AnyDeviceClientCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyDeviceClientCertVerifier").finish()
    }
}

impl ClientCertVerifier for AnyDeviceClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA to hint at.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        // No DeviceId is needed here, only that the certificate is a
        // well-formed P-256 device certificate (DCR-040): any device is
        // welcome at this layer.
        identity_point(end_entity.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }
}

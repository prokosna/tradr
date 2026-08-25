//! The self-signed device certificate QUIC's TLS 1.3 presents on
//! `direct-quic`, `holepunch-quic` and `wifi-direct` (docs/05-security.md,
//! "Why there are two encryption layers"). Every field but the
//! `SubjectPublicKeyInfo` is a fixed constant, needing no `Clock`, no `Rng`.

use std::fmt;

use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP_256_R_1};
use der::asn1::{Any, BitString, ObjectIdentifier, UtcTime};
use der::{DateTime, Decode, Encode};
use p256::PublicKey;
use p256::ecdsa::Signature as EcdsaSignature;
use tradr_core::{DomainTag, KeyStore, KeyStoreError, PUBLIC_KEY_POINT_LEN, PublicKeyPoint};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// The certificate's issuer and subject, byte-identical and constant on
/// every device (docs/05-security.md): the `SubjectPublicKeyInfo` stays
/// the only place a device's identity appears.
const SUBJECT: &str = "CN=Tradr Device";

/// An error building or reading a self-signed device certificate. Never
/// names the bytes it refused (rule F4): every variant is either a
/// wrapped parser error with no application-level content, or a bare tag.
#[derive(Debug)]
pub enum CertificateError {
    /// The input is not a well-formed DER X.509 certificate.
    Malformed(der::Error),
    /// This device's own certificate could not be encoded. Unreachable with
    /// the constants this module fixes; present so a construction failure is
    /// not reported as a parse failure of an input there is none of.
    Encoding(der::Error),
    /// The `SubjectPublicKeyInfo`'s algorithm is not `id-ecPublicKey` over
    /// `prime256v1`.
    NotP256,
    /// The subject public key is not exactly 65 bytes tagged `0x04`.
    NotUncompressedPoint,
    /// The subject public key is not a point on the P-256 curve.
    PointNotOnCurve,
    /// The `KeyStore` failed to report the device's identity or to sign.
    KeyStore(KeyStoreError),
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "not a well-formed DER X.509 certificate: {e}"),
            Self::Encoding(e) => write!(f, "could not encode this device's certificate: {e}"),
            Self::NotP256 => write!(
                f,
                "subject public key info is not id-ecPublicKey over prime256v1"
            ),
            Self::NotUncompressedPoint => {
                write!(f, "subject public key is not a 65-byte uncompressed point")
            }
            Self::PointNotOnCurve => write!(f, "subject public key is not on the P-256 curve"),
            Self::KeyStore(e) => write!(f, "key store error: {e}"),
        }
    }
}

impl std::error::Error for CertificateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(e) | Self::Encoding(e) => Some(e),
            Self::KeyStore(e) => Some(e),
            Self::NotP256 | Self::NotUncompressedPoint | Self::PointNotOnCurve => None,
        }
    }
}

// AlgorithmIdentifier for ecdsa-with-SHA256: RFC 5758 requires the
// parameters field to be absent, and this same value names both the TBS
// signature field and the outer signatureAlgorithm.
fn ecdsa_with_sha_256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA_256,
        parameters: None,
    }
}

/// Builds the self-signed device certificate: `SubjectPublicKeyInfo` holds
/// `key_store`'s identity public key, and the `TBSCertificate` is signed
/// under `DomainTag::CertificateTbs` (docs/05-security.md, "Why there are
/// two encryption layers"). Every other field is the constant this module
/// fixes.
pub fn build_self_signed(key_store: &dyn KeyStore) -> Result<Vec<u8>, CertificateError> {
    let identity = key_store
        .public_identity()
        .map_err(CertificateError::KeyStore)?;

    let name: Name = SUBJECT.parse().map_err(CertificateError::Encoding)?;

    let subject_public_key_info = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(Any::from(SECP_256_R_1)),
        },
        subject_public_key: BitString::from_bytes(identity.identity_pub().as_bytes())
            .map_err(CertificateError::Encoding)?,
    };

    // The fixed window docs/05-security.md settles on: nothing validates
    // this certificate as a chain, so a narrow window would only be a
    // field nothing reads until it silently starts refusing connections.
    let not_before = DateTime::new(2020, 1, 1, 0, 0, 0).map_err(CertificateError::Encoding)?;
    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_date_time(not_before).map_err(CertificateError::Encoding)?,
        ),
        not_after: Time::INFINITY,
    };

    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1]).map_err(CertificateError::Encoding)?,
        signature: ecdsa_with_sha_256(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    let tbs_der = tbs_certificate
        .to_der()
        .map_err(CertificateError::Encoding)?;

    // `CertificateTbs`'s separation is `Required(&[0x30])`: it refuses a
    // message not already starting with the DER SEQUENCE tag rather than
    // prepending one, so the bytes signed are exactly the bytes carried.
    let raw_signature = key_store
        .sign(DomainTag::CertificateTbs, &tbs_der)
        .map_err(CertificateError::KeyStore)?;
    let ecdsa_signature = EcdsaSignature::from_slice(raw_signature.as_bytes())
        .map_err(|e| CertificateError::KeyStore(KeyStoreError::Backend(Box::new(e))))?;
    let signature = BitString::from_bytes(ecdsa_signature.to_der().as_bytes())
        .map_err(CertificateError::Encoding)?;

    let certificate = Certificate {
        tbs_certificate,
        signature_algorithm: ecdsa_with_sha_256(),
        signature,
    };

    certificate.to_der().map_err(CertificateError::Encoding)
}

/// Reads the identity public key out of a certificate `build_self_signed`
/// produced. Does not verify the certificate's self-signature: nothing
/// here authenticates a peer, since TLS 1.3's `CertificateVerify` does
/// that against this same `SubjectPublicKeyInfo` (WI-M1-003).
pub fn identity_point(certificate_der: &[u8]) -> Result<PublicKeyPoint, CertificateError> {
    let certificate =
        Certificate::from_der(certificate_der).map_err(CertificateError::Malformed)?;
    let spki = &certificate.tbs_certificate.subject_public_key_info;

    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(CertificateError::NotP256);
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.decode_as::<ObjectIdentifier>().ok());
    if curve != Some(SECP_256_R_1) {
        return Err(CertificateError::NotP256);
    }

    let point_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CertificateError::NotUncompressedPoint)?;
    if point_bytes.len() != PUBLIC_KEY_POINT_LEN || point_bytes[0] != 0x04 {
        return Err(CertificateError::NotUncompressedPoint);
    }

    // The length-and-tag check above must run first: `from_sec1_bytes`
    // also accepts a compressed point, so it cannot be what tells the two
    // refusals apart.
    PublicKey::from_sec1_bytes(point_bytes).map_err(|_| CertificateError::PointNotOnCurve)?;

    Ok(PublicKeyPoint::from_bytes(point_bytes)
        .expect("length and leading tag were just checked to match PublicKeyPoint's encoding"))
}

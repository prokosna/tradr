//! Wraps a `KeyStore` as rustls's external signer for TLS 1.3's
//! `CertificateVerify` (docs/05-security.md, "A key store is shared, and
//! the implementations pay for it"; DCR-041, ADR-0011). No private key
//! byte ever passes through this module: every signature is produced by
//! `KeyStore::sign`.

use std::fmt;
use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm};
use tradr_core::{DomainTag, KeyStore};

/// The one scheme this deployment signs with (ADR-0012): P-256 with
/// SHA-256, matching the curve `tradr-identity` generates and the curve
/// `certificate.rs` puts in the `SubjectPublicKeyInfo`.
const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

/// A `rustls::sign::SigningKey` backed by a `KeyStore`. `Send + Sync`
/// because DCR-041 makes that part of what a `KeyStore` is, and rustls
/// holds this behind `Arc<dyn SigningKey>` for the life of a config.
pub(crate) struct KeyStoreSigningKey {
    key_store: Arc<dyn KeyStore>,
}

// `KeyStore` itself carries no `Debug` impl, and printing key material
// would violate rule F4 regardless: both types name only themselves.
impl fmt::Debug for KeyStoreSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStoreSigningKey").finish()
    }
}

impl KeyStoreSigningKey {
    pub(crate) fn new(key_store: Arc<dyn KeyStore>) -> Self {
        Self { key_store }
    }
}

impl SigningKey for KeyStoreSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SCHEME).then(|| {
            Box::new(KeyStoreSigner {
                key_store: self.key_store.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct KeyStoreSigner {
    key_store: Arc<dyn KeyStore>,
}

impl fmt::Debug for KeyStoreSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStoreSigner").finish()
    }
}

impl Signer for KeyStoreSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        // `message` is RFC 8446 4.4.3's whole CertificateVerify content:
        // 64 spaces, the context string, a 0x00 separator, then the
        // transcript hash. `DomainTag::TlsCertificateVerify`'s separation
        // is `Required` on exactly that prefix, so nothing is prepended.
        let signature = self
            .key_store
            .sign(DomainTag::TlsCertificateVerify, message)
            .map_err(|e| RustlsError::General(e.to_string()))?;

        // The KeyStore returns 64 raw bytes of r || s; rustls expects the
        // scheme's own encoding, DER, the same conversion certificate.rs
        // already performs for the self-signed certificate's signature.
        let raw = p256::ecdsa::Signature::from_slice(signature.as_bytes())
            .map_err(|e| RustlsError::General(e.to_string()))?;
        Ok(raw.to_der().as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

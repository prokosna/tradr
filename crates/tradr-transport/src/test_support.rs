use std::sync::Arc;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use tradr_core::{
    Backing, DeviceId, DomainTag, KeyStore, KeyStoreError, PublicIdentity, PublicKeyPoint,
    SharedSecret, Signature, SoftwareReason,
};

#[derive(Debug)]
pub(crate) struct TestKeyStore {
    identity_key: SigningKey,
    agreement_key: SecretKey,
}

impl TestKeyStore {
    pub(crate) fn with_scalars(identity: [u8; 32], agreement: [u8; 32]) -> Self {
        Self {
            identity_key: SigningKey::from_slice(&identity).expect("a fixed valid P-256 scalar"),
            agreement_key: SecretKey::from_slice(&agreement).expect("a fixed valid P-256 scalar"),
        }
    }

    pub(crate) fn identity_point(&self) -> PublicKeyPoint {
        let point = self.identity_key.verifying_key().to_encoded_point(false);
        PublicKeyPoint::from_bytes(point.as_bytes()).expect("p256 writes 65 bytes uncompressed")
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

pub(crate) fn device(seed: u8) -> Arc<TestKeyStore> {
    Arc::new(TestKeyStore::with_scalars(
        [seed; 32],
        [seed.wrapping_add(0x40); 32],
    ))
}

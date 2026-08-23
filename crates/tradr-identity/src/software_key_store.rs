//! An in-memory `KeyStore` over P-256 (ADR-0011, ADR-0012). Persisting the
//! keys through a platform secure element or keyring is WI-M0-007b's job;
//! this type only generates, signs and agrees, entirely from the injected
//! `Rng` and entirely in process memory.

use std::fmt;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};

use tradr_core::{
    Backing, DEVICE_ID_LEN, DeviceId, DomainTag, KeyStore, KeyStoreError, PublicIdentity,
    PublicKeyPoint, Rng, SharedSecret, Signature, SoftwareReason,
};

/// A `KeyStore` holding its P-256 identity and agreement keys in process
/// memory. `Debug` intentionally prints no field: the public half is
/// reachable through `public_identity`, and nothing else should leave this
/// type through a log line.
pub struct SoftwareKeyStore {
    identity_key: SigningKey,
    agreement_key: SecretKey,
}

impl SoftwareKeyStore {
    /// Generates a fresh identity key and a fresh, distinct agreement key,
    /// drawing every byte of randomness from `rng`. Fails rather than
    /// falling back to any other entropy source when `rng` cannot supply
    /// bytes.
    pub fn generate(rng: &dyn Rng) -> Result<Self, KeyStoreError> {
        let identity_key = SigningKey::from(random_secret_key(rng)?);
        let agreement_key = random_secret_key(rng)?;
        Ok(Self {
            identity_key,
            agreement_key,
        })
    }
}

impl fmt::Debug for SoftwareKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKeyStore").finish()
    }
}

/// Draws stop after this many rejected scalars. A uniform draw falls
/// outside the field with probability about 2^-32, so this many
/// consecutive rejections from a working source will not happen in this
/// project's lifetime; reaching the bound means the source is stuck, not
/// unlucky.
const SCALAR_DRAW_LIMIT: usize = 16;

/// Draws a valid P-256 non-zero scalar from `rng` by rejection sampling,
/// consuming fresh bytes from `rng` on each retry. Bounded: an `Rng` that
/// keeps succeeding but never returns a byte string P-256 accepts (an
/// all-zero buffer, for instance) must not hang the caller forever.
fn random_secret_key(rng: &dyn Rng) -> Result<SecretKey, KeyStoreError> {
    for _ in 0..SCALAR_DRAW_LIMIT {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes)
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return Ok(key);
        }
    }
    Err(KeyStoreError::Backend(Box::new(RngExhausted)))
}

/// The retry bound in `random_secret_key` was reached: `rng` kept
/// returning `Ok`, but never a byte string P-256 accepts.
#[derive(Debug)]
struct RngExhausted;

impl fmt::Display for RngExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rng produced {SCALAR_DRAW_LIMIT} draws with no valid P-256 scalar; treating it as stuck rather than unlucky"
        )
    }
}

impl std::error::Error for RngExhausted {}

/// Converts a SEC-1 encoded point's bytes into a `PublicKeyPoint`, which
/// only fails on the wrong length. That length is fixed by the curve, so a
/// failure here would mean the `p256` encoding changed underneath us.
fn public_key_point(bytes: &[u8]) -> Result<PublicKeyPoint, KeyStoreError> {
    PublicKeyPoint::from_bytes(bytes).map_err(|e| KeyStoreError::Backend(Box::new(e)))
}

impl KeyStore for SoftwareKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        let identity_point = self.identity_key.verifying_key().to_encoded_point(false);
        let identity_pub = public_key_point(identity_point.as_bytes())?;

        let agreement_point = self.agreement_key.public_key().to_encoded_point(false);
        let agreement_pub = public_key_point(agreement_point.as_bytes())?;

        let hash = blake3::hash(identity_pub.as_bytes());
        let device_id = DeviceId::from_bytes(&hash.as_bytes()[..DEVICE_ID_LEN])
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;

        Ok(PublicIdentity::new(identity_pub, agreement_pub, device_id))
    }

    fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError> {
        let mut payload = domain.prefix().to_vec();
        payload.extend_from_slice(message);

        // RFC 6979 deterministic signing: the nonce comes from the private
        // key and the message, never from `rng`. See docs/05-security.md.
        let raw: EcdsaSignature = self
            .identity_key
            .try_sign(&payload)
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let normalized = raw.normalize_s().unwrap_or(raw);

        Ok(Signature::from_bytes(normalized.to_bytes().to_vec()))
    }

    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        let peer_key = PublicKey::from_sec1_bytes(peer_public.as_bytes())
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let shared = p256::ecdh::diffie_hellman(
            self.agreement_key.to_nonzero_scalar(),
            peer_key.as_affine(),
        );
        Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
    }

    fn backing(&self) -> Backing {
        // This crate never attempts a secure element (that begins at
        // WI-M0-007b), and on this milestone's Linux target there is no
        // secure element category to fall back from (ADR-0012).
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    }
}

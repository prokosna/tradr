//! An in-memory `KeyStore` over P-256 (ADR-0011, ADR-0012), with an
//! optional load-or-generate policy over a `SecretStore` (WI-M0-007b).
//! The two real Linux `SecretStore` backends, Secret Service and a
//! `0600` file, are WI-M0-007d/e; this type generates, signs, agrees,
//! and persists through whatever `SecretStore` it is given.

use std::fmt;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{FieldBytes, PublicKey, SecretKey};

use tradr_core::{
    Backing, DEVICE_ID_LEN, DeviceId, DomainTag, KeyStore, KeyStoreError, PublicIdentity,
    PublicKeyPoint, Rng, SecretStore, SharedSecret, Signature, SoftwareReason, StorageLevel,
};

/// The stored form's version byte. A stored value carrying any other byte
/// is refused rather than misread as a key, which is what keeps a future
/// format change from being mistaken for one of today's keys.
const STORED_FORMAT_VERSION: u8 = 1;

/// The byte length of one P-256 scalar.
const SCALAR_LEN: usize = 32;

/// The stored form's total length: the version byte, the identity scalar,
/// then the agreement scalar.
const STORED_LEN: usize = 1 + SCALAR_LEN + SCALAR_LEN;

/// A `KeyStore` holding its P-256 identity and agreement keys in process
/// memory. `Debug` intentionally prints no field: the public half is
/// reachable through `public_identity`, and nothing else should leave this
/// type through a log line.
pub struct SoftwareKeyStore {
    identity_key: SigningKey,
    agreement_key: SecretKey,
    backing: Backing,
}

impl SoftwareKeyStore {
    /// Generates a fresh identity key and a fresh, distinct agreement key,
    /// drawing every byte of randomness from `rng`. Fails rather than
    /// falling back to any other entropy source when `rng` cannot supply
    /// bytes. Backed by no `SecretStore`, so nothing is written anywhere.
    pub fn generate(rng: &dyn Rng) -> Result<Self, KeyStoreError> {
        let identity_key = SigningKey::from(random_secret_key(rng)?);
        let agreement_key = random_secret_key(rng)?;
        Ok(Self {
            identity_key,
            agreement_key,
            backing: Backing::Software(SoftwareReason::PlatformHasNoSecureElement),
        })
    }

    /// Loads the device key from `slot` in `store`, or generates and
    /// stores one if `slot` is empty. A load that fails is an error,
    /// never treated as an empty slot: that would overwrite an identity
    /// that was merely unreachable. A stored value present but
    /// unparseable is likewise an error, leaving the store untouched.
    pub fn open(store: &dyn SecretStore, slot: &str, rng: &dyn Rng) -> Result<Self, KeyStoreError> {
        let loaded = store
            .load(slot)
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let backing = backing_for_level(store.level());

        if let Some(bytes) = loaded {
            let (identity_key, agreement_key) = decode_stored(&bytes)?;
            return Ok(Self {
                identity_key,
                agreement_key,
                backing,
            });
        }

        let identity_key = SigningKey::from(random_secret_key(rng)?);
        let agreement_key = random_secret_key(rng)?;
        store
            .store(slot, &encode_stored(&identity_key, &agreement_key))
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;

        Ok(Self {
            identity_key,
            agreement_key,
            backing,
        })
    }
}

impl fmt::Debug for SoftwareKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKeyStore").finish()
    }
}

// What `backing()` reports for a `SoftwareKeyStore` opened at `level`.
// Reaching the Secret Service is a different sentence from falling past
// it to a file (docs/05-security.md, "Key storage"), even though both
// Linux levels are software: neither keeps the key from coming back
// into this process to be used.
fn backing_for_level(level: StorageLevel) -> Backing {
    let reason = match level {
        StorageLevel::SecretService => SoftwareReason::PlatformHasNoSecureElement,
        StorageLevel::File => SoftwareReason::NoSecretService,
    };
    Backing::Software(reason)
}

// Serializes both scalars into the stored form: a version byte, the
// identity scalar, then the agreement scalar, in that fixed order.
fn encode_stored(identity_key: &SigningKey, agreement_key: &SecretKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STORED_LEN);
    bytes.push(STORED_FORMAT_VERSION);
    bytes.extend_from_slice(&identity_key.to_bytes());
    bytes.extend_from_slice(&agreement_key.to_bytes());
    bytes
}

// Parses the stored form, refusing any length or version that does not
// match exactly rather than misreading it as a key.
fn decode_stored(bytes: &[u8]) -> Result<(SigningKey, SecretKey), KeyStoreError> {
    if bytes.len() != STORED_LEN {
        return Err(KeyStoreError::Backend(Box::new(
            StoredKeyError::WrongLength(bytes.len()),
        )));
    }
    if bytes[0] != STORED_FORMAT_VERSION {
        return Err(KeyStoreError::Backend(Box::new(
            StoredKeyError::UnknownVersion(bytes[0]),
        )));
    }

    let identity_bytes = FieldBytes::from_slice(&bytes[1..1 + SCALAR_LEN]);
    let identity_key =
        SigningKey::from_bytes(identity_bytes).map_err(|e| KeyStoreError::Backend(Box::new(e)))?;

    let agreement_key = SecretKey::from_slice(&bytes[1 + SCALAR_LEN..])
        .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;

    Ok((identity_key, agreement_key))
}

/// The stored form failed to parse: the wrong length or an unrecognized
/// version byte.
#[derive(Debug)]
enum StoredKeyError {
    /// The value's length was not exactly `STORED_LEN`.
    WrongLength(usize),
    /// The version byte was not `STORED_FORMAT_VERSION`.
    UnknownVersion(u8),
}

impl fmt::Display for StoredKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "stored key must be {STORED_LEN} bytes, got {len}")
            }
            Self::UnknownVersion(v) => write!(f, "stored key has unknown format version {v}"),
        }
    }
}

impl std::error::Error for StoredKeyError {}

/// Draws stop after this many rejected scalars. A uniform draw falls
/// outside the field with probability about 2^-32, so this many
/// consecutive rejections from a working source will not happen in this
/// project's lifetime; reaching the bound means the source is stuck, not
/// unlucky.
const SCALAR_DRAW_LIMIT: usize = 16;

// Draws a valid P-256 non-zero scalar from `rng` by rejection sampling,
// consuming fresh bytes from `rng` on each retry. Bounded: an `Rng` that
// keeps succeeding but never returns a byte string P-256 accepts (an
// all-zero buffer, for instance) must not hang the caller forever.
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

// Converts a SEC-1 encoded point's bytes into a `PublicKeyPoint`, which
// only fails on the wrong length. That length is fixed by the curve, so a
// failure here would mean the `p256` encoding changed underneath us.
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
        let payload = domain
            .payload(message)
            .map_err(KeyStoreError::DomainSeparation)?;

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
        self.backing
    }
}

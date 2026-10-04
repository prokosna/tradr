//! HPKE base mode implementation (RFC 9180, ADR-0025, DCR-173).
//!
//! Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use tradr_core::{KeyStoreError, PublicKeyPoint, Rng, RngError, SharedSecret};

// HPKE ciphersuite identifier constants from RFC 9180 Section 7.
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x10";
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x03";
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

// Drawing bound to prevent unbounded loops if entropy source stalls.
const SCALAR_DRAW_LIMIT: usize = 16;

/// Errors produced by HPKE operations.
#[derive(Debug)]
pub enum HpkeError {
    /// Decryption or authentication verification of ciphertext failed.
    OpenFailed,
    /// Ciphertext sealing failed.
    SealFailed,
    /// A public key point is not a valid uncompressed point on the P-256 curve.
    InvalidPoint,
    /// A private key scalar is not a valid non-zero P-256 scalar.
    InvalidScalar,
    /// Diffie-Hellman key agreement failed in the underlying key store.
    Agreement(KeyStoreError),
    /// The agreed shared secret length is unexpected for this suite.
    InvalidSharedSecretLength(usize),
    /// Random number generation failed.
    Rng(RngError),
    /// The RNG failed to produce a valid P-256 scalar within the retry bound.
    RngExhausted,
    /// Key derivation function failed.
    KdfFailed,
    /// Requested exporter length exceeds the protocol maximum.
    ExportLengthTooLarge,
    /// AEAD sequence number limit has been reached for this context.
    MessageLimitReached,
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenFailed => write!(f, "hpke open failed: ciphertext authentication error"),
            Self::SealFailed => write!(f, "hpke seal failed: ciphertext encryption error"),
            Self::InvalidPoint => write!(f, "invalid P-256 public key point"),
            Self::InvalidScalar => write!(f, "invalid P-256 private scalar"),
            Self::Agreement(e) => write!(f, "hpke agreement failed: {e}"),
            Self::InvalidSharedSecretLength(len) => {
                write!(f, "hpke agreement returned {len} bytes, expected 32")
            }
            Self::Rng(e) => write!(f, "hpke rng failed: {e}"),
            Self::RngExhausted => write!(
                f,
                "rng failed to produce a valid P-256 scalar within {SCALAR_DRAW_LIMIT} attempts"
            ),
            Self::KdfFailed => write!(f, "hpke key derivation failed"),
            Self::ExportLengthTooLarge => write!(f, "hpke export length exceeds maximum limit"),
            Self::MessageLimitReached => write!(f, "hpke message sequence limit reached"),
        }
    }
}

impl std::error::Error for HpkeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Agreement(e) => Some(e),
            Self::Rng(e) => Some(e),
            _ => None,
        }
    }
}

/// Sender context for sealing messages and exporting secrets in HPKE base mode.
pub struct SenderContext {
    key: [u8; 32],
    base_nonce: [u8; 12],
    seq: u64,
    exporter_secret: [u8; 32],
    overflowed: bool,
}

impl fmt::Debug for SenderContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SenderContext")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl SenderContext {
    /// Encrypts and authenticates plaintext with associated data.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
        if self.overflowed {
            return Err(HpkeError::MessageLimitReached);
        }
        let nonce = self.compute_nonce()?;
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        let payload = Payload { msg: pt, aad };
        let ct = match cipher.encrypt(Nonce::from_slice(&nonce), payload) {
            Ok(c) => c,
            Err(_) => return Err(HpkeError::SealFailed),
        };
        self.increment_seq()?;
        Ok(ct)
    }

    /// Exports a secret derived from the exporter secret and context.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, HpkeError> {
        labeled_expand(
            HPKE_SUITE_ID,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }

    // Computes per-message nonce by XORing base nonce with sequence number bytes.
    fn compute_nonce(&self) -> Result<[u8; 12], HpkeError> {
        if self.overflowed {
            return Err(HpkeError::MessageLimitReached);
        }
        let mut nonce = self.base_nonce;
        let seq_be = self.seq.to_be_bytes();
        for (i, b) in seq_be.iter().enumerate() {
            nonce[4 + i] ^= *b;
        }
        Ok(nonce)
    }

    // Advances sequence number, catching counter overflow.
    fn increment_seq(&mut self) -> Result<(), HpkeError> {
        if self.seq == u64::MAX {
            self.overflowed = true;
            return Err(HpkeError::MessageLimitReached);
        }
        self.seq += 1;
        Ok(())
    }
}

/// Receiver context for opening messages and exporting secrets in HPKE base mode.
pub struct ReceiverContext {
    key: [u8; 32],
    base_nonce: [u8; 12],
    seq: u64,
    exporter_secret: [u8; 32],
    overflowed: bool,
}

impl fmt::Debug for ReceiverContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiverContext")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl ReceiverContext {
    /// Decrypts and authenticates ciphertext with associated data.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
        if self.overflowed {
            return Err(HpkeError::MessageLimitReached);
        }
        let nonce = self.compute_nonce()?;
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        let payload = Payload { msg: ct, aad };
        let pt = match cipher.decrypt(Nonce::from_slice(&nonce), payload) {
            Ok(p) => p,
            Err(_) => return Err(HpkeError::OpenFailed),
        };
        self.increment_seq()?;
        Ok(pt)
    }

    /// Exports a secret derived from the exporter secret and context.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, HpkeError> {
        labeled_expand(
            HPKE_SUITE_ID,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }

    // Computes per-message nonce by XORing base nonce with sequence number bytes.
    fn compute_nonce(&self) -> Result<[u8; 12], HpkeError> {
        if self.overflowed {
            return Err(HpkeError::MessageLimitReached);
        }
        let mut nonce = self.base_nonce;
        let seq_be = self.seq.to_be_bytes();
        for (i, b) in seq_be.iter().enumerate() {
            nonce[4 + i] ^= *b;
        }
        Ok(nonce)
    }

    // Advances sequence number, catching counter overflow.
    fn increment_seq(&mut self) -> Result<(), HpkeError> {
        if self.seq == u64::MAX {
            self.overflowed = true;
            return Err(HpkeError::MessageLimitReached);
        }
        self.seq += 1;
        Ok(())
    }
}

// Validates that a byte slice represents an uncompressed curve point.
fn parse_uncompressed_point(bytes: &[u8]) -> Result<p256::PublicKey, HpkeError> {
    if bytes.first() != Some(&0x04) {
        return Err(HpkeError::InvalidPoint);
    }
    match p256::PublicKey::from_sec1_bytes(bytes) {
        Ok(pk) => Ok(pk),
        Err(_) => Err(HpkeError::InvalidPoint),
    }
}

// RFC 9180 Section 4: LabeledExtract(salt, label, ikm)
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, &labeled_ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

// RFC 9180 Section 4: LabeledExpand(prk, label, info, L)
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, HpkeError> {
    if len > 255 * 32 {
        return Err(HpkeError::ExportLengthTooLarge);
    }
    let len_u16 = match u16::try_from(len) {
        Ok(v) => v,
        Err(_) => return Err(HpkeError::ExportLengthTooLarge),
    };
    let mut labeled_info = Vec::with_capacity(
        2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&len_u16.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let hk = match Hkdf::<Sha256>::from_prk(prk) {
        Ok(h) => h,
        Err(_) => return Err(HpkeError::KdfFailed),
    };
    let mut okm = vec![0u8; len];
    if hk.expand(&labeled_info, &mut okm).is_err() {
        return Err(HpkeError::KdfFailed);
    }
    Ok(okm)
}

// RFC 9180 Section 4: LabeledExpand specialized for 32-byte outputs.
fn labeled_expand_32(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
) -> Result<[u8; 32], HpkeError> {
    let bytes = labeled_expand(suite_id, prk, label, info, 32)?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(HpkeError::KdfFailed);
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

// RFC 9180 Section 4: LabeledExpand specialized for 12-byte outputs.
fn labeled_expand_12(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
) -> Result<[u8; 12], HpkeError> {
    let bytes = labeled_expand(suite_id, prk, label, info, 12)?;
    let mut out = [0u8; 12];
    if bytes.len() != 12 {
        return Err(HpkeError::KdfFailed);
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Key schedule outputs: encryption key, base nonce, and exporter secret.
struct KeyScheduleMaterial {
    key: [u8; 32],
    base_nonce: [u8; 12],
    exporter_secret: [u8; 32],
}

// RFC 9180 Section 5.1: KeySchedule base mode.
fn key_schedule(shared_secret: &[u8; 32], info: &[u8]) -> Result<KeyScheduleMaterial, HpkeError> {
    let psk_id_hash = labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info);

    let mut key_schedule_context = [0u8; 1 + 32 + 32];
    key_schedule_context[0] = 0x00;
    key_schedule_context[1..33].copy_from_slice(&psk_id_hash);
    key_schedule_context[33..65].copy_from_slice(&info_hash);

    let secret = labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"");

    let key = labeled_expand_32(HPKE_SUITE_ID, &secret, b"key", &key_schedule_context)?;
    let base_nonce =
        labeled_expand_12(HPKE_SUITE_ID, &secret, b"base_nonce", &key_schedule_context)?;
    let exporter_secret = labeled_expand_32(HPKE_SUITE_ID, &secret, b"exp", &key_schedule_context)?;

    Ok(KeyScheduleMaterial {
        key,
        base_nonce,
        exporter_secret,
    })
}

/// Sets up an HPKE base mode sender context with an explicit ephemeral private key scalar.
pub fn setup_base_sender_with_ephemeral(
    pk_r: &PublicKeyPoint,
    sk_e: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 65], SenderContext), HpkeError> {
    let pk_r_parsed = parse_uncompressed_point(pk_r.as_bytes())?;
    let sk_e_parsed = match p256::SecretKey::from_slice(sk_e) {
        Ok(k) => k,
        Err(_) => return Err(HpkeError::InvalidScalar),
    };

    let pk_e = sk_e_parsed.public_key();
    let enc_point = pk_e.to_encoded_point(false);
    let mut enc = [0u8; 65];
    if enc_point.as_bytes().len() != 65 {
        return Err(HpkeError::InvalidPoint);
    }
    enc.copy_from_slice(enc_point.as_bytes());

    let shared =
        p256::ecdh::diffie_hellman(sk_e_parsed.to_nonzero_scalar(), pk_r_parsed.as_affine());
    let dh_bytes = shared.raw_secret_bytes();

    let mut kem_context = [0u8; 130];
    kem_context[..65].copy_from_slice(&enc);
    kem_context[65..].copy_from_slice(pk_r.as_bytes());

    let eae_prk = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh_bytes.as_slice());
    let shared_secret = labeled_expand_32(KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context)?;

    let material = key_schedule(&shared_secret, info)?;

    Ok((
        enc,
        SenderContext {
            key: material.key,
            base_nonce: material.base_nonce,
            seq: 0,
            exporter_secret: material.exporter_secret,
            overflowed: false,
        },
    ))
}

/// Sets up an HPKE base mode sender context, drawing ephemeral key entropy from `rng`.
pub fn setup_base_sender(
    pk_r: &PublicKeyPoint,
    rng: &dyn Rng,
    info: &[u8],
) -> Result<([u8; 65], SenderContext), HpkeError> {
    for _ in 0..SCALAR_DRAW_LIMIT {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes).map_err(HpkeError::Rng)?;
        if p256::SecretKey::from_slice(&bytes).is_ok() {
            return setup_base_sender_with_ephemeral(pk_r, &bytes, info);
        }
    }
    Err(HpkeError::RngExhausted)
}

/// Sets up an HPKE base mode receiver context from encapsulated key `enc`.
pub fn setup_base_receiver(
    enc: &[u8; 65],
    pk_r: &PublicKeyPoint,
    info: &[u8],
    agree: &dyn Fn(&PublicKeyPoint) -> Result<SharedSecret, KeyStoreError>,
) -> Result<ReceiverContext, HpkeError> {
    if parse_uncompressed_point(enc).is_err() {
        return Err(HpkeError::InvalidPoint);
    }
    if parse_uncompressed_point(pk_r.as_bytes()).is_err() {
        return Err(HpkeError::InvalidPoint);
    }

    let enc_point = match PublicKeyPoint::from_bytes(enc) {
        Ok(p) => p,
        Err(_) => return Err(HpkeError::InvalidPoint),
    };
    let shared_secret_dh = agree(&enc_point).map_err(HpkeError::Agreement)?;
    let dh_bytes = shared_secret_dh.as_bytes();
    if dh_bytes.len() != 32 {
        return Err(HpkeError::InvalidSharedSecretLength(dh_bytes.len()));
    }

    let mut kem_context = [0u8; 130];
    kem_context[..65].copy_from_slice(enc);
    kem_context[65..].copy_from_slice(pk_r.as_bytes());

    let eae_prk = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh_bytes);
    let shared_secret = labeled_expand_32(KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context)?;

    let material = key_schedule(&shared_secret, info)?;

    Ok(ReceiverContext {
        key: material.key,
        base_nonce: material.base_nonce,
        seq: 0,
        exporter_secret: material.exporter_secret,
        overflowed: false,
    })
}

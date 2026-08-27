//! Content integrity types. See `docs/04-protocol.md`, "A piece is
//! verified before it is written", and [ADR-0006](../../../docs/adr/0006-blake3-for-content-integrity.md).
//! `tradr-integrity` implements `ContentVerifier` with `bao` verified
//! streaming; this module only declares what a verified piece is and
//! what checking one means, so `tradr-core` names no hashing crate.

use std::fmt;

/// The BLAKE3 root hash of an item's full content, carried on the wire as
/// `Item.content_hash`. A piece is checked against it, at the piece's
/// absolute offset, before the piece is written anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Builds a `ContentHash` from its 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Why a claimed piece failed to verify against a `ContentHash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    /// The verification path decoded, but not to the content hash, offset
    /// or length claimed for it.
    Mismatch,
    /// The bytes offered were not a well-formed verification path at all.
    Malformed,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch => write!(f, "piece does not verify against the content hash"),
            Self::Malformed => write!(f, "piece is not a well-formed verification path"),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Checks a claimed piece of an item's content against its `ContentHash`.
/// `offset` and `content_len` claim the range `slice` covers; only a
/// `slice` that decodes to exactly `content_len` bytes at `offset` under
/// `hash` is trusted, and its bytes are what `verify` returns.
pub trait ContentVerifier: Send + Sync {
    /// Verifies `slice` as the `[offset, offset + content_len)` range of
    /// the content committed to by `hash`, returning the verified bytes.
    fn verify(
        &self,
        hash: &ContentHash,
        offset: u64,
        content_len: u64,
        slice: &[u8],
    ) -> Result<Vec<u8>, VerificationError>;
}

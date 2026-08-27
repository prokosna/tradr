#![forbid(unsafe_code)]
//! `bao` verified streaming, implementing `tradr-core`'s `ContentVerifier`.
//! See `docs/02-architecture.md`, "Where content verification lives", and
//! [ADR-0006](../../../docs/adr/0006-blake3-for-content-integrity.md). The
//! only crate that may name `bao` (checked by `ci/layer-deps.sh`), so that
//! nowhere else assembles a Merkle path by hand.

use std::fmt;
use std::io::{Cursor, Read};

use tradr_core::{ContentHash, ContentVerifier, VerificationError};

/// Why `slice` could not extract the requested range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceError {
    /// The requested `[offset, offset + len)` range extends beyond the
    /// content `slice` was asked to extract from.
    OutOfRange,
    /// `bao`'s extractor failed while reading the content or the outboard.
    Extraction,
}

impl fmt::Display for SliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange => write!(f, "requested range lies outside the content"),
            Self::Extraction => write!(f, "failed to extract the requested range"),
        }
    }
}

impl std::error::Error for SliceError {}

/// Encodes `content` as a `bao` outboard, returning it alongside the
/// BLAKE3 root. The outboard is what makes verified streaming possible
/// without duplicating the content bytes into the encoding itself.
pub fn outboard(content: &[u8]) -> (Vec<u8>, ContentHash) {
    let (outboard, hash) = bao::encode::outboard(content);
    (outboard, ContentHash::from_bytes(*hash.as_bytes()))
}

/// Extracts the `bao` slice covering `[offset, offset + len)` of `content`,
/// given its `outboard`. Refuses a range `content` does not contain rather
/// than handing it to `bao`, whose extractor will otherwise happily walk
/// past the end and hand back a slice that decodes as an empty read.
pub fn slice(
    content: &[u8],
    outboard: &[u8],
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, SliceError> {
    let content_len = content.len() as u64;
    let end = offset.checked_add(len).ok_or(SliceError::OutOfRange)?;
    if end > content_len {
        return Err(SliceError::OutOfRange);
    }

    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        Cursor::new(content),
        Cursor::new(outboard),
        offset,
        len,
    );
    let mut out = Vec::new();
    extractor
        .read_to_end(&mut out)
        .map_err(|_| SliceError::Extraction)?;
    Ok(out)
}

/// A `ContentVerifier` backed by `bao` verified streaming.
pub struct BaoVerifier;

impl ContentVerifier for BaoVerifier {
    fn verify(
        &self,
        hash: &ContentHash,
        offset: u64,
        content_len: u64,
        slice: &[u8],
    ) -> Result<Vec<u8>, VerificationError> {
        let bao_hash = bao::Hash::from_bytes(*hash.as_bytes());
        let mut decoder =
            bao::decode::SliceDecoder::new(Cursor::new(slice), &bao_hash, offset, content_len);

        let mut out = Vec::new();
        let result = decoder.read_to_end(&mut out);
        let consumed = decoder.into_inner().position();
        result.map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => VerificationError::Mismatch,
            _ => VerificationError::Malformed,
        })?;

        // A shorter claimed content_len decodes successfully but leaves
        // part of the slice unread; a claim past the item's end decodes
        // as a valid empty read. Neither is caught by decoding success
        // alone, so both the yielded length and full consumption of the
        // slice are checked before the bytes are trusted.
        if out.len() as u64 != content_len || consumed != slice.len() as u64 {
            return Err(VerificationError::Mismatch);
        }

        Ok(out)
    }
}

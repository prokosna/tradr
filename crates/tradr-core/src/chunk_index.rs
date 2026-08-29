//! An index into an Item's 1 MiB reference chunks. See `docs/04-protocol.md`,
//! "Chunk sizes": chunk boundaries never move when the transport does, so
//! this reference size is what lets a transfer resume across a path switch.

/// The size in bytes of one reference chunk.
pub const REFERENCE_CHUNK_SIZE_BYTES: u64 = 1024 * 1024;

/// A chunk's position within an Item, counted in reference chunks of
/// `REFERENCE_CHUNK_SIZE_BYTES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkIndex(u64);

/// An error computing a `ChunkIndex`'s byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkIndexError {
    /// `index * REFERENCE_CHUNK_SIZE_BYTES` does not fit in a `u64`.
    OffsetOverflow,
}

impl std::fmt::Display for ChunkIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OffsetOverflow => write!(f, "chunk index overflows u64 as a byte offset"),
        }
    }
}

impl std::error::Error for ChunkIndexError {}

impl ChunkIndex {
    /// Builds a `ChunkIndex` from its raw chunk position.
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// Returns the raw chunk position.
    pub fn value(self) -> u64 {
        self.0
    }

    /// Returns the byte offset of this chunk's first byte, returning an
    /// error rather than wrapping when the multiplication overflows `u64`.
    pub fn byte_offset(self) -> Result<u64, ChunkIndexError> {
        self.0
            .checked_mul(REFERENCE_CHUNK_SIZE_BYTES)
            .ok_or(ChunkIndexError::OffsetOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_offset_multiplies_by_the_reference_chunk_size() {
        assert_eq!(ChunkIndex::new(0).byte_offset(), Ok(0));
        assert_eq!(
            ChunkIndex::new(1).byte_offset(),
            Ok(REFERENCE_CHUNK_SIZE_BYTES)
        );
        assert_eq!(
            ChunkIndex::new(3).byte_offset(),
            Ok(3 * REFERENCE_CHUNK_SIZE_BYTES)
        );
    }

    #[test]
    fn byte_offset_errors_instead_of_wrapping_on_overflow() {
        let result = ChunkIndex::new(u64::MAX).byte_offset();

        assert_eq!(result, Err(ChunkIndexError::OffsetOverflow));
    }
}

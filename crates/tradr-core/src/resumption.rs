//! Transfer resumption tracking at reference chunk boundaries.
//!
//! Maintains verified chunk state and sub-chunk piece progress across
//! transport handoffs without binding to concrete I/O mechanisms.

use std::collections::BTreeMap;

use crate::{ChunkIndex, ItemId, REFERENCE_CHUNK_SIZE_BYTES};

/// Errors encountered when recording progress or querying chunk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumptionError {
    /// The requested chunk index exceeds the total chunk count of the item.
    ChunkOutOfBounds {
        /// The invalid chunk index.
        index: ChunkIndex,
        /// Total number of chunks in the item.
        total_chunks: u64,
    },
    /// The piece range extends beyond the boundary of the target chunk.
    PieceOutOfBounds {
        /// The target chunk index.
        index: ChunkIndex,
        /// Byte offset within the chunk.
        offset_in_chunk: u32,
        /// Byte length of the piece payload.
        payload_len: u32,
        /// Expected size of this chunk in bytes.
        chunk_size: u32,
    },
}

impl std::fmt::Display for ResumptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChunkOutOfBounds {
                index,
                total_chunks,
            } => {
                write!(
                    f,
                    "chunk index {} out of bounds for item with {} chunks",
                    index.value(),
                    total_chunks
                )
            }
            Self::PieceOutOfBounds {
                index,
                offset_in_chunk,
                payload_len,
                chunk_size,
            } => {
                write!(
                    f,
                    "piece [{}, {}) out of bounds for chunk {} of size {}",
                    offset_in_chunk,
                    offset_in_chunk.saturating_add(*payload_len),
                    index.value(),
                    chunk_size
                )
            }
        }
    }
}

impl std::error::Error for ResumptionError {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ChunkState {
    verified: bool,
    failed_attempts: u32,
    ranges: Vec<(u32, u32)>,
}

/// Tracks chunk-level reception, verification, and piece assembly for an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemResumption {
    item_id: ItemId,
    total_bytes: u64,
    total_chunks: u64,
    chunks: BTreeMap<u64, ChunkState>,
    verified_chunks_count: u64,
}

impl ItemResumption {
    /// Creates a new resumption tracker for an item of the given byte length.
    pub fn new(item_id: ItemId, total_bytes: u64) -> Self {
        let total_chunks = if total_bytes == 0 {
            0
        } else {
            total_bytes.div_ceil(REFERENCE_CHUNK_SIZE_BYTES)
        };

        Self {
            item_id,
            total_bytes,
            total_chunks,
            chunks: BTreeMap::new(),
            verified_chunks_count: 0,
        }
    }

    /// Returns the unique identifier of the item being tracked.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// Returns the total expected byte length of the item.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns the total number of reference chunks composing the item.
    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    /// Computes the expected byte size of a specific chunk.
    pub fn chunk_size(&self, index: ChunkIndex) -> Result<u32, ResumptionError> {
        if index.value() >= self.total_chunks {
            return Err(ResumptionError::ChunkOutOfBounds {
                index,
                total_chunks: self.total_chunks,
            });
        }

        if index.value() + 1 == self.total_chunks {
            let remainder = self.total_bytes % REFERENCE_CHUNK_SIZE_BYTES;
            if remainder == 0 {
                Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
            } else {
                Ok(remainder as u32)
            }
        } else {
            Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
        }
    }

    /// Records a received sub-chunk piece and reports whether the chunk is complete.
    pub fn record_piece(
        &mut self,
        index: ChunkIndex,
        offset_in_chunk: u32,
        payload_len: u32,
    ) -> Result<bool, ResumptionError> {
        if index.value() >= self.total_chunks {
            return Err(ResumptionError::ChunkOutOfBounds {
                index,
                total_chunks: self.total_chunks,
            });
        }

        let chunk_sz = self.chunk_size(index)?;
        let end_offset = match offset_in_chunk.checked_add(payload_len) {
            Some(end) if end <= chunk_sz => end,
            _ => {
                return Err(ResumptionError::PieceOutOfBounds {
                    index,
                    offset_in_chunk,
                    payload_len,
                    chunk_size: chunk_sz,
                });
            }
        };

        let state = self.chunks.entry(index.value()).or_default();
        if state.verified {
            return Ok(true);
        }

        if payload_len > 0 {
            let mut merged = Vec::with_capacity(state.ranges.len() + 1);
            let mut inserted = false;
            let (mut cur_start, mut cur_end) = (offset_in_chunk, end_offset);

            for &(r_start, r_end) in &state.ranges {
                if r_end < cur_start {
                    merged.push((r_start, r_end));
                } else if r_start > cur_end {
                    if !inserted {
                        merged.push((cur_start, cur_end));
                        inserted = true;
                    }
                    merged.push((r_start, r_end));
                } else {
                    cur_start = cur_start.min(r_start);
                    cur_end = cur_end.max(r_end);
                }
            }

            if !inserted {
                merged.push((cur_start, cur_end));
            }
            state.ranges = merged;
        }

        let is_complete = state.ranges.len() == 1 && state.ranges[0] == (0, chunk_sz);
        Ok(is_complete)
    }

    /// Marks a chunk as cryptographically verified.
    pub fn mark_verified(&mut self, index: ChunkIndex) -> Result<(), ResumptionError> {
        if index.value() >= self.total_chunks {
            return Err(ResumptionError::ChunkOutOfBounds {
                index,
                total_chunks: self.total_chunks,
            });
        }

        let chunk_sz = self.chunk_size(index)?;
        let state = self.chunks.entry(index.value()).or_default();
        if !state.verified {
            state.verified = true;
            state.ranges = vec![(0, chunk_sz)];
            self.verified_chunks_count += 1;
        }

        Ok(())
    }

    /// Resets received chunk state after verification failure and increments retry count.
    pub fn mark_failed(&mut self, index: ChunkIndex) -> Result<u32, ResumptionError> {
        if index.value() >= self.total_chunks {
            return Err(ResumptionError::ChunkOutOfBounds {
                index,
                total_chunks: self.total_chunks,
            });
        }

        let state = self.chunks.entry(index.value()).or_default();
        if state.verified {
            state.verified = false;
            self.verified_chunks_count = self.verified_chunks_count.saturating_sub(1);
        }
        state.ranges.clear();
        state.failed_attempts = state.failed_attempts.saturating_add(1);

        Ok(state.failed_attempts)
    }

    /// Checks whether all byte ranges of a chunk have been received.
    pub fn is_chunk_complete(&self, index: ChunkIndex) -> Result<bool, ResumptionError> {
        if index.value() >= self.total_chunks {
            return Err(ResumptionError::ChunkOutOfBounds {
                index,
                total_chunks: self.total_chunks,
            });
        }

        let chunk_sz = self.chunk_size(index)?;
        if let Some(state) = self.chunks.get(&index.value()) {
            Ok(state.verified || (state.ranges.len() == 1 && state.ranges[0] == (0, chunk_sz)))
        } else {
            Ok(false)
        }
    }

    /// Checks whether a chunk has successfully passed hash verification.
    pub fn is_chunk_verified(&self, index: ChunkIndex) -> Result<bool, ResumptionError> {
        if index.value() >= self.total_chunks {
            return Err(ResumptionError::ChunkOutOfBounds {
                index,
                total_chunks: self.total_chunks,
            });
        }

        if let Some(state) = self.chunks.get(&index.value()) {
            Ok(state.verified)
        } else {
            Ok(false)
        }
    }

    /// Returns true if all chunks are verified or the item is zero bytes.
    pub fn is_item_complete(&self) -> bool {
        self.total_bytes == 0 || self.verified_chunks_count == self.total_chunks
    }

    /// Calculates total non-overlapping verified and partial bytes received.
    pub fn bytes_received(&self) -> u64 {
        let mut total = 0u64;
        for state in self.chunks.values() {
            for &(start, end) in &state.ranges {
                total = total.saturating_add((end - start) as u64);
            }
        }
        total
    }

    /// Selects the next contiguous batch of unverified chunks to request.
    pub fn next_chunk_request(&self, max_count: u32) -> Option<(ChunkIndex, u32)> {
        if max_count == 0 || self.total_chunks == 0 || self.is_item_complete() {
            return None;
        }

        let mut start_unverified = None;
        for idx in 0..self.total_chunks {
            let is_verified = self.chunks.get(&idx).is_some_and(|s| s.verified);
            if !is_verified {
                start_unverified = Some(idx);
                break;
            }
        }

        let from_chunk = start_unverified?;
        let mut count = 0u32;
        while count < max_count && (from_chunk + count as u64) < self.total_chunks {
            let idx = from_chunk + count as u64;
            let is_verified = self.chunks.get(&idx).is_some_and(|s| s.verified);
            if is_verified {
                break;
            }
            count += 1;
        }

        if count == 0 {
            None
        } else {
            Some((ChunkIndex::new(from_chunk), count))
        }
    }

    /// Returns a list of all unverified chunk indices for the item.
    pub fn missing_chunks(&self) -> Vec<ChunkIndex> {
        if self.total_chunks == 0 || self.is_item_complete() {
            return Vec::new();
        }

        let mut missing = Vec::new();
        for idx in 0..self.total_chunks {
            let is_verified = self.chunks.get(&idx).is_some_and(|s| s.verified);
            if !is_verified {
                missing.push(ChunkIndex::new(idx));
            }
        }
        missing
    }
}

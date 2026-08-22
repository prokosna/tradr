#![forbid(unsafe_code)]
//! Layer 0 domain types: `DeviceId`, `TransferId`, `ChunkIndex`, `TrustTier`.
//! Pure data and invariants, depending on nothing beyond `std` (rule B1,
//! invariant I4). Every type here validates bytes another layer produced;
//! none of them hash, generate, or serialize.

mod chunk_index;
mod device_id;
mod transfer_id;
mod trust_tier;

pub use chunk_index::{ChunkIndex, ChunkIndexError, REFERENCE_CHUNK_SIZE_BYTES};
pub use device_id::{DEVICE_ID_LEN, DeviceId, DeviceIdError};
pub use transfer_id::{TransferId, TransferIdError};
pub use trust_tier::{TrustTier, TrustTierError};

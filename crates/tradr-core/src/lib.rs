#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Layer 0 domain types (`DeviceId`, `TransferId`, `ChunkIndex`,
//! `TrustTier`) plus the Layer 1 `Clock`, `Rng`, and `KeyStore` traits.
//! Depends on nothing beyond `std` (rule B1, invariant I4). Domain types
//! here validate bytes another layer produced; the traits declare
//! operations only, and every implementation belongs to Layer 3.

mod chunk_index;
mod clock;
mod device_id;
mod item_id;
mod key_store;
mod rel_path;
mod rng;
mod transfer_id;
mod trust_tier;

pub use chunk_index::{ChunkIndex, ChunkIndexError, REFERENCE_CHUNK_SIZE_BYTES};
pub use clock::{Clock, Monotonic, UnixTime, UnixTimeError};
pub use device_id::{DEVICE_ID_LEN, DeviceId, DeviceIdError};
pub use item_id::{ITEM_ID_MAX_LEN, ItemId, ItemIdError};
pub use key_store::{
    Backing, DomainTag, KeyStore, KeyStoreError, PUBLIC_KEY_POINT_LEN, PublicIdentity,
    PublicKeyPoint, PublicKeyPointError, SharedSecret, Signature, SoftwareReason,
};
pub use rel_path::{REL_PATH_COMPONENT_MAX_LEN, RelPath, RelPathError};
pub use rng::{Rng, RngError};
pub use transfer_id::{TransferId, TransferIdError};
pub use trust_tier::{TrustTier, TrustTierError};

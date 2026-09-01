#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Layer 0 domain types (`DeviceId`, `TransferId`, `ChunkIndex`,
//! `TrustTier`) plus the Layer 1 `Clock`, `Rng`, `KeyStore`, `Vfs`,
//! `SecureChannel`, `Transport` and `DiscoverySource` traits, plus
//! `PeerList`'s pure merge (docs/03). Depends on nothing beyond `std`
//! (rule B1, invariant I4): traits declare operations Layer 3 implements.

mod browse;
mod channel;
mod chunk_index;
mod clock;
mod content;
mod control;
mod data;
mod device_id;
mod discovery;
mod fingerprint;
mod future;
mod hello;
mod item_id;
mod key_store;
mod link;
mod rel_path;
mod resumption;
mod rng;
mod share_id;
mod transfer_id;
mod transport;
mod trust_tier;
mod vfs;

pub use browse::{
    Ack, BrowseCodec, BrowseDomainError, BrowseMessage, Delete, DirListing, FsChange, FsChangeKind,
    FsEvent, ListDir, Mkdir, ReadFile, ReadFileBegin, Rename, Stat, StatResult, Watch, WriteFile,
    WriteMode, handle_browse_stream,
};
pub use channel::{RecvStream, SecureChannel, SendStream, TransportError, TransportId};
pub use chunk_index::{ChunkIndex, ChunkIndexError, REFERENCE_CHUNK_SIZE_BYTES};
pub use clock::{Clock, Monotonic, UnixTime, UnixTimeError};
pub use content::{ContentHash, ContentVerifier, VerificationError};
pub use control::{
    ItemAcceptance, ItemAcceptanceError, OfferItem, OfferItemError, OfferOrigin, OfferOriginError,
    RejectReason, RejectReasonError, TransferAccept, TransferAcceptError, TransferOffer,
    TransferOfferError, TransferReject,
};
pub use data::{
    ChunkDataError, ChunkDataHeader, ChunkRequest, ChunkRerequest, FlowControl, ItemComplete,
    TransferProgress,
};
pub use device_id::{DEVICE_ID_LEN, DeviceId, DeviceIdError};
pub use discovery::{
    Capabilities, DISPLAY_NAME_MAX_LEN, DiscoveryError, DiscoveryEvent, DiscoverySource,
    DisplayName, DisplayNameError, OBSERVATION_KEY_MAX_LEN, ObservationId, ObservationKey,
    ObservationKeyError, Peer, PeerList, PeerListError, PeerObservation, SourceId,
};
pub use fingerprint::{
    FINGERPRINT_ROW_COUNT, FINGERPRINT_WORD_COUNT, FINGERPRINT_WORDS_PER_ROW, Fingerprint,
};
pub use future::BoxFuture;
pub use hello::{
    HELLO_NONCE_LEN, HelloNonce, KeyBinding, NoCommonVersion, PeerHello, PeerHelloAck,
    VersionRange, VersionRangeError, negotiate_version,
};
pub use item_id::{ITEM_ID_MAX_LEN, ItemId, ItemIdError};
pub use key_store::{
    Backing, DomainTag, KeyStore, KeyStoreError, MissingSeparation, PUBLIC_KEY_POINT_LEN,
    PublicIdentity, PublicKeyPoint, PublicKeyPointError, SecretStore, SecretStoreError, Separation,
    SharedSecret, Signature, SoftwareReason, StorageLevel,
};
pub use link::{
    HALF_SECRET_LEN, HalfSecret, INVITE_ID_LEN, InviteId, LINK_ID_LEN, LINK_SECRET_LEN,
    LinkApprove, LinkDecline, LinkDeclineReason, LinkDeclineReasonError, LinkError, LinkId,
    LinkReply, LinkSecret,
};
pub use rel_path::{REL_PATH_COMPONENT_MAX_LEN, RelPath, RelPathError};
pub use resumption::{ItemResumption, ResumptionError};
pub use rng::{Rng, RngError};
pub use share_id::{ShareId, ShareIdError};
pub use transfer_id::{TransferId, TransferIdError};
pub use transport::{Candidate, CandidateError, Incoming, PeerExpectation, Transport};
pub use trust_tier::{TrustTier, TrustTierError};
pub use vfs::{DirEntry, EntryKind, Metadata, ReadAt, RootId, Vfs, VfsError, WriteAt};

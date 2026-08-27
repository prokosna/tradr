//! Layer 0 vocabulary for the Transfer Offer exchange (docs/04-protocol.md,
//! DCR-058). Covers offer manifests, item descriptors, acceptance/rejection
//! messages, and validation rules. Depends only on `std` and this crate's
//! own types (rule B1); wire conversions belong to `tradr-proto`.

use std::collections::HashSet;
use std::fmt;

use crate::chunk_index::REFERENCE_CHUNK_SIZE_BYTES;
use crate::content::ContentHash;
use crate::discovery::DisplayName;
use crate::item_id::ItemId;
use crate::rel_path::RelPath;
use crate::transfer_id::TransferId;

/// The origin of a transfer offer (docs/04, `control.proto`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfferOrigin {
    /// Drag and drop from the host desktop.
    DragDrop,
    /// Shared via Android ACTION_SEND share sheet.
    ShareSheet,
    /// Pulled or requested from a peer's shared root.
    ShareBrowse,
    /// Pasted or shared from the clipboard.
    Clipboard,
}

/// An error converting a wire `i32` to an `OfferOrigin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferOriginError {
    /// The wire value was `OFFER_ORIGIN_UNSPECIFIED` (0).
    Unspecified,
    /// The wire value matches no origin `control.proto` defines.
    Unknown(i32),
}

impl fmt::Display for OfferOriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "offer origin is unspecified"),
            Self::Unknown(value) => write!(f, "offer origin wire value {value} matches no origin"),
        }
    }
}

impl std::error::Error for OfferOriginError {}

impl TryFrom<i32> for OfferOrigin {
    type Error = OfferOriginError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Err(OfferOriginError::Unspecified),
            1 => Ok(Self::DragDrop),
            2 => Ok(Self::ShareSheet),
            3 => Ok(Self::ShareBrowse),
            4 => Ok(Self::Clipboard),
            other => Err(OfferOriginError::Unknown(other)),
        }
    }
}

impl From<OfferOrigin> for i32 {
    fn from(origin: OfferOrigin) -> Self {
        match origin {
            OfferOrigin::DragDrop => 1,
            OfferOrigin::ShareSheet => 2,
            OfferOrigin::ShareBrowse => 3,
            OfferOrigin::Clipboard => 4,
        }
    }
}

/// The reason a peer rejected a transfer offer (docs/04, `control.proto`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// The user explicitly declined the transfer offer.
    UserDeclined,
    /// The receiver lacks sufficient storage space.
    NoSpace,
    /// The transfer exceeds transport or policy limits (e.g. over BLE).
    TooLarge,
    /// The sender or transfer is not trusted.
    NotTrusted,
    /// The receiver is currently busy with another transfer.
    Busy,
}

/// An error converting a wire `i32` to a `RejectReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReasonError {
    /// The wire value was `REJECT_REASON_UNSPECIFIED` (0).
    Unspecified,
    /// The wire value matches no reason `control.proto` defines.
    Unknown(i32),
}

impl fmt::Display for RejectReasonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "reject reason is unspecified"),
            Self::Unknown(value) => write!(f, "reject reason wire value {value} matches no reason"),
        }
    }
}

impl std::error::Error for RejectReasonError {}

impl TryFrom<i32> for RejectReason {
    type Error = RejectReasonError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Err(RejectReasonError::Unspecified),
            1 => Ok(Self::UserDeclined),
            2 => Ok(Self::NoSpace),
            3 => Ok(Self::TooLarge),
            4 => Ok(Self::NotTrusted),
            5 => Ok(Self::Busy),
            other => Err(RejectReasonError::Unknown(other)),
        }
    }
}

impl From<RejectReason> for i32 {
    fn from(reason: RejectReason) -> Self {
        match reason {
            RejectReason::UserDeclined => 1,
            RejectReason::NoSpace => 2,
            RejectReason::TooLarge => 3,
            RejectReason::NotTrusted => 4,
            RejectReason::Busy => 5,
        }
    }
}

/// An error constructing an `OfferItem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferItemError {
    /// The declared size was zero. Zero-byte items have no chunks to request.
    EmptySize,
}

impl fmt::Display for OfferItemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySize => write!(f, "item size must be non-zero"),
        }
    }
}

impl std::error::Error for OfferItemError {}

/// A single item offered in a transfer (docs/04, DCR-058).
///
/// `mime` and `mtime` are omitted per DCR-058: neither field participates in
/// protocol decisions at Layer 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferItem {
    item_id: ItemId,
    rel_path: RelPath,
    size: u64,
    content_hash: ContentHash,
}

impl OfferItem {
    /// Builds an `OfferItem`, refusing a zero `size`.
    pub fn new(
        item_id: ItemId,
        rel_path: RelPath,
        size: u64,
        content_hash: ContentHash,
    ) -> Result<Self, OfferItemError> {
        if size == 0 {
            return Err(OfferItemError::EmptySize);
        }
        Ok(Self {
            item_id,
            rel_path,
            size,
            content_hash,
        })
    }

    /// The unique identifier of this item within the transfer.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// The relative path for placing the item.
    pub fn rel_path(&self) -> &RelPath {
        &self.rel_path
    }

    /// The size of the item in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The BLAKE3 root hash of the item's full content.
    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    /// Number of 1 MiB reference chunks this item covers.
    pub fn chunk_count(&self) -> u64 {
        self.size.div_ceil(REFERENCE_CHUNK_SIZE_BYTES)
    }
}

/// An error constructing a `TransferOffer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferOfferError {
    /// The offer carried no items.
    NoItems,
    /// Two items in the offer shared an item ID.
    DuplicateItemId(ItemId),
    /// The declared total bytes did not match the sum of item sizes.
    TotalBytesMismatch {
        /// The total bytes declared on the offer.
        declared: u64,
        /// The sum of item sizes computed from the items list.
        summed: u64,
    },
}

impl fmt::Display for TransferOfferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoItems => write!(f, "transfer offer must contain at least one item"),
            Self::DuplicateItemId(id) => write!(f, "duplicate item id in transfer offer: {id}"),
            Self::TotalBytesMismatch { declared, summed } => {
                write!(
                    f,
                    "declared total bytes ({declared}) does not match sum of item sizes ({summed})"
                )
            }
        }
    }
}

impl std::error::Error for TransferOfferError {}

/// A transfer offer describing files available to be transferred (docs/04,
/// DCR-058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOffer {
    transfer_id: TransferId,
    items: Vec<OfferItem>,
    total_bytes: u64,
    sender_label: Option<DisplayName>,
    origin: Option<OfferOrigin>,
}

impl TransferOffer {
    /// Builds a `TransferOffer`, validating that `items` is non-empty, contains
    /// no duplicate `ItemId`s, and that `total_bytes` equals the sum of item sizes.
    pub fn new(
        transfer_id: TransferId,
        items: Vec<OfferItem>,
        total_bytes: u64,
        sender_label: Option<DisplayName>,
        origin: Option<OfferOrigin>,
    ) -> Result<Self, TransferOfferError> {
        if items.is_empty() {
            return Err(TransferOfferError::NoItems);
        }

        let mut seen: HashSet<ItemId> = HashSet::new();
        let mut sum: u64 = 0;
        let mut overflow = false;

        for item in &items {
            if !seen.insert(*item.item_id()) {
                return Err(TransferOfferError::DuplicateItemId(*item.item_id()));
            }
            if let Some(next) = sum.checked_add(item.size()) {
                sum = next;
            } else {
                overflow = true;
            }
        }

        if overflow || sum != total_bytes {
            return Err(TransferOfferError::TotalBytesMismatch {
                declared: total_bytes,
                summed: sum,
            });
        }

        Ok(Self {
            transfer_id,
            items,
            total_bytes,
            sender_label,
            origin,
        })
    }

    /// The transfer's unique identifier.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The items contained in this offer.
    pub fn items(&self) -> &[OfferItem] {
        &self.items
    }

    /// Total declared bytes across all items.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// The sender's human-readable label, if provided.
    pub fn sender_label(&self) -> Option<&DisplayName> {
        self.sender_label.as_ref()
    }

    /// The origin indicating how the transfer was initiated, if provided.
    pub fn origin(&self) -> Option<OfferOrigin> {
        self.origin
    }
}

/// An error constructing an `ItemAcceptance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemAcceptanceError {
    /// A declined item declared a non-zero `resume_chunk` or non-empty `have_chunks`.
    DeclinedWithProgress,
    /// `have_chunks` contained duplicate chunk indices.
    DuplicateHaveChunk(u64),
}

impl fmt::Display for ItemAcceptanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeclinedWithProgress => {
                write!(
                    f,
                    "declined item must not declare resume_chunk or have_chunks"
                )
            }
            Self::DuplicateHaveChunk(chunk) => {
                write!(f, "duplicate chunk {chunk} in have_chunks")
            }
        }
    }
}

impl std::error::Error for ItemAcceptanceError {}

/// Acceptance decision and resumption state for a single item (docs/04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemAcceptance {
    item_id: ItemId,
    accepted: bool,
    resume_chunk: u64,
    have_chunks: Vec<u64>,
}

impl ItemAcceptance {
    /// Builds an `ItemAcceptance`, refusing progress fields when `accepted` is false
    /// and refusing duplicate entries in `have_chunks`.
    pub fn new(
        item_id: ItemId,
        accepted: bool,
        resume_chunk: u64,
        have_chunks: Vec<u64>,
    ) -> Result<Self, ItemAcceptanceError> {
        if !accepted && (resume_chunk != 0 || !have_chunks.is_empty()) {
            return Err(ItemAcceptanceError::DeclinedWithProgress);
        }

        let mut seen: HashSet<u64> = HashSet::new();
        for &chunk in &have_chunks {
            if !seen.insert(chunk) {
                return Err(ItemAcceptanceError::DuplicateHaveChunk(chunk));
            }
        }

        Ok(Self {
            item_id,
            accepted,
            resume_chunk,
            have_chunks,
        })
    }

    /// The item being accepted or declined.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// Whether the receiver accepted this item.
    pub fn accepted(&self) -> bool {
        self.accepted
    }

    /// The starting chunk index to request contiguously.
    pub fn resume_chunk(&self) -> u64 {
        self.resume_chunk
    }

    /// Discontiguous chunks the receiver already holds.
    pub fn have_chunks(&self) -> &[u64] {
        &self.have_chunks
    }
}

/// An error constructing or validating a `TransferAccept`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferAcceptError {
    /// The acceptance carried no items.
    NoItems,
    /// Two items in the acceptance shared an item ID.
    DuplicateItemId(ItemId),
    /// The acceptance transfer ID did not match the offer transfer ID.
    TransferIdMismatch,
    /// An accepted item ID was not present in the offer.
    UnknownItemId(ItemId),
    /// An accepted item's resume chunk was not below the item's chunk count.
    ResumeChunkOutOfRange {
        /// The item ID with the invalid resume chunk.
        item_id: ItemId,
        /// The resume chunk that was out of range.
        resume_chunk: u64,
        /// Total reference chunks for the item in the offer.
        chunk_count: u64,
    },
    /// A chunk index in `have_chunks` was not below the item's chunk count.
    HaveChunkOutOfRange {
        /// The item ID with the invalid chunk.
        item_id: ItemId,
        /// The chunk index that was out of range.
        chunk: u64,
        /// Total reference chunks for the item in the offer.
        chunk_count: u64,
    },
}

impl fmt::Display for TransferAcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoItems => write!(f, "transfer accept must contain at least one item"),
            Self::DuplicateItemId(id) => write!(f, "duplicate item id in transfer accept: {id}"),
            Self::TransferIdMismatch => {
                write!(f, "transfer accept transfer id does not match offer")
            }
            Self::UnknownItemId(id) => {
                write!(f, "item id {id} in transfer accept was not in offer")
            }
            Self::ResumeChunkOutOfRange {
                item_id,
                resume_chunk,
                chunk_count,
            } => {
                write!(
                    f,
                    "resume chunk {resume_chunk} out of range for item {item_id} (chunk count: {chunk_count})"
                )
            }
            Self::HaveChunkOutOfRange {
                item_id,
                chunk,
                chunk_count,
            } => {
                write!(
                    f,
                    "have chunk {chunk} out of range for item {item_id} (chunk count: {chunk_count})"
                )
            }
        }
    }
}

impl std::error::Error for TransferAcceptError {}

/// The receiver's response accepting or declining items in a transfer offer (docs/04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferAccept {
    transfer_id: TransferId,
    items: Vec<ItemAcceptance>,
    destination_label: Option<DisplayName>,
}

impl TransferAccept {
    /// Builds a `TransferAccept`, validating that `items` is non-empty and contains
    /// no duplicate `ItemId`s.
    pub fn new(
        transfer_id: TransferId,
        items: Vec<ItemAcceptance>,
        destination_label: Option<DisplayName>,
    ) -> Result<Self, TransferAcceptError> {
        if items.is_empty() {
            return Err(TransferAcceptError::NoItems);
        }

        let mut seen: HashSet<ItemId> = HashSet::new();
        for item in &items {
            if !seen.insert(*item.item_id()) {
                return Err(TransferAcceptError::DuplicateItemId(*item.item_id()));
            }
        }

        Ok(Self {
            transfer_id,
            items,
            destination_label,
        })
    }

    /// The transfer being accepted.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Per-item acceptance decisions.
    pub fn items(&self) -> &[ItemAcceptance] {
        &self.items
    }

    /// Human-readable label for destination folder, if provided.
    pub fn destination_label(&self) -> Option<&DisplayName> {
        self.destination_label.as_ref()
    }

    /// Validates this acceptance against the corresponding offer (docs/04).
    ///
    /// Confirms matching `transfer_id`, that all accepted item IDs exist in the offer,
    /// and that `resume_chunk` and `have_chunks` are strictly within each item's
    /// `chunk_count`.
    pub fn for_offer(&self, offer: &TransferOffer) -> Result<(), TransferAcceptError> {
        if self.transfer_id != offer.transfer_id() {
            return Err(TransferAcceptError::TransferIdMismatch);
        }

        for item_acc in &self.items {
            let offer_item = offer
                .items()
                .iter()
                .find(|it| it.item_id() == item_acc.item_id())
                .ok_or_else(|| TransferAcceptError::UnknownItemId(*item_acc.item_id()))?;

            let chunk_count = offer_item.chunk_count();

            if item_acc.accepted() && item_acc.resume_chunk() >= chunk_count {
                return Err(TransferAcceptError::ResumeChunkOutOfRange {
                    item_id: *item_acc.item_id(),
                    resume_chunk: item_acc.resume_chunk(),
                    chunk_count,
                });
            }

            for &chunk in item_acc.have_chunks() {
                if chunk >= chunk_count {
                    return Err(TransferAcceptError::HaveChunkOutOfRange {
                        item_id: *item_acc.item_id(),
                        chunk,
                        chunk_count,
                    });
                }
            }
        }

        Ok(())
    }
}

/// The receiver's response rejecting a transfer offer in its entirety (docs/04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReject {
    transfer_id: TransferId,
    reason: Option<RejectReason>,
    note: Option<DisplayName>,
}

impl TransferReject {
    /// Builds a `TransferReject`.
    pub fn new(
        transfer_id: TransferId,
        reason: Option<RejectReason>,
        note: Option<DisplayName>,
    ) -> Self {
        Self {
            transfer_id,
            reason,
            note,
        }
    }

    /// The transfer being rejected.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The reason for rejecting the transfer, if provided.
    pub fn reason(&self) -> Option<RejectReason> {
        self.reason
    }

    /// An optional human-readable note explaining the rejection.
    pub fn note(&self) -> Option<&DisplayName> {
        self.note.as_ref()
    }
}

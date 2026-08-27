//! Domain types for Data plane messages (docs/04-protocol.md).
//! Covers chunk requests, rerequests, data stream headers, completion
//! signals, receiver flow control, and transfer progress metrics.

use crate::{ChunkIndex, ItemId, RelPath, TransferId};

/// A pull-based request for a batch of sequential chunks of an Item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRequest {
    transfer_id: TransferId,
    item_id: ItemId,
    from_chunk: ChunkIndex,
    count: u32,
}

impl ChunkRequest {
    /// Creates a new `ChunkRequest`.
    pub fn new(
        transfer_id: TransferId,
        item_id: ItemId,
        from_chunk: ChunkIndex,
        count: u32,
    ) -> Self {
        Self {
            transfer_id,
            item_id,
            from_chunk,
            count,
        }
    }

    /// The transfer this request belongs to.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The item within the transfer being requested.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// The starting chunk index of the requested batch.
    pub fn from_chunk(&self) -> ChunkIndex {
        self.from_chunk
    }

    /// The number of sequential chunks requested.
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// A request for specific individual chunks after validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRerequest {
    transfer_id: TransferId,
    item_id: ItemId,
    chunks: Vec<ChunkIndex>,
}

impl ChunkRerequest {
    /// Creates a new `ChunkRerequest`.
    pub fn new(transfer_id: TransferId, item_id: ItemId, chunks: Vec<ChunkIndex>) -> Self {
        Self {
            transfer_id,
            item_id,
            chunks,
        }
    }

    /// The transfer this rerequest belongs to.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The item within the transfer being rerequested.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// The list of chunk indices being rerequested.
    pub fn chunks(&self) -> &[ChunkIndex] {
        &self.chunks
    }
}

/// The protobuf header preceding raw chunk payload bytes on a data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkDataHeader {
    transfer_id: TransferId,
    item_id: ItemId,
    chunk_index: ChunkIndex,
    payload_len: u32,
    verify_path: Vec<u8>,
    last: bool,
    offset_in_chunk: u32,
}

impl ChunkDataHeader {
    /// Creates a new `ChunkDataHeader`.
    pub fn new(
        transfer_id: TransferId,
        item_id: ItemId,
        chunk_index: ChunkIndex,
        payload_len: u32,
        verify_path: Vec<u8>,
        last: bool,
        offset_in_chunk: u32,
    ) -> Self {
        Self {
            transfer_id,
            item_id,
            chunk_index,
            payload_len,
            verify_path,
            last,
            offset_in_chunk,
        }
    }

    /// The transfer this chunk belongs to.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The item within the transfer this chunk belongs to.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// The reference chunk index.
    pub fn chunk_index(&self) -> ChunkIndex {
        self.chunk_index
    }

    /// Length of the raw payload following this header in bytes.
    pub fn payload_len(&self) -> u32 {
        self.payload_len
    }

    /// The BLAKE3 tree path (bao outboard) for incremental verification.
    pub fn verify_path(&self) -> &[u8] {
        &self.verify_path
    }

    /// Whether this is the final piece of the item.
    pub fn is_last(&self) -> bool {
        self.last
    }

    /// Offset within the 1 MiB reference chunk when subdivided.
    pub fn offset_in_chunk(&self) -> u32 {
        self.offset_in_chunk
    }
}

/// Notification sent when all chunks of an item have been received and processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemComplete {
    transfer_id: TransferId,
    item_id: ItemId,
    verified: bool,
    final_path: Option<RelPath>,
}

impl ItemComplete {
    /// Creates a new `ItemComplete`.
    pub fn new(
        transfer_id: TransferId,
        item_id: ItemId,
        verified: bool,
        final_path: Option<RelPath>,
    ) -> Self {
        Self {
            transfer_id,
            item_id,
            verified,
            final_path,
        }
    }

    /// The transfer this completion status belongs to.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// The item that finished receiving or verifying.
    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    /// True if content hash verification succeeded.
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// The final relative path on the receiver, present on successful placement.
    pub fn final_path(&self) -> Option<&RelPath> {
        self.final_path.as_ref()
    }
}

/// Receiver backpressure notification to adjust in-flight chunk limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowControl {
    transfer_id: TransferId,
    max_inflight_chunks: u32,
    reason: Option<String>,
}

impl FlowControl {
    /// Creates a new `FlowControl`.
    pub fn new(transfer_id: TransferId, max_inflight_chunks: u32, reason: Option<String>) -> Self {
        Self {
            transfer_id,
            max_inflight_chunks,
            reason,
        }
    }

    /// The transfer this flow control applies to.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Maximum in-flight chunks allowed by receiver; 0 pauses the transfer.
    pub fn max_inflight_chunks(&self) -> u32 {
        self.max_inflight_chunks
    }

    /// Optional reason for backpressure (e.g. slow disk, low battery).
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// Progress metrics reported for an active transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct TransferProgress {
    transfer_id: TransferId,
    bytes_received: u64,
    bytes_total: u64,
    items_completed: u32,
    items_total: u32,
    throughput_bps: f64,
    active_transport: Option<String>,
}

impl TransferProgress {
    /// Creates a new `TransferProgress`.
    pub fn new(
        transfer_id: TransferId,
        bytes_received: u64,
        bytes_total: u64,
        items_completed: u32,
        items_total: u32,
        throughput_bps: f64,
        active_transport: Option<String>,
    ) -> Self {
        Self {
            transfer_id,
            bytes_received,
            bytes_total,
            items_completed,
            items_total,
            throughput_bps,
            active_transport,
        }
    }

    /// The transfer being monitored.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Total bytes received so far across all items.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Total expected bytes for all items in the transfer.
    pub fn bytes_total(&self) -> u64 {
        self.bytes_total
    }

    /// Count of items fully received and verified.
    pub fn items_completed(&self) -> u32 {
        self.items_completed
    }

    /// Total items in the transfer.
    pub fn items_total(&self) -> u32 {
        self.items_total
    }

    /// Moving average throughput in bytes per second.
    pub fn throughput_bps(&self) -> f64 {
        self.throughput_bps
    }

    /// Name of the active transport path if known.
    pub fn active_transport(&self) -> Option<&str> {
        self.active_transport.as_deref()
    }
}

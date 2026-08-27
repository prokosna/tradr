//! Wire conversions and framing helpers for Data plane messages.
//! Converts between raw protobuf messages in `tradr.v1` and validated
//! domain types in `tradr-core`.

use prost::Message;
use tradr_core::{
    ChunkDataHeader, ChunkIndex, ChunkRequest, ChunkRerequest, FlowControl, ItemComplete, ItemId,
    ItemIdError, RelPath, RelPathError, TransferId, TransferIdError, TransferProgress,
};

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;

/// Errors arising from invalid fields in incoming wire messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferWireError {
    /// The transfer_id field was not a valid UUIDv7.
    InvalidTransferId(TransferIdError),
    /// The item_id field failed identifier constraints.
    InvalidItemId(ItemIdError),
    /// The final_path field was not a valid relative path.
    InvalidPath(RelPathError),
    /// The chunk count in ChunkRequest was zero.
    ZeroCount,
    /// The chunks list in ChunkRerequest was empty.
    EmptyChunks,
}

impl std::fmt::Display for TransferWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransferId(e) => write!(f, "transfer_id invalid: {e}"),
            Self::InvalidItemId(e) => write!(f, "item_id invalid: {e}"),
            Self::InvalidPath(e) => write!(f, "final_path invalid: {e}"),
            Self::ZeroCount => write!(f, "chunk count must be non-zero"),
            Self::EmptyChunks => write!(f, "chunks list must not be empty"),
        }
    }
}

impl std::error::Error for TransferWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTransferId(e) => Some(e),
            Self::InvalidItemId(e) => Some(e),
            Self::InvalidPath(e) => Some(e),
            Self::ZeroCount | Self::EmptyChunks => None,
        }
    }
}

/// Errors arising during encoding or decoding framed transfer messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferFrameError {
    /// The frame's type byte did not match the expected message type.
    WrongMessageType {
        /// The expected message type code.
        expected: u8,
        /// The received message type code.
        got: u8,
    },
    /// Framing could not encode or decode the byte sequence.
    Framing(FrameError),
    /// Protobuf payload decoding failed.
    Decode(prost::DecodeError),
    /// Wire validation failed on decoded fields.
    Wire(TransferWireError),
}

impl std::fmt::Display for TransferFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongMessageType { expected, got } => {
                write!(f, "expected frame type 0x{expected:02x}, got 0x{got:02x}")
            }
            Self::Framing(e) => write!(f, "frame error: {e}"),
            Self::Decode(e) => write!(f, "protobuf decode error: {e}"),
            Self::Wire(e) => write!(f, "wire validation error: {e}"),
        }
    }
}

impl std::error::Error for TransferFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongMessageType { .. } => None,
            Self::Framing(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<FrameError> for TransferFrameError {
    fn from(err: FrameError) -> Self {
        Self::Framing(err)
    }
}

impl From<prost::DecodeError> for TransferFrameError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<TransferWireError> for TransferFrameError {
    fn from(err: TransferWireError) -> Self {
        Self::Wire(err)
    }
}

/// Converts a domain `ChunkRequest` to wire format.
pub fn chunk_request_to_wire(req: &ChunkRequest) -> v1::ChunkRequest {
    v1::ChunkRequest {
        transfer_id: req.transfer_id().to_string(),
        item_id: req.item_id().to_string(),
        from_chunk: req.from_chunk().value(),
        count: req.count(),
    }
}

/// Validates and converts a wire `ChunkRequest` to domain format.
pub fn chunk_request_from_wire(
    message: v1::ChunkRequest,
) -> Result<ChunkRequest, TransferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(TransferWireError::InvalidTransferId)?;
    let item_id = ItemId::new(&message.item_id).map_err(TransferWireError::InvalidItemId)?;
    if message.count == 0 {
        return Err(TransferWireError::ZeroCount);
    }
    Ok(ChunkRequest::new(
        transfer_id,
        item_id,
        ChunkIndex::new(message.from_chunk),
        message.count,
    ))
}

/// Converts a domain `ChunkRerequest` to wire format.
pub fn chunk_rerequest_to_wire(req: &ChunkRerequest) -> v1::ChunkRerequest {
    v1::ChunkRerequest {
        transfer_id: req.transfer_id().to_string(),
        item_id: req.item_id().to_string(),
        chunks: req.chunks().iter().map(|c| c.value()).collect(),
    }
}

/// Validates and converts a wire `ChunkRerequest` to domain format.
pub fn chunk_rerequest_from_wire(
    message: v1::ChunkRerequest,
) -> Result<ChunkRerequest, TransferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(TransferWireError::InvalidTransferId)?;
    let item_id = ItemId::new(&message.item_id).map_err(TransferWireError::InvalidItemId)?;
    if message.chunks.is_empty() {
        return Err(TransferWireError::EmptyChunks);
    }
    let chunks = message.chunks.into_iter().map(ChunkIndex::new).collect();
    Ok(ChunkRerequest::new(transfer_id, item_id, chunks))
}

/// Converts a domain `ChunkDataHeader` to wire format.
pub fn chunk_data_header_to_wire(header: &ChunkDataHeader) -> v1::ChunkData {
    v1::ChunkData {
        transfer_id: header.transfer_id().to_string(),
        item_id: header.item_id().to_string(),
        chunk_index: header.chunk_index().value(),
        payload_len: header.payload_len(),
        verify_path: header.verify_path().to_vec(),
        last: header.is_last(),
        offset_in_chunk: header.offset_in_chunk(),
    }
}

/// Validates and converts a wire `ChunkData` header to domain format.
pub fn chunk_data_header_from_wire(
    message: v1::ChunkData,
) -> Result<ChunkDataHeader, TransferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(TransferWireError::InvalidTransferId)?;
    let item_id = ItemId::new(&message.item_id).map_err(TransferWireError::InvalidItemId)?;
    Ok(ChunkDataHeader::new(
        transfer_id,
        item_id,
        ChunkIndex::new(message.chunk_index),
        message.payload_len,
        message.verify_path,
        message.last,
        message.offset_in_chunk,
    ))
}

/// Converts a domain `ItemComplete` to wire format.
pub fn item_complete_to_wire(item: &ItemComplete) -> v1::ItemComplete {
    v1::ItemComplete {
        transfer_id: item.transfer_id().to_string(),
        item_id: item.item_id().to_string(),
        verified: item.is_verified(),
        final_path: item.final_path().map(|p| p.to_string()).unwrap_or_default(),
    }
}

/// Validates and converts a wire `ItemComplete` to domain format.
pub fn item_complete_from_wire(
    message: v1::ItemComplete,
) -> Result<ItemComplete, TransferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(TransferWireError::InvalidTransferId)?;
    let item_id = ItemId::new(&message.item_id).map_err(TransferWireError::InvalidItemId)?;
    let final_path = if message.final_path.is_empty() {
        None
    } else {
        Some(RelPath::new(&message.final_path).map_err(TransferWireError::InvalidPath)?)
    };
    Ok(ItemComplete::new(
        transfer_id,
        item_id,
        message.verified,
        final_path,
    ))
}

/// Converts a domain `FlowControl` to wire format.
pub fn flow_control_to_wire(fc: &FlowControl) -> v1::FlowControl {
    v1::FlowControl {
        transfer_id: fc.transfer_id().to_string(),
        max_inflight_chunks: fc.max_inflight_chunks(),
        reason: fc.reason().map(|s| s.to_string()).unwrap_or_default(),
    }
}

/// Validates and converts a wire `FlowControl` to domain format.
pub fn flow_control_from_wire(message: v1::FlowControl) -> Result<FlowControl, TransferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(TransferWireError::InvalidTransferId)?;
    let reason = if message.reason.is_empty() {
        None
    } else {
        Some(message.reason)
    };
    Ok(FlowControl::new(
        transfer_id,
        message.max_inflight_chunks,
        reason,
    ))
}

/// Converts a domain `TransferProgress` to wire format.
pub fn transfer_progress_to_wire(tp: &TransferProgress) -> v1::TransferProgress {
    v1::TransferProgress {
        transfer_id: tp.transfer_id().to_string(),
        bytes_received: tp.bytes_received(),
        bytes_total: tp.bytes_total(),
        items_completed: tp.items_completed(),
        items_total: tp.items_total(),
        throughput_bps: tp.throughput_bps(),
        active_transport: tp
            .active_transport()
            .map(|s| s.to_string())
            .unwrap_or_default(),
    }
}

/// Validates and converts a wire `TransferProgress` to domain format.
pub fn transfer_progress_from_wire(
    message: v1::TransferProgress,
) -> Result<TransferProgress, TransferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(TransferWireError::InvalidTransferId)?;
    let active_transport = if message.active_transport.is_empty() {
        None
    } else {
        Some(message.active_transport)
    };
    Ok(TransferProgress::new(
        transfer_id,
        message.bytes_received,
        message.bytes_total,
        message.items_completed,
        message.items_total,
        message.throughput_bps,
        active_transport,
    ))
}

/// Encodes a `ChunkRequest` to a framed ChunkRequest message.
pub fn encode_chunk_request_frame(
    req: &ChunkRequest,
    max_frame_size: u32,
) -> Result<Vec<u8>, TransferFrameError> {
    let wire = chunk_request_to_wire(req);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::ChunkRequest.code(), &payload, max_frame_size)
        .map_err(TransferFrameError::Framing)
}

/// Decodes a framed ChunkRequest message into a domain `ChunkRequest`.
pub fn decode_chunk_request_frame(frame: &Frame) -> Result<ChunkRequest, TransferFrameError> {
    let expected = MessageType::ChunkRequest.code();
    if frame.type_code() != expected {
        return Err(TransferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ChunkRequest::decode(frame.payload()).map_err(TransferFrameError::Decode)?;
    chunk_request_from_wire(wire).map_err(TransferFrameError::Wire)
}

/// Encodes a `ChunkRerequest` to a framed ChunkRerequest message.
pub fn encode_chunk_rerequest_frame(
    req: &ChunkRerequest,
    max_frame_size: u32,
) -> Result<Vec<u8>, TransferFrameError> {
    let wire = chunk_rerequest_to_wire(req);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::ChunkRerequest.code(), &payload, max_frame_size)
        .map_err(TransferFrameError::Framing)
}

/// Decodes a framed ChunkRerequest message into a domain `ChunkRerequest`.
pub fn decode_chunk_rerequest_frame(frame: &Frame) -> Result<ChunkRerequest, TransferFrameError> {
    let expected = MessageType::ChunkRerequest.code();
    if frame.type_code() != expected {
        return Err(TransferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ChunkRerequest::decode(frame.payload()).map_err(TransferFrameError::Decode)?;
    chunk_rerequest_from_wire(wire).map_err(TransferFrameError::Wire)
}

/// Encodes a `ChunkDataHeader` to a framed ChunkData message.
pub fn encode_chunk_data_header_frame(
    header: &ChunkDataHeader,
    max_frame_size: u32,
) -> Result<Vec<u8>, TransferFrameError> {
    let wire = chunk_data_header_to_wire(header);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::ChunkData.code(), &payload, max_frame_size)
        .map_err(TransferFrameError::Framing)
}

/// Decodes a framed ChunkData message into a domain `ChunkDataHeader`.
pub fn decode_chunk_data_header_frame(
    frame: &Frame,
) -> Result<ChunkDataHeader, TransferFrameError> {
    let expected = MessageType::ChunkData.code();
    if frame.type_code() != expected {
        return Err(TransferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ChunkData::decode(frame.payload()).map_err(TransferFrameError::Decode)?;
    chunk_data_header_from_wire(wire).map_err(TransferFrameError::Wire)
}

/// Encodes an `ItemComplete` to a framed ItemComplete message.
pub fn encode_item_complete_frame(
    item: &ItemComplete,
    max_frame_size: u32,
) -> Result<Vec<u8>, TransferFrameError> {
    let wire = item_complete_to_wire(item);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::ItemComplete.code(), &payload, max_frame_size)
        .map_err(TransferFrameError::Framing)
}

/// Decodes a framed ItemComplete message into a domain `ItemComplete`.
pub fn decode_item_complete_frame(frame: &Frame) -> Result<ItemComplete, TransferFrameError> {
    let expected = MessageType::ItemComplete.code();
    if frame.type_code() != expected {
        return Err(TransferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ItemComplete::decode(frame.payload()).map_err(TransferFrameError::Decode)?;
    item_complete_from_wire(wire).map_err(TransferFrameError::Wire)
}

/// Encodes a `FlowControl` to a framed FlowControl message.
pub fn encode_flow_control_frame(
    fc: &FlowControl,
    max_frame_size: u32,
) -> Result<Vec<u8>, TransferFrameError> {
    let wire = flow_control_to_wire(fc);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::FlowControl.code(), &payload, max_frame_size)
        .map_err(TransferFrameError::Framing)
}

/// Decodes a framed FlowControl message into a domain `FlowControl`.
pub fn decode_flow_control_frame(frame: &Frame) -> Result<FlowControl, TransferFrameError> {
    let expected = MessageType::FlowControl.code();
    if frame.type_code() != expected {
        return Err(TransferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::FlowControl::decode(frame.payload()).map_err(TransferFrameError::Decode)?;
    flow_control_from_wire(wire).map_err(TransferFrameError::Wire)
}

/// Encodes a `TransferProgress` to a framed TransferProgress message.
pub fn encode_transfer_progress_frame(
    tp: &TransferProgress,
    max_frame_size: u32,
) -> Result<Vec<u8>, TransferFrameError> {
    let wire = transfer_progress_to_wire(tp);
    let payload = wire.encode_to_vec();
    encode_frame(
        MessageType::TransferProgress.code(),
        &payload,
        max_frame_size,
    )
    .map_err(TransferFrameError::Framing)
}

/// Decodes a framed TransferProgress message into a domain `TransferProgress`.
pub fn decode_transfer_progress_frame(
    frame: &Frame,
) -> Result<TransferProgress, TransferFrameError> {
    let expected = MessageType::TransferProgress.code();
    if frame.type_code() != expected {
        return Err(TransferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::TransferProgress::decode(frame.payload()).map_err(TransferFrameError::Decode)?;
    transfer_progress_from_wire(wire).map_err(TransferFrameError::Wire)
}

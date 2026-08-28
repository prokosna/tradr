//! Converts between wire `control.proto` Offer messages and native Layer 0
//! types in `tradr-core` (docs/04-protocol.md, DCR-058, DCR-059). Reshapes
//! and validates wire fields without deciding business logic.

use prost::Message;
use tradr_core::{
    ContentHash, DisplayName, ItemAcceptance, ItemAcceptanceError, ItemId, ItemIdError, OfferItem,
    OfferItemError, OfferOrigin, REFERENCE_CHUNK_SIZE_BYTES, RejectReason, RelPath, RelPathError,
    TransferAccept, TransferAcceptError, TransferId, TransferIdError, TransferOffer,
    TransferOfferError, TransferReject,
};

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;

/// Errors arising from invalid fields in incoming Offer exchange wire messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferWireError {
    /// The transfer_id field was not a valid UUIDv7.
    InvalidTransferId(TransferIdError),
    /// An item's chunk_size did not equal REFERENCE_CHUNK_SIZE_BYTES.
    InvalidChunkSize {
        /// The chunk size received on the wire.
        got: u32,
    },
    /// An item's item_id was not a valid identifier.
    InvalidItemId(ItemIdError),
    /// An item's relative_path failed path safety validation.
    InvalidRelPath(RelPathError),
    /// An item's content_hash was not exactly 32 bytes.
    InvalidContentHash {
        /// The byte length received on the wire.
        len: usize,
    },
    /// An item failed OfferItem construction rules (e.g. zero size).
    InvalidItem(OfferItemError),
    /// The transfer offer failed TransferOffer construction rules.
    InvalidOffer(TransferOfferError),
    /// An item acceptance failed ItemAcceptance construction rules.
    InvalidItemAcceptance(ItemAcceptanceError),
    /// The transfer accept failed TransferAccept construction rules.
    InvalidAccept(TransferAcceptError),
}

impl std::fmt::Display for OfferWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransferId(e) => write!(f, "transfer_id invalid: {e}"),
            Self::InvalidChunkSize { got } => {
                write!(
                    f,
                    "item chunk_size must be {REFERENCE_CHUNK_SIZE_BYTES}, got {got}"
                )
            }
            Self::InvalidItemId(e) => write!(f, "item_id invalid: {e}"),
            Self::InvalidRelPath(e) => write!(f, "relative_path invalid: {e}"),
            Self::InvalidContentHash { len } => {
                write!(f, "content_hash must be 32 bytes, got {len}")
            }
            Self::InvalidItem(e) => write!(f, "offer item invalid: {e}"),
            Self::InvalidOffer(e) => write!(f, "transfer offer invalid: {e}"),
            Self::InvalidItemAcceptance(e) => write!(f, "item acceptance invalid: {e}"),
            Self::InvalidAccept(e) => write!(f, "transfer accept invalid: {e}"),
        }
    }
}

impl std::error::Error for OfferWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTransferId(e) => Some(e),
            Self::InvalidChunkSize { .. } => None,
            Self::InvalidItemId(e) => Some(e),
            Self::InvalidRelPath(e) => Some(e),
            Self::InvalidContentHash { .. } => None,
            Self::InvalidItem(e) => Some(e),
            Self::InvalidOffer(e) => Some(e),
            Self::InvalidItemAcceptance(e) => Some(e),
            Self::InvalidAccept(e) => Some(e),
        }
    }
}

/// Errors arising during encoding or decoding framed Offer exchange messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferFrameError {
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
    Wire(OfferWireError),
}

impl std::fmt::Display for OfferFrameError {
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

impl std::error::Error for OfferFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongMessageType { .. } => None,
            Self::Framing(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<FrameError> for OfferFrameError {
    fn from(err: FrameError) -> Self {
        Self::Framing(err)
    }
}

impl From<prost::DecodeError> for OfferFrameError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<OfferWireError> for OfferFrameError {
    fn from(err: OfferWireError) -> Self {
        Self::Wire(err)
    }
}

/// Validates and converts a wire `TransferOffer` to a domain `TransferOffer`.
pub fn transfer_offer_from_wire(
    message: v1::TransferOffer,
) -> Result<TransferOffer, OfferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(OfferWireError::InvalidTransferId)?;

    let mut items = Vec::with_capacity(message.items.len());
    for item in message.items {
        if item.chunk_size != REFERENCE_CHUNK_SIZE_BYTES as u32 {
            return Err(OfferWireError::InvalidChunkSize {
                got: item.chunk_size,
            });
        }
        let item_id = ItemId::new(&item.item_id).map_err(OfferWireError::InvalidItemId)?;
        let rel_path = RelPath::new(&item.relative_path).map_err(OfferWireError::InvalidRelPath)?;
        let hash_bytes: [u8; 32] = item
            .content_hash
            .try_into()
            .map_err(|bytes: Vec<u8>| OfferWireError::InvalidContentHash { len: bytes.len() })?;
        let content_hash = ContentHash::from_bytes(hash_bytes);
        let offer_item = OfferItem::new(item_id, rel_path, item.size, content_hash)
            .map_err(OfferWireError::InvalidItem)?;
        items.push(offer_item);
    }

    let sender_label = DisplayName::new(&message.sender_label).ok();
    let origin = OfferOrigin::try_from(message.origin).ok();

    TransferOffer::new(
        transfer_id,
        items,
        message.total_bytes,
        sender_label,
        origin,
    )
    .map_err(OfferWireError::InvalidOffer)
}

/// Converts a domain `TransferOffer` to wire format. Infallible.
pub fn transfer_offer_to_wire(offer: &TransferOffer) -> v1::TransferOffer {
    v1::TransferOffer {
        transfer_id: offer.transfer_id().to_string(),
        items: offer
            .items()
            .iter()
            .map(|item| v1::OfferItem {
                item_id: item.item_id().to_string(),
                relative_path: item.rel_path().to_string(),
                size: item.size(),
                content_hash: item.content_hash().as_bytes().to_vec(),
                mtime: 0,
                mime: String::new(),
                chunk_size: REFERENCE_CHUNK_SIZE_BYTES as u32,
            })
            .collect(),
        total_bytes: offer.total_bytes(),
        sender_label: offer
            .sender_label()
            .map(|name| name.as_str().to_string())
            .unwrap_or_default(),
        origin: offer.origin().map(i32::from).unwrap_or(0),
    }
}

/// Validates and converts a wire `TransferAccept` to a domain `TransferAccept`.
pub fn transfer_accept_from_wire(
    message: v1::TransferAccept,
) -> Result<TransferAccept, OfferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(OfferWireError::InvalidTransferId)?;

    let mut items = Vec::with_capacity(message.items.len());
    for item in message.items {
        let item_id = ItemId::new(&item.item_id).map_err(OfferWireError::InvalidItemId)?;
        let item_acc =
            ItemAcceptance::new(item_id, item.accepted, item.resume_chunk, item.have_chunks)
                .map_err(OfferWireError::InvalidItemAcceptance)?;
        items.push(item_acc);
    }

    let destination_label = DisplayName::new(&message.destination_label).ok();

    TransferAccept::new(transfer_id, items, destination_label)
        .map_err(OfferWireError::InvalidAccept)
}

/// Converts a domain `TransferAccept` to wire format. Infallible.
pub fn transfer_accept_to_wire(accept: &TransferAccept) -> v1::TransferAccept {
    v1::TransferAccept {
        transfer_id: accept.transfer_id().to_string(),
        items: accept
            .items()
            .iter()
            .map(|item| v1::ItemAcceptance {
                item_id: item.item_id().to_string(),
                accepted: item.accepted(),
                resume_chunk: item.resume_chunk(),
                have_chunks: item.have_chunks().to_vec(),
            })
            .collect(),
        destination_label: accept
            .destination_label()
            .map(|name| name.as_str().to_string())
            .unwrap_or_default(),
    }
}

/// Validates and converts a wire `TransferReject` to a domain `TransferReject`.
pub fn transfer_reject_from_wire(
    message: v1::TransferReject,
) -> Result<TransferReject, OfferWireError> {
    let transfer_id: TransferId = message
        .transfer_id
        .parse()
        .map_err(OfferWireError::InvalidTransferId)?;
    let reason = RejectReason::try_from(message.reason).ok();
    let note = DisplayName::new(&message.note).ok();
    Ok(TransferReject::new(transfer_id, reason, note))
}

/// Converts a domain `TransferReject` to wire format. Infallible.
pub fn transfer_reject_to_wire(reject: &TransferReject) -> v1::TransferReject {
    v1::TransferReject {
        transfer_id: reject.transfer_id().to_string(),
        reason: reject.reason().map(i32::from).unwrap_or(0),
        note: reject
            .note()
            .map(|name| name.as_str().to_string())
            .unwrap_or_default(),
    }
}

/// Encodes a `TransferOffer` to a framed TransferOffer message.
pub fn encode_transfer_offer_frame(
    offer: &TransferOffer,
    max_frame_size: u32,
) -> Result<Vec<u8>, OfferFrameError> {
    let wire = transfer_offer_to_wire(offer);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::TransferOffer.code(), &payload, max_frame_size)
        .map_err(OfferFrameError::Framing)
}

/// Decodes a framed TransferOffer message into a domain `TransferOffer`.
pub fn decode_transfer_offer_frame(frame: &Frame) -> Result<TransferOffer, OfferFrameError> {
    let expected = MessageType::TransferOffer.code();
    if frame.type_code() != expected {
        return Err(OfferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::TransferOffer::decode(frame.payload()).map_err(OfferFrameError::Decode)?;
    transfer_offer_from_wire(wire).map_err(OfferFrameError::Wire)
}

/// Encodes a `TransferAccept` to a framed TransferAccept message.
pub fn encode_transfer_accept_frame(
    accept: &TransferAccept,
    max_frame_size: u32,
) -> Result<Vec<u8>, OfferFrameError> {
    let wire = transfer_accept_to_wire(accept);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::TransferAccept.code(), &payload, max_frame_size)
        .map_err(OfferFrameError::Framing)
}

/// Decodes a framed TransferAccept message into a domain `TransferAccept`.
pub fn decode_transfer_accept_frame(frame: &Frame) -> Result<TransferAccept, OfferFrameError> {
    let expected = MessageType::TransferAccept.code();
    if frame.type_code() != expected {
        return Err(OfferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::TransferAccept::decode(frame.payload()).map_err(OfferFrameError::Decode)?;
    transfer_accept_from_wire(wire).map_err(OfferFrameError::Wire)
}

/// Encodes a `TransferReject` to a framed TransferReject message.
pub fn encode_transfer_reject_frame(
    reject: &TransferReject,
    max_frame_size: u32,
) -> Result<Vec<u8>, OfferFrameError> {
    let wire = transfer_reject_to_wire(reject);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::TransferReject.code(), &payload, max_frame_size)
        .map_err(OfferFrameError::Framing)
}

/// Decodes a framed TransferReject message into a domain `TransferReject`.
pub fn decode_transfer_reject_frame(frame: &Frame) -> Result<TransferReject, OfferFrameError> {
    let expected = MessageType::TransferReject.code();
    if frame.type_code() != expected {
        return Err(OfferFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::TransferReject::decode(frame.payload()).map_err(OfferFrameError::Decode)?;
    transfer_reject_from_wire(wire).map_err(OfferFrameError::Wire)
}

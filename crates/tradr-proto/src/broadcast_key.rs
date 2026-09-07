//! Converts between wire `BroadcastKeyOffer` and native `tradr_core` types
//! (docs/11-account-linking.md, "The exchange, and why it needs no roles").
//! Reshapes bytes without deciding meaning, key storage, or trust tiers.

use prost::Message;
use tradr_core::{
    AccountBroadcastKey, BroadcastKeyError, BroadcastKeyOffer, BroadcastKeyOfferError, UnixTime,
};

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;

/// Everything a `broadcast_key_offer_from_wire` call can refuse a peer for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastKeyWireError {
    /// The key was not exactly 32 bytes.
    InvalidKey(BroadcastKeyError),
    /// The generation was 0 or the creation time was at or before the epoch.
    InvalidOffer(BroadcastKeyOfferError),
}

impl std::fmt::Display for BroadcastKeyWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey(e) => write!(f, "broadcast key invalid: {e}"),
            Self::InvalidOffer(e) => write!(f, "broadcast key offer invalid: {e}"),
        }
    }
}

impl std::error::Error for BroadcastKeyWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidKey(e) => Some(e),
            Self::InvalidOffer(e) => Some(e),
        }
    }
}

/// Converts a wire `BroadcastKeyOffer` into a native `BroadcastKeyOffer` (docs/11).
pub fn broadcast_key_offer_from_wire(
    message: v1::BroadcastKeyOffer,
) -> Result<BroadcastKeyOffer, BroadcastKeyWireError> {
    let key =
        AccountBroadcastKey::from_bytes(&message.key).map_err(BroadcastKeyWireError::InvalidKey)?;
    let created_at = UnixTime::from_secs(message.created_at);
    BroadcastKeyOffer::new(key, message.generation, created_at)
        .map_err(BroadcastKeyWireError::InvalidOffer)
}

/// Converts a native `BroadcastKeyOffer` into a wire `BroadcastKeyOffer`.
pub fn broadcast_key_offer_to_wire(offer: &BroadcastKeyOffer) -> v1::BroadcastKeyOffer {
    v1::BroadcastKeyOffer {
        key: offer.key().as_bytes().to_vec(),
        generation: offer.generation(),
        created_at: offer.created_at().as_secs(),
    }
}

/// An error encoding or decoding a framed BroadcastKeyOffer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastKeyFrameError {
    /// The frame's type byte did not match the expected message type.
    WrongMessageType {
        /// The expected type byte.
        expected: u8,
        /// The type byte received on the frame.
        got: u8,
    },
    /// Framing could not encode or decode the byte sequence.
    Framing(FrameError),
    /// The protobuf payload could not be decoded.
    Decode(prost::DecodeError),
    /// The wire message contained invalid fields.
    Wire(BroadcastKeyWireError),
}

impl std::fmt::Display for BroadcastKeyFrameError {
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

impl std::error::Error for BroadcastKeyFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongMessageType { .. } => None,
            Self::Framing(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<FrameError> for BroadcastKeyFrameError {
    fn from(err: FrameError) -> Self {
        Self::Framing(err)
    }
}

impl From<prost::DecodeError> for BroadcastKeyFrameError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<BroadcastKeyWireError> for BroadcastKeyFrameError {
    fn from(err: BroadcastKeyWireError) -> Self {
        Self::Wire(err)
    }
}

/// Encodes a `BroadcastKeyOffer` to a framed message under `MessageType::BroadcastKeyOffer`.
pub fn encode_broadcast_key_offer_frame(
    offer: &BroadcastKeyOffer,
    max_frame_size: u32,
) -> Result<Vec<u8>, BroadcastKeyFrameError> {
    let wire = broadcast_key_offer_to_wire(offer);
    let payload = wire.encode_to_vec();
    encode_frame(
        MessageType::BroadcastKeyOffer.code(),
        &payload,
        max_frame_size,
    )
    .map_err(BroadcastKeyFrameError::Framing)
}

/// Decodes a framed `BroadcastKeyOffer` message into a native `BroadcastKeyOffer`.
pub fn decode_broadcast_key_offer_frame(
    frame: &Frame,
) -> Result<BroadcastKeyOffer, BroadcastKeyFrameError> {
    let expected = MessageType::BroadcastKeyOffer.code();
    if frame.type_code() != expected {
        return Err(BroadcastKeyFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire =
        v1::BroadcastKeyOffer::decode(frame.payload()).map_err(BroadcastKeyFrameError::Decode)?;
    broadcast_key_offer_from_wire(wire).map_err(BroadcastKeyFrameError::Wire)
}

//! Converts between the wire `LinkReply`/`LinkApprove`/`LinkDecline` and the
//! native `tradr_core::Link*` types (docs/11-account-linking.md, "What the
//! three linking messages carry"). This module reshapes bytes and nothing
//! else: no hash, no signature check, no `DeviceId` derivation. Deciding
//! meaning belongs one layer up.

use tradr_core::{
    DisplayName, HalfSecret, InviteId, LinkApprove, LinkDecline, LinkDeclineReason, LinkError,
    LinkId, LinkReply, PublicKeyPoint, PublicKeyPointError,
};

use prost::Message;

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;

/// Everything a `link_reply_from_wire`, `link_approve_from_wire` or
/// `link_decline_from_wire` call can refuse a peer for. No variant carries a
/// value from the wire (rule F4): a wrong length is reported by length
/// alone, and nothing carries any part of `Attestation.id_token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkWireError {
    /// `LinkReply.device` was absent.
    MissingDevice,
    /// `LinkReply.attestation` was absent.
    MissingAttestation,
    /// `Attestation.id_token` was the empty string. proto3 cannot tell an
    /// absent string from an empty one, and the token is the whole of what
    /// this exchange verifies.
    EmptyAttestationToken,
    /// `invite_id` was not exactly `INVITE_ID_LEN` bytes.
    InvalidInviteId(LinkError),
    /// `DeviceInfo.identity_pub` was not a valid public key point.
    InvalidIdentityPub(PublicKeyPointError),
    /// `DeviceInfo.agreement_pub` was not a valid public key point.
    InvalidAgreementPub(PublicKeyPointError),
    /// `LinkReply.half_secret` was not exactly `HALF_SECRET_LEN` bytes.
    InvalidHalfSecret(LinkError),
    /// `LinkApprove.link_id` was not exactly `LINK_ID_LEN` bytes.
    InvalidLinkId(LinkError),
}

impl std::fmt::Display for LinkWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDevice => write!(f, "LinkReply.device is absent"),
            Self::MissingAttestation => write!(f, "LinkReply.attestation is absent"),
            Self::EmptyAttestationToken => write!(f, "Attestation.id_token is empty"),
            Self::InvalidInviteId(e) => write!(f, "invite_id invalid: {e}"),
            Self::InvalidIdentityPub(e) => write!(f, "DeviceInfo.identity_pub invalid: {e}"),
            Self::InvalidAgreementPub(e) => write!(f, "DeviceInfo.agreement_pub invalid: {e}"),
            Self::InvalidHalfSecret(e) => write!(f, "half_secret invalid: {e}"),
            Self::InvalidLinkId(e) => write!(f, "link_id invalid: {e}"),
        }
    }
}

impl std::error::Error for LinkWireError {}

/// Converts a wire `LinkReply` into a `LinkReply` (docs/11). `device_id`,
/// `platform` and `capabilities` are read by nothing; `display_name` is
/// dropped rather than refused when invalid; `attestation.issuer` and
/// `issued_at` are discarded in favor of the token's own claims.
pub fn link_reply_from_wire(message: v1::LinkReply) -> Result<LinkReply, LinkWireError> {
    let invite_id =
        InviteId::from_bytes(&message.invite_id).map_err(LinkWireError::InvalidInviteId)?;

    let device = message.device.ok_or(LinkWireError::MissingDevice)?;
    let identity_pub = PublicKeyPoint::from_bytes(&device.identity_pub)
        .map_err(LinkWireError::InvalidIdentityPub)?;
    let agreement_pub = PublicKeyPoint::from_bytes(&device.agreement_pub)
        .map_err(LinkWireError::InvalidAgreementPub)?;
    let display_name = DisplayName::new(&device.display_name).ok();

    let attestation = message
        .attestation
        .ok_or(LinkWireError::MissingAttestation)?;
    if attestation.id_token.is_empty() {
        return Err(LinkWireError::EmptyAttestationToken);
    }

    let half_secret =
        HalfSecret::from_bytes(&message.half_secret).map_err(LinkWireError::InvalidHalfSecret)?;

    let mut reply = LinkReply::new(
        invite_id,
        identity_pub,
        agreement_pub,
        attestation.id_token,
        half_secret,
    );
    if let Some(display_name) = display_name {
        reply = reply.with_display_name(display_name);
    }
    Ok(reply)
}

/// Converts a `LinkReply` into a wire `LinkReply`. Infallible: `LinkReply`
/// is already validated. `device_id`, `platform`, `capabilities`, `issuer`
/// and `issued_at` are written at wire defaults, since nothing on the
/// native side carries them.
pub fn link_reply_to_wire(reply: &LinkReply) -> v1::LinkReply {
    v1::LinkReply {
        invite_id: reply.invite_id().as_bytes().to_vec(),
        device: Some(v1::DeviceInfo {
            device_id: Vec::new(),
            identity_pub: reply.identity_pub().as_bytes().to_vec(),
            agreement_pub: reply.agreement_pub().as_bytes().to_vec(),
            display_name: reply
                .display_name()
                .map(|name| name.as_str().to_string())
                .unwrap_or_default(),
            platform: v1::Platform::Unspecified as i32,
            capabilities: 0,
        }),
        attestation: Some(v1::Attestation {
            id_token: reply.attestation_token().to_string(),
            issuer: String::new(),
            issued_at: 0,
        }),
        half_secret: reply.half_secret().as_bytes().to_vec(),
    }
}

/// Converts a wire `LinkApprove` into a `LinkApprove`, refusing an
/// `invite_id` or `link_id` of the wrong length.
pub fn link_approve_from_wire(message: v1::LinkApprove) -> Result<LinkApprove, LinkWireError> {
    let invite_id =
        InviteId::from_bytes(&message.invite_id).map_err(LinkWireError::InvalidInviteId)?;
    let link_id = LinkId::from_bytes(&message.link_id).map_err(LinkWireError::InvalidLinkId)?;
    Ok(LinkApprove::new(invite_id, link_id))
}

/// Converts a `LinkApprove` into a wire `LinkApprove`. Infallible.
pub fn link_approve_to_wire(approve: &LinkApprove) -> v1::LinkApprove {
    v1::LinkApprove {
        invite_id: approve.invite_id().as_bytes().to_vec(),
        link_id: approve.link_id().as_bytes().to_vec(),
    }
}

/// Converts a wire `LinkDecline` into a `LinkDecline`, refusing an
/// `invite_id` of the wrong length. `reason` decorates and decides
/// nothing: an unspecified or unrecognised value is dropped and the
/// decline still stands.
pub fn link_decline_from_wire(message: v1::LinkDecline) -> Result<LinkDecline, LinkWireError> {
    let invite_id =
        InviteId::from_bytes(&message.invite_id).map_err(LinkWireError::InvalidInviteId)?;
    let reason = LinkDeclineReason::try_from(message.reason).ok();
    Ok(LinkDecline::new(invite_id, reason))
}

/// Converts a `LinkDecline` into a wire `LinkDecline`. Infallible.
pub fn link_decline_to_wire(decline: &LinkDecline) -> v1::LinkDecline {
    v1::LinkDecline {
        invite_id: decline.invite_id().as_bytes().to_vec(),
        reason: decline.reason().map(i32::from).unwrap_or(0),
    }
}

/// An error encoding or decoding a framed LinkReply, LinkApprove or
/// LinkDecline message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFrameError {
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
    Wire(LinkWireError),
}

impl std::fmt::Display for LinkFrameError {
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

impl std::error::Error for LinkFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongMessageType { .. } => None,
            Self::Framing(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<FrameError> for LinkFrameError {
    fn from(err: FrameError) -> Self {
        Self::Framing(err)
    }
}

impl From<prost::DecodeError> for LinkFrameError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<LinkWireError> for LinkFrameError {
    fn from(err: LinkWireError) -> Self {
        Self::Wire(err)
    }
}

/// Encodes a `LinkReply` to a framed LinkReply message under `MessageType::LinkReply`.
pub fn encode_link_reply_frame(
    reply: &LinkReply,
    max_frame_size: u32,
) -> Result<Vec<u8>, LinkFrameError> {
    let wire = link_reply_to_wire(reply);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::LinkReply.code(), &payload, max_frame_size)
        .map_err(LinkFrameError::Framing)
}

/// Decodes a framed LinkReply message into a native `LinkReply`.
pub fn decode_link_reply_frame(frame: &Frame) -> Result<LinkReply, LinkFrameError> {
    let expected = MessageType::LinkReply.code();
    if frame.type_code() != expected {
        return Err(LinkFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::LinkReply::decode(frame.payload()).map_err(LinkFrameError::Decode)?;
    link_reply_from_wire(wire).map_err(LinkFrameError::Wire)
}

/// Encodes a `LinkApprove` to a framed LinkApprove message under `MessageType::LinkApprove`.
pub fn encode_link_approve_frame(
    approve: &LinkApprove,
    max_frame_size: u32,
) -> Result<Vec<u8>, LinkFrameError> {
    let wire = link_approve_to_wire(approve);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::LinkApprove.code(), &payload, max_frame_size)
        .map_err(LinkFrameError::Framing)
}

/// Decodes a framed LinkApprove message into a native `LinkApprove`.
pub fn decode_link_approve_frame(frame: &Frame) -> Result<LinkApprove, LinkFrameError> {
    let expected = MessageType::LinkApprove.code();
    if frame.type_code() != expected {
        return Err(LinkFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::LinkApprove::decode(frame.payload()).map_err(LinkFrameError::Decode)?;
    link_approve_from_wire(wire).map_err(LinkFrameError::Wire)
}

/// Encodes a `LinkDecline` to a framed LinkDecline message under `MessageType::LinkDecline`.
pub fn encode_link_decline_frame(
    decline: &LinkDecline,
    max_frame_size: u32,
) -> Result<Vec<u8>, LinkFrameError> {
    let wire = link_decline_to_wire(decline);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::LinkDecline.code(), &payload, max_frame_size)
        .map_err(LinkFrameError::Framing)
}

/// Decodes a framed LinkDecline message into a native `LinkDecline`.
pub fn decode_link_decline_frame(frame: &Frame) -> Result<LinkDecline, LinkFrameError> {
    let expected = MessageType::LinkDecline.code();
    if frame.type_code() != expected {
        return Err(LinkFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::LinkDecline::decode(frame.payload()).map_err(LinkFrameError::Decode)?;
    link_decline_from_wire(wire).map_err(LinkFrameError::Wire)
}

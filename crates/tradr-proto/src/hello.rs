//! Converts between wire `Hello`/`HelloAck` and native `PeerHello`/`PeerHelloAck`
//! (docs/04, DCR-053). This module reshapes bytes and nothing else: no
//! signature check, no hash, no `DeviceId` derivation. Deciding meaning
//! belongs to `tradr-identity`, which never sees a generated wire type.

use tradr_core::{
    Capabilities, DisplayName, HELLO_NONCE_LEN, HelloNonce, KeyBinding, PeerHello, PeerHelloAck,
    PublicKeyPoint, PublicKeyPointError, Signature, TrustTier, TrustTierError, UnixTime,
    VersionRange, VersionRangeError,
};

use prost::Message;

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;

/// Everything a `peer_hello_from_wire` or `peer_hello_ack_from_wire` call
/// can refuse an untrusted peer for. Every variant names the field at
/// fault, and none carries the value at fault (rule F4): a wrong-length
/// key or nonce is reported by length alone, never by its bytes, and no
/// variant carries anything from `Attestation.id_token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloWireError {
    /// `Hello.device` was absent. proto3 makes message fields optional,
    /// so a peer can send nothing here; a `Default::default()` would give
    /// it a `DeviceInfo` with empty keys, which is what an attacker sends.
    MissingDevice,
    /// `Hello.attestation` was absent.
    MissingAttestation,
    /// `Hello.key_binding` was absent.
    MissingKeyBinding,
    /// `Hello.min_version` / `max_version` did not form a range the
    /// native `VersionRange` accepts.
    InvalidVersionRange(VersionRangeError),
    /// `DeviceInfo.identity_pub` was not a valid public key point.
    InvalidIdentityPub(PublicKeyPointError),
    /// `DeviceInfo.agreement_pub` was not a valid public key point.
    InvalidAgreementPub(PublicKeyPointError),
    /// `KeyBinding.agreement_pub` was not a valid public key point.
    InvalidKeyBindingAgreementPub(PublicKeyPointError),
    /// `Hello.nonce` was not exactly `HELLO_NONCE_LEN` bytes.
    InvalidNonce {
        /// The length the wire actually carried.
        len: usize,
    },
    /// `HelloAck.assigned_tier` named `TRUST_TIER_UNSPECIFIED` or a value
    /// no `TrustTier` variant defines. An unspecified tier must never be
    /// treated as a grant.
    InvalidAssignedTier(TrustTierError),
}

impl std::fmt::Display for HelloWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDevice => write!(f, "Hello.device is absent"),
            Self::MissingAttestation => write!(f, "Hello.attestation is absent"),
            Self::MissingKeyBinding => write!(f, "Hello.key_binding is absent"),
            Self::InvalidVersionRange(e) => write!(f, "Hello version range invalid: {e}"),
            Self::InvalidIdentityPub(e) => {
                write!(f, "DeviceInfo.identity_pub invalid: {e}")
            }
            Self::InvalidAgreementPub(e) => {
                write!(f, "DeviceInfo.agreement_pub invalid: {e}")
            }
            Self::InvalidKeyBindingAgreementPub(e) => {
                write!(f, "KeyBinding.agreement_pub invalid: {e}")
            }
            Self::InvalidNonce { len } => {
                write!(f, "Hello.nonce must be {HELLO_NONCE_LEN} bytes, got {len}")
            }
            Self::InvalidAssignedTier(e) => {
                write!(f, "HelloAck.assigned_tier invalid: {e}")
            }
        }
    }
}

impl std::error::Error for HelloWireError {}

/// Converts a wire `Hello` into a `PeerHello` (DCR-053). `capabilities` is
/// narrowed to low 16 bits and invalid/long `display_name` is dropped.
/// `attestation.issuer`/`issued_at` are discarded in favor of token claims.
/// Keys, nonce and version ranges are strictly validated.
pub fn peer_hello_from_wire(message: v1::Hello) -> Result<PeerHello, HelloWireError> {
    let versions = VersionRange::new(message.min_version, message.max_version)
        .map_err(HelloWireError::InvalidVersionRange)?;

    let device = message.device.ok_or(HelloWireError::MissingDevice)?;
    let identity_pub = PublicKeyPoint::from_bytes(&device.identity_pub)
        .map_err(HelloWireError::InvalidIdentityPub)?;
    let agreement_pub = PublicKeyPoint::from_bytes(&device.agreement_pub)
        .map_err(HelloWireError::InvalidAgreementPub)?;
    let capabilities = Capabilities::from_bits(device.capabilities as u16);
    let display_name = DisplayName::new(&device.display_name).ok();

    let attestation = message
        .attestation
        .ok_or(HelloWireError::MissingAttestation)?;

    let key_binding_wire = message
        .key_binding
        .ok_or(HelloWireError::MissingKeyBinding)?;
    let key_binding_agreement_pub = PublicKeyPoint::from_bytes(&key_binding_wire.agreement_pub)
        .map_err(HelloWireError::InvalidKeyBindingAgreementPub)?;
    let key_binding = KeyBinding::new(
        key_binding_agreement_pub,
        Signature::from_bytes(key_binding_wire.signature),
        UnixTime::from_secs(key_binding_wire.not_after),
    );

    let nonce_bytes: [u8; HELLO_NONCE_LEN] = message
        .nonce
        .try_into()
        .map_err(|bytes: Vec<u8>| HelloWireError::InvalidNonce { len: bytes.len() })?;
    let nonce = HelloNonce::from_bytes(nonce_bytes);

    let mut hello = PeerHello::new(
        versions,
        identity_pub,
        agreement_pub,
        attestation.id_token,
        key_binding,
        nonce,
        capabilities,
    );
    if let Some(display_name) = display_name {
        hello = hello.with_display_name(display_name);
    }
    Ok(hello)
}

/// Converts a `PeerHello` into a wire `Hello`. Infallible: `PeerHello` is
/// already validated. `device_id`, `platform`, `issuer` and `issued_at`
/// are written at wire defaults (docs/04 step 2 recomputes Device ID from
/// `identity_pub` rather than trusting wire copy).
pub fn peer_hello_to_wire(hello: &PeerHello) -> v1::Hello {
    v1::Hello {
        min_version: hello.versions().min(),
        max_version: hello.versions().max(),
        device: Some(v1::DeviceInfo {
            device_id: Vec::new(),
            identity_pub: hello.identity_pub().as_bytes().to_vec(),
            agreement_pub: hello.agreement_pub().as_bytes().to_vec(),
            display_name: hello
                .display_name()
                .map(|name| name.as_str().to_string())
                .unwrap_or_default(),
            platform: v1::Platform::Unspecified as i32,
            capabilities: hello.capabilities().bits() as u32,
        }),
        attestation: Some(v1::Attestation {
            id_token: hello.attestation_token().to_string(),
            issuer: String::new(),
            issued_at: 0,
        }),
        key_binding: Some(v1::KeyBinding {
            agreement_pub: hello.key_binding().agreement_pub().as_bytes().to_vec(),
            signature: hello.key_binding().signature().as_bytes().to_vec(),
            not_after: hello.key_binding().not_after().as_secs(),
        }),
        nonce: hello.nonce().as_bytes().to_vec(),
    }
}

/// Converts a wire `HelloAck` into a `PeerHelloAck`, refusing
/// `assigned_tier` values `TryFrom<i32> for TrustTier` refuses:
/// `TRUST_TIER_UNSPECIFIED` and any integer no variant defines. An
/// unspecified tier must never be treated as a grant.
pub fn peer_hello_ack_from_wire(message: v1::HelloAck) -> Result<PeerHelloAck, HelloWireError> {
    let assigned_tier =
        TrustTier::try_from(message.assigned_tier).map_err(HelloWireError::InvalidAssignedTier)?;
    Ok(PeerHelloAck::new(
        message.negotiated_version,
        message.max_frame_size,
        Signature::from_bytes(message.nonce_signature),
        assigned_tier,
    ))
}

/// Converts a `PeerHelloAck` into a wire `HelloAck`. Infallible: a
/// `PeerHelloAck` was already validated when it was built.
///
/// `visible_shares` is written empty: `PeerHelloAck` carries no Share
/// vocabulary, since Shares arrive in M3.
pub fn peer_hello_ack_to_wire(ack: &PeerHelloAck) -> v1::HelloAck {
    v1::HelloAck {
        negotiated_version: ack.negotiated_version(),
        max_frame_size: ack.max_frame_size(),
        nonce_signature: ack.nonce_signature().as_bytes().to_vec(),
        assigned_tier: i32::from(ack.assigned_tier()),
        visible_shares: Vec::new(),
    }
}

/// An error encoding or decoding a framed Hello or HelloAck message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloFrameError {
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
    Wire(HelloWireError),
}

impl std::fmt::Display for HelloFrameError {
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

impl std::error::Error for HelloFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongMessageType { .. } => None,
            Self::Framing(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<FrameError> for HelloFrameError {
    fn from(err: FrameError) -> Self {
        Self::Framing(err)
    }
}

impl From<prost::DecodeError> for HelloFrameError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<HelloWireError> for HelloFrameError {
    fn from(err: HelloWireError) -> Self {
        Self::Wire(err)
    }
}

/// Encodes a `PeerHello` to a framed Hello message under `MessageType::Hello`.
pub fn encode_hello_frame(
    hello: &PeerHello,
    max_frame_size: u32,
) -> Result<Vec<u8>, HelloFrameError> {
    let wire = peer_hello_to_wire(hello);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::Hello.code(), &payload, max_frame_size)
        .map_err(HelloFrameError::Framing)
}

/// Decodes a framed Hello message into a native `PeerHello`.
pub fn decode_hello_frame(frame: &Frame) -> Result<PeerHello, HelloFrameError> {
    let expected = MessageType::Hello.code();
    if frame.type_code() != expected {
        return Err(HelloFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::Hello::decode(frame.payload()).map_err(HelloFrameError::Decode)?;
    peer_hello_from_wire(wire).map_err(HelloFrameError::Wire)
}

/// Encodes a `PeerHelloAck` to a framed HelloAck message under `MessageType::HelloAck`.
pub fn encode_hello_ack_frame(
    ack: &PeerHelloAck,
    max_frame_size: u32,
) -> Result<Vec<u8>, HelloFrameError> {
    let wire = peer_hello_ack_to_wire(ack);
    let payload = wire.encode_to_vec();
    encode_frame(MessageType::HelloAck.code(), &payload, max_frame_size)
        .map_err(HelloFrameError::Framing)
}

/// Decodes a framed HelloAck message into a native `PeerHelloAck`.
pub fn decode_hello_ack_frame(frame: &Frame) -> Result<PeerHelloAck, HelloFrameError> {
    let expected = MessageType::HelloAck.code();
    if frame.type_code() != expected {
        return Err(HelloFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::HelloAck::decode(frame.payload()).map_err(HelloFrameError::Decode)?;
    peer_hello_ack_from_wire(wire).map_err(HelloFrameError::Wire)
}

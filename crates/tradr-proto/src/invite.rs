//! Converts between the wire `Invite` and the native `tradr_core::Invite`
//! (docs/11-account-linking.md, "What the Invite carries, and how it
//! travels"), and encodes the result as the base64url blob a QR or a
//! pasted chat message carries. An `Invite` is never framed, so this
//! module names no `Frame` and no `MessageType`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use prost::Message;

use tradr_core::{
    DisplayName, HalfSecret, Invite, InviteId, LinkError, PublicKeyPoint, PublicKeyPointError,
    UnixTime,
};

use crate::v1;

/// The version byte a blob opens with (docs/11). A blob opening with any
/// other byte is refused as an invite this build cannot read, a different
/// sentence from a malformed one.
pub const INVITE_BLOB_VERSION: u8 = 0x01;

/// The longest a pasted blob may be before it is even decoded (docs/11,
/// "Why an invite's size is a design constraint here and nowhere else").
pub const INVITE_BLOB_MAX_CHARS: usize = 4096;

/// Everything an `invite_from_wire` call can refuse a blob for. No variant
/// carries a value read off the wire (rule F4): a wrong length is reported
/// by length alone, and nothing carries any part of `Attestation.id_token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteWireError {
    /// `Invite.device` was absent.
    MissingDevice,
    /// `Invite.attestation` was absent.
    MissingAttestation,
    /// `Attestation.id_token` was the empty string. proto3 cannot tell an
    /// absent string from an empty one, and the token is the whole of what
    /// a replier verifies before answering.
    EmptyAttestationToken,
    /// `invite_id` was not exactly `INVITE_ID_LEN` bytes.
    InvalidInviteId(LinkError),
    /// `DeviceInfo.identity_pub` was not a valid public key point.
    InvalidIdentityPub(PublicKeyPointError),
    /// `DeviceInfo.agreement_pub` was not a valid public key point.
    InvalidAgreementPub(PublicKeyPointError),
    /// `Invite.half_secret` was not exactly `HALF_SECRET_LEN` bytes.
    InvalidHalfSecret(LinkError),
    /// `expires_at` was zero. proto3 cannot tell an absent `int64` from a
    /// zero one, and an invite that expired in 1970 is not what any writer
    /// meant.
    ZeroExpiresAt,
}

impl std::fmt::Display for InviteWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDevice => write!(f, "Invite.device is absent"),
            Self::MissingAttestation => write!(f, "Invite.attestation is absent"),
            Self::EmptyAttestationToken => write!(f, "Attestation.id_token is empty"),
            Self::InvalidInviteId(e) => write!(f, "invite_id invalid: {e}"),
            Self::InvalidIdentityPub(e) => write!(f, "DeviceInfo.identity_pub invalid: {e}"),
            Self::InvalidAgreementPub(e) => write!(f, "DeviceInfo.agreement_pub invalid: {e}"),
            Self::InvalidHalfSecret(e) => write!(f, "half_secret invalid: {e}"),
            Self::ZeroExpiresAt => write!(f, "expires_at is zero"),
        }
    }
}

impl std::error::Error for InviteWireError {}

/// Converts a wire `Invite` into an `Invite` (docs/11). `device_id`,
/// `platform` and `capabilities` are read by nothing; `display_name` is
/// dropped rather than refused when invalid; `attestation.issuer` and
/// `issued_at` are discarded in favor of the token's own claims.
pub fn invite_from_wire(message: v1::Invite) -> Result<Invite, InviteWireError> {
    let invite_id =
        InviteId::from_bytes(&message.invite_id).map_err(InviteWireError::InvalidInviteId)?;

    let device = message.device.ok_or(InviteWireError::MissingDevice)?;
    let identity_pub = PublicKeyPoint::from_bytes(&device.identity_pub)
        .map_err(InviteWireError::InvalidIdentityPub)?;
    let agreement_pub = PublicKeyPoint::from_bytes(&device.agreement_pub)
        .map_err(InviteWireError::InvalidAgreementPub)?;
    let display_name = DisplayName::new(&device.display_name).ok();

    let attestation = message
        .attestation
        .ok_or(InviteWireError::MissingAttestation)?;
    if attestation.id_token.is_empty() {
        return Err(InviteWireError::EmptyAttestationToken);
    }

    let half_secret =
        HalfSecret::from_bytes(&message.half_secret).map_err(InviteWireError::InvalidHalfSecret)?;

    if message.expires_at == 0 {
        return Err(InviteWireError::ZeroExpiresAt);
    }
    let expires_at = UnixTime::from_secs(message.expires_at);

    let mut invite = Invite::new(
        invite_id,
        identity_pub,
        agreement_pub,
        attestation.id_token,
        half_secret,
        expires_at,
    );
    if let Some(display_name) = display_name {
        invite = invite.with_display_name(display_name);
    }
    Ok(invite)
}

/// Converts an `Invite` into a wire `Invite`. Infallible: `Invite` is
/// already validated. `device_id`, `platform`, `capabilities`, `issuer`
/// and `issued_at` are written at wire defaults, since nothing on the
/// native side carries them.
pub fn invite_to_wire(invite: &Invite) -> v1::Invite {
    v1::Invite {
        invite_id: invite.invite_id().as_bytes().to_vec(),
        device: Some(v1::DeviceInfo {
            device_id: Vec::new(),
            identity_pub: invite.identity_pub().as_bytes().to_vec(),
            agreement_pub: invite.agreement_pub().as_bytes().to_vec(),
            display_name: invite
                .display_name()
                .map(|name| name.as_str().to_string())
                .unwrap_or_default(),
            platform: v1::Platform::Unspecified as i32,
            capabilities: 0,
        }),
        attestation: Some(v1::Attestation {
            id_token: invite.attestation_token().to_string(),
            issuer: String::new(),
            issued_at: 0,
        }),
        half_secret: invite.half_secret().as_bytes().to_vec(),
        expires_at: invite.expires_at().as_secs(),
    }
}

/// Why a pasted or scanned blob could not be turned into an `Invite`.
#[derive(Debug)]
pub enum InviteBlobError {
    /// The blob's character length exceeded `INVITE_BLOB_MAX_CHARS`,
    /// checked before any decoding.
    TooLong {
        /// The number of characters the blob actually had.
        actual: usize,
    },
    /// The blob was not valid unpadded base64url.
    Base64(base64::DecodeError),
    /// The blob decoded to zero bytes, leaving no version byte to read.
    Empty,
    /// The blob's leading byte was not `INVITE_BLOB_VERSION`: an invite
    /// made by a build this one cannot read, not a malformed one.
    UnsupportedVersion(u8),
    /// The bytes following the version byte were not a valid `v1::Invite`.
    Decode(prost::DecodeError),
    /// The decoded `v1::Invite` contained invalid fields.
    Wire(InviteWireError),
}

impl std::fmt::Display for InviteBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { actual } => write!(
                f,
                "invite blob is {actual} characters, longer than {INVITE_BLOB_MAX_CHARS}"
            ),
            Self::Base64(e) => write!(f, "invite blob is not valid base64url: {e}"),
            Self::Empty => write!(f, "invite blob decoded to zero bytes"),
            Self::UnsupportedVersion(byte) => {
                write!(f, "invite blob version 0x{byte:02x} is not supported")
            }
            Self::Decode(e) => write!(f, "invite blob protobuf decode error: {e}"),
            Self::Wire(e) => write!(f, "invite blob wire validation error: {e}"),
        }
    }
}

impl std::error::Error for InviteBlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLong { .. } | Self::Empty | Self::UnsupportedVersion(_) => None,
            Self::Base64(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<base64::DecodeError> for InviteBlobError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64(err)
    }
}

impl From<prost::DecodeError> for InviteBlobError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<InviteWireError> for InviteBlobError {
    fn from(err: InviteWireError) -> Self {
        Self::Wire(err)
    }
}

/// Encodes `invite` as the base64url blob a QR or a pasted chat message
/// carries: `INVITE_BLOB_VERSION` followed by the encoded `v1::Invite`
/// (docs/11). The QR encodes exactly this string, so there is one payload
/// and one parser.
pub fn invite_to_blob(invite: &Invite) -> String {
    let encoded = invite_to_wire(invite).encode_to_vec();
    let mut bytes = Vec::with_capacity(1 + encoded.len());
    bytes.push(INVITE_BLOB_VERSION);
    bytes.extend_from_slice(&encoded);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes the base64url blob a QR or a pasted chat message carries back
/// into an `Invite` (docs/11). The QR encodes exactly this string, so
/// there is one parser. Refuses an over-length blob before decoding it.
pub fn invite_from_blob(blob: &str) -> Result<Invite, InviteBlobError> {
    if blob.len() > INVITE_BLOB_MAX_CHARS {
        return Err(InviteBlobError::TooLong { actual: blob.len() });
    }

    let bytes = URL_SAFE_NO_PAD.decode(blob)?;
    let (version, body) = bytes.split_first().ok_or(InviteBlobError::Empty)?;
    if *version != INVITE_BLOB_VERSION {
        return Err(InviteBlobError::UnsupportedVersion(*version));
    }

    let wire = v1::Invite::decode(body)?;
    Ok(invite_from_wire(wire)?)
}

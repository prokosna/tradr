//! The mDNS TXT record codec (docs/03, "1. mDNS / DNS-SD -- the same LAN,
//! Tier 0"). Pure encode/decode of the six wire values; no daemon, socket,
//! or executor appears here.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tradr_core::{Capabilities, DeviceId, DisplayName, DisplayNameError};

/// The number of bytes an Agreement Key Tag occupies: the first 8 bytes of
/// `BLAKE3(agreement_pub)` (docs/03, and CONTEXT.md's "Agreement Key Tag",
/// which is not the Fingerprint).
pub const AGREEMENT_KEY_TAG_LEN: usize = 8;

/// The most bytes a `Platform` token may occupy.
pub const PLATFORM_MAX_LEN: usize = 16;

/// docs/03's TXT `p`: an opaque, validated token and never a closed set.
/// Change Drill D7 adds iOS, and a device must not become invisible to
/// this build because it named a platform this build has not heard of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform(String);

/// An error constructing a `Platform` from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    /// The input was empty.
    Empty,
    /// The input was longer than `PLATFORM_MAX_LEN` bytes.
    TooLong(usize),
    /// The input contained a control character.
    ControlCharacter(char),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "platform is empty"),
            Self::TooLong(len) => {
                write!(
                    f,
                    "platform must be at most {PLATFORM_MAX_LEN} bytes, got {len}"
                )
            }
            Self::ControlCharacter(c) => write!(f, "platform contains control character {c:?}"),
        }
    }
}

impl std::error::Error for PlatformError {}

impl Platform {
    /// Validates `s` against the same two rules as `Candidate::new`, plus
    /// the length bound `PLATFORM_MAX_LEN`: reject empty, reject a control
    /// character, reject over-length. Checks nothing else, so an
    /// unrecognised value such as `ios` is accepted -- Change Drill D7.
    pub fn new(s: &str) -> Result<Self, PlatformError> {
        if s.is_empty() {
            return Err(PlatformError::Empty);
        }
        if s.len() > PLATFORM_MAX_LEN {
            return Err(PlatformError::TooLong(s.len()));
        }
        if let Some(c) = s.chars().find(|c| c.is_control()) {
            return Err(PlatformError::ControlCharacter(c));
        }
        Ok(Self(s.to_string()))
    }

    /// The token exactly as given to `new`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An error reading a peer's TXT record.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxtError {
    /// A required key was absent.
    MissingKey(&'static str),
    /// `v` did not parse as a decimal `u32`.
    MalformedVersion,
    /// `id` did not decode to exactly `DEVICE_ID_LEN` bytes.
    MalformedDeviceId,
    /// `pk` did not decode to exactly `AGREEMENT_KEY_TAG_LEN` bytes.
    MalformedAgreementKeyTag,
    /// `c` did not parse as a decimal `u16`.
    MalformedCapabilities,
    /// `n` was present but failed `DisplayName::new`.
    InvalidDisplayName(DisplayNameError),
    /// `p` failed `Platform::new`.
    InvalidPlatform(PlatformError),
}

impl fmt::Display for TxtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey(key) => write!(f, "TXT record is missing required key {key:?}"),
            Self::MalformedVersion => write!(f, "TXT record's v is not a valid decimal u32"),
            Self::MalformedDeviceId => {
                write!(f, "TXT record's id is not a valid base64url device id")
            }
            Self::MalformedAgreementKeyTag => {
                write!(
                    f,
                    "TXT record's pk is not a valid base64url agreement key tag"
                )
            }
            Self::MalformedCapabilities => {
                write!(f, "TXT record's c is not a valid decimal u16")
            }
            Self::InvalidDisplayName(e) => write!(f, "TXT record's n is invalid: {e}"),
            Self::InvalidPlatform(e) => write!(f, "TXT record's p is invalid: {e}"),
        }
    }
}

impl std::error::Error for TxtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDisplayName(e) => Some(e),
            Self::InvalidPlatform(e) => Some(e),
            _ => None,
        }
    }
}

/// The six values docs/03's TXT table defines, as this device publishes
/// them or as read from a peer's advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    version: u32,
    device_id: DeviceId,
    agreement_key_tag: [u8; AGREEMENT_KEY_TAG_LEN],
    display_name: Option<DisplayName>,
    platform: Platform,
    capabilities: Capabilities,
}

// Looks up the first occurrence of `key` in `pairs`, matching rule 8:
// a duplicate key is resolved by taking the first occurrence.
fn find_first<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

impl TxtRecord {
    /// `v`, the protocol major version this build speaks.
    pub const PROTOCOL_VERSION: u32 = 1;

    /// Builds the record this device publishes.
    pub fn new(
        device_id: DeviceId,
        agreement_key_tag: [u8; AGREEMENT_KEY_TAG_LEN],
        display_name: Option<DisplayName>,
        capabilities: Capabilities,
        platform: Platform,
    ) -> Self {
        Self {
            version: Self::PROTOCOL_VERSION,
            device_id,
            agreement_key_tag,
            display_name,
            platform,
            capabilities,
        }
    }

    /// The key/value pairs to publish, in the deterministic order
    /// `v, id, pk, n, p, c`. `n` is omitted entirely when there is no
    /// display name, never emitted as an empty value.
    pub fn to_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::with_capacity(6);
        pairs.push(("v".to_string(), self.version.to_string()));
        pairs.push((
            "id".to_string(),
            URL_SAFE_NO_PAD.encode(self.device_id.as_bytes()),
        ));
        pairs.push((
            "pk".to_string(),
            URL_SAFE_NO_PAD.encode(self.agreement_key_tag),
        ));
        if let Some(name) = &self.display_name {
            pairs.push(("n".to_string(), name.as_str().to_string()));
        }
        pairs.push(("p".to_string(), self.platform.as_str().to_string()));
        pairs.push(("c".to_string(), self.capabilities.bits().to_string()));
        pairs
    }

    /// Reads a peer's record. `Err` is a record that is malformed; an
    /// unrecognised key is ignored, and an unrecognised `v` is accepted and
    /// preserved rather than rejected -- filtering by version belongs to
    /// `Hello` (docs/04, "Versioning").
    pub fn parse(pairs: &[(String, String)]) -> Result<TxtRecord, TxtError> {
        let version_raw = find_first(pairs, "v").ok_or(TxtError::MissingKey("v"))?;
        let version: u32 = version_raw
            .parse()
            .map_err(|_| TxtError::MalformedVersion)?;

        let id_raw = find_first(pairs, "id").ok_or(TxtError::MissingKey("id"))?;
        let id_bytes = URL_SAFE_NO_PAD
            .decode(id_raw)
            .map_err(|_| TxtError::MalformedDeviceId)?;
        let device_id = DeviceId::from_bytes(&id_bytes).map_err(|_| TxtError::MalformedDeviceId)?;

        let pk_raw = find_first(pairs, "pk").ok_or(TxtError::MissingKey("pk"))?;
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(pk_raw)
            .map_err(|_| TxtError::MalformedAgreementKeyTag)?;
        let agreement_key_tag: [u8; AGREEMENT_KEY_TAG_LEN] = pk_bytes
            .try_into()
            .map_err(|_| TxtError::MalformedAgreementKeyTag)?;

        let display_name = match find_first(pairs, "n") {
            Some(n) => Some(DisplayName::new(n).map_err(TxtError::InvalidDisplayName)?),
            None => None,
        };

        let platform_raw = find_first(pairs, "p").ok_or(TxtError::MissingKey("p"))?;
        let platform = Platform::new(platform_raw).map_err(TxtError::InvalidPlatform)?;

        let c_raw = find_first(pairs, "c").ok_or(TxtError::MissingKey("c"))?;
        let c: u16 = c_raw.parse().map_err(|_| TxtError::MalformedCapabilities)?;
        let capabilities = Capabilities::from_bits(c);

        Ok(TxtRecord {
            version,
            device_id,
            agreement_key_tag,
            display_name,
            platform,
            capabilities,
        })
    }

    /// The protocol major version read from `v`, whatever value it was --
    /// never filtered here.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The peer's Device ID.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The peer's Agreement Key Tag: the first 8 bytes of
    /// `BLAKE3(agreement_pub)`, not the Fingerprint.
    pub fn agreement_key_tag(&self) -> [u8; AGREEMENT_KEY_TAG_LEN] {
        self.agreement_key_tag
    }

    /// The name the peer publishes, if any.
    pub fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    /// The capability bitmask the peer published, reserved bits included.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// The platform token the peer published.
    pub fn platform(&self) -> &Platform {
        &self.platform
    }
}

//! The BLE advertisement codec (docs/03, ADR-0019).

use std::fmt;

use tradr_core::Capabilities;

use crate::eid::{EID_LEN, Eid};

/// The advertisement payload version (ADR-0019).
pub const ADVERTISEMENT_VERSION: u8 = 0x01;

/// The number of bytes in the Service Data payload (ADR-0019).
pub const SERVICE_DATA_LEN: usize = 10;

/// The overhead in bytes for the 128-bit Service Data AD structure (ADR-0019).
pub const AD_STRUCTURE_OVERHEAD: usize = 18;

/// The length in bytes of the Flags AD structure written by the platform (ADR-0019).
pub const FLAGS_AD_LEN: usize = 3;

/// The maximum length of a legacy BLE advertisement payload (ADR-0019).
pub const ADVERTISEMENT_MAX_LEN: usize = 31;

/// The Tradr BLE service UUID in big-endian order (ADR-0019).
pub const TRADR_SERVICE_UUID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x01, 0x6e, 0xed, 0x40, 0xd6, 0x85, 0xd3, 0x37, 0x94, 0xea, 0xa7, 0xb2, 0x1c,
];

/// The Tradr BLE service UUID in little-endian order as written in an AD structure (ADR-0019).
pub const TRADR_SERVICE_UUID_LE: [u8; 16] = [
    0x1c, 0xb2, 0xa7, 0xea, 0x94, 0x37, 0xd3, 0x85, 0xd6, 0x40, 0xed, 0x6e, 0x01, 0x00, 0x00, 0x00,
];

const _: () =
    assert!(FLAGS_AD_LEN + AD_STRUCTURE_OVERHEAD + SERVICE_DATA_LEN <= ADVERTISEMENT_MAX_LEN);

/// An error constructing or parsing a BLE advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisementError {
    /// The input was not exactly the expected number of bytes.
    WrongLength {
        /// The number of bytes the type requires.
        expected: usize,
        /// The number of bytes actually given.
        actual: usize,
    },
    /// The advertisement version byte was not recognised.
    UnknownVersion(u8),
    /// The platform code exceeds the 4-bit limit.
    InvalidPlatformCode(u8),
}

impl fmt::Display for AdvertisementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::UnknownVersion(version) => {
                write!(f, "unknown advertisement version {version}")
            }
            Self::InvalidPlatformCode(code) => {
                write!(f, "platform code {code} exceeds 4-bit limit")
            }
        }
    }
}

impl std::error::Error for AdvertisementError {}

/// A 4-bit platform identifier carried in the advertisement flags byte (ADR-0019).
///
/// An unassigned code is accepted so future platforms remain visible (Change Drill D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlatformCode(u8);

impl PlatformCode {
    /// Unknown platform.
    pub const UNKNOWN: Self = Self(0);
    /// Linux platform.
    pub const LINUX: Self = Self(1);
    /// Windows platform.
    pub const WINDOWS: Self = Self(2);
    /// macOS platform.
    pub const MAC: Self = Self(3);
    /// Android platform.
    pub const ANDROID: Self = Self(4);

    /// Builds a `PlatformCode` from a 4-bit integer, refusing values above 15.
    pub const fn from_code(code: u8) -> Result<Self, AdvertisementError> {
        if code > 15 {
            return Err(AdvertisementError::InvalidPlatformCode(code));
        }
        Ok(Self(code))
    }

    /// Returns the raw 4-bit platform code.
    pub const fn code(self) -> u8 {
        self.0
    }
}

/// A BLE proximity advertisement payload (ADR-0019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advertisement {
    eid: Eid,
    platform: PlatformCode,
    capabilities: Capabilities,
}

impl Advertisement {
    /// Keeps only `Capabilities` bits 0-3 because those are the transports; the rest arrives in `Hello`.
    pub fn new(eid: Eid, platform: PlatformCode, capabilities: Capabilities) -> Self {
        Self {
            eid,
            platform,
            capabilities: Capabilities::from_bits(capabilities.bits() & 0x000F),
        }
    }

    /// Returns the Ephemeral Identifier (EID).
    pub fn eid(&self) -> Eid {
        self.eid
    }

    /// Returns the platform code.
    pub fn platform(&self) -> PlatformCode {
        self.platform
    }

    /// Returns the transport capability flags that were kept.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Serializes the advertisement into a 10-byte Service Data payload.
    pub fn service_data(&self) -> [u8; SERVICE_DATA_LEN] {
        let mut bytes = [0u8; SERVICE_DATA_LEN];
        bytes[0] = ADVERTISEMENT_VERSION;
        bytes[1..1 + EID_LEN].copy_from_slice(self.eid.as_bytes());
        bytes[1 + EID_LEN] = (self.platform.code() << 4) | (self.capabilities.bits() as u8 & 0x0F);
        bytes
    }

    /// Deserializes an advertisement from a 10-byte Service Data payload.
    pub fn from_service_data(bytes: &[u8]) -> Result<Self, AdvertisementError> {
        if bytes.len() != SERVICE_DATA_LEN {
            return Err(AdvertisementError::WrongLength {
                expected: SERVICE_DATA_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != ADVERTISEMENT_VERSION {
            return Err(AdvertisementError::UnknownVersion(bytes[0]));
        }

        let eid =
            Eid::from_bytes(&bytes[1..1 + EID_LEN]).expect("slice length is checked to be EID_LEN");
        let platform =
            PlatformCode::from_code(bytes[1 + EID_LEN] >> 4).expect("4-bit shift is at most 15");
        let capabilities = Capabilities::from_bits((bytes[1 + EID_LEN] & 0x0F) as u16);

        Ok(Self {
            eid,
            platform,
            capabilities,
        })
    }
}

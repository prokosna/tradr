//! A device's permanent identifier. See `docs/05-security.md`: the value
//! itself is the first 16 bytes of `BLAKE3(identity_pub)`, computed above
//! this layer. This module only validates and displays bytes it is given.

use std::fmt;
use std::str::FromStr;

/// The number of bytes a `DeviceId` occupies.
pub const DEVICE_ID_LEN: usize = 16;

/// A device's permanent identifier: the first 16 bytes of
/// `BLAKE3(identity_pub)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

/// An error constructing a `DeviceId` from bytes or from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIdError {
    /// The input was not exactly `DEVICE_ID_LEN` bytes long.
    WrongLength(usize),
    /// The input string was not valid hex of the expected length.
    InvalidHex,
}

impl fmt::Display for DeviceIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "device id must be {DEVICE_ID_LEN} bytes, got {len}")
            }
            Self::InvalidHex => write!(f, "device id string is not valid hex"),
        }
    }
}

impl std::error::Error for DeviceIdError {}

impl DeviceId {
    /// Builds a `DeviceId` from exactly `DEVICE_ID_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceIdError> {
        let array: [u8; DEVICE_ID_LEN] = bytes
            .try_into()
            .map_err(|_| DeviceIdError::WrongLength(bytes.len()))?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for DeviceId {
    type Err = DeviceIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != DEVICE_ID_LEN * 2 {
            return Err(DeviceIdError::InvalidHex);
        }
        let mut array = [0u8; DEVICE_ID_LEN];
        for (i, out) in array.iter_mut().enumerate() {
            let hex_pair = s.get(i * 2..i * 2 + 2).ok_or(DeviceIdError::InvalidHex)?;
            *out = hex_byte(hex_pair).ok_or(DeviceIdError::InvalidHex)?;
        }
        Ok(Self(array))
    }
}

// `from_str_radix` accepts a leading sign, so "+f" parses as 15 under a
// naive call. Requiring both characters to be ASCII hex digits first closes
// that, keeping FromStr injective over its accepted strings.
fn hex_byte(pair: &str) -> Option<u8> {
    let bytes = pair.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_hexdigit() || !bytes[1].is_ascii_hexdigit() {
        return None;
    }
    u8::from_str_radix(pair, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_display_and_from_str() {
        let original = DeviceId::from_bytes(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
        .expect("16 bytes must construct");

        let rendered = original.to_string();
        let parsed: DeviceId = rendered.parse().expect("its own rendering must parse");

        assert_eq!(original, parsed);
        assert_eq!(rendered, "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn from_str_accepts_uppercase_hex() {
        let lower: DeviceId = "00112233445566778899aabbccddeeff".parse().unwrap();
        let upper: DeviceId = "00112233445566778899AABBCCDDEEFF".parse().unwrap();

        assert_eq!(lower, upper);
    }

    #[test]
    fn from_bytes_rejects_a_fifteen_byte_slice() {
        let bytes = [0u8; 15];
        let result = DeviceId::from_bytes(&bytes);

        assert_eq!(result, Err(DeviceIdError::WrongLength(15)));
    }

    #[test]
    fn from_bytes_rejects_a_seventeen_byte_slice() {
        let bytes = [0u8; 17];
        let result = DeviceId::from_bytes(&bytes);

        assert_eq!(result, Err(DeviceIdError::WrongLength(17)));
    }

    #[test]
    fn from_str_rejects_a_non_hex_character() {
        let result: Result<DeviceId, _> = "00112233445566778899aabbccddeegf".parse();

        assert_eq!(result, Err(DeviceIdError::InvalidHex));
    }

    #[test]
    fn from_str_rejects_a_leading_plus_sign() {
        let result: Result<DeviceId, _> = "+f0102030405060708090a0b0c0d0e0f".parse();

        assert_eq!(result, Err(DeviceIdError::InvalidHex));
    }

    #[test]
    fn any_accepted_string_displays_as_its_own_lowercase_form() {
        let candidates = [
            "00112233445566778899aabbccddeeff",
            "00112233445566778899AABBCCDDEEFF",
            "AaBb223344556677889900ccDdEeFf11",
        ];

        for input in candidates {
            let parsed: DeviceId = input.parse().expect("candidate must be accepted");
            assert_eq!(parsed.to_string(), input.to_ascii_lowercase());
        }
    }
}

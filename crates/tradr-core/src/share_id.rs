//! A Share's identifier. See `docs/04-protocol.md`: it is a UUIDv7 the
//! sender assigns, which needs randomness and a clock to generate, both
//! supplied by Layer 1. This module only validates a value produced there.

use std::fmt;
use std::str::FromStr;

const CANONICAL_LEN: usize = 36;
const HYPHEN_POSITIONS: [usize; 4] = [8, 13, 18, 23];

/// A Share's identifier: a UUIDv7, canonically rendered as hyphenated hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShareId([u8; 16]);

/// An error parsing a `ShareId` from its canonical string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareIdError {
    /// The string was not 36 characters of hyphenated hex in the UUID shape.
    InvalidFormat,
    /// The version nibble was not 7.
    WrongVersion(u8),
    /// The variant bits were not the RFC 4122 pattern `10`.
    WrongVariant,
}

impl fmt::Display for ShareIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "share id is not a canonical hyphenated uuid"),
            Self::WrongVersion(version) => {
                write!(f, "share id version nibble is {version}, expected 7")
            }
            Self::WrongVariant => write!(f, "share id variant bits are not RFC 4122"),
        }
    }
}

impl std::error::Error for ShareIdError {}

fn parse_canonical(s: &str) -> Result<[u8; 16], ShareIdError> {
    if s.len() != CANONICAL_LEN {
        return Err(ShareIdError::InvalidFormat);
    }
    for position in HYPHEN_POSITIONS {
        if s.as_bytes()[position] != b'-' {
            return Err(ShareIdError::InvalidFormat);
        }
    }

    let mut bytes = [0u8; 16];
    let mut out = 0;
    let mut cursor = 0;
    while out < bytes.len() {
        if HYPHEN_POSITIONS.contains(&cursor) {
            cursor += 1;
            continue;
        }
        let hex_pair = s
            .get(cursor..cursor + 2)
            .ok_or(ShareIdError::InvalidFormat)?;
        bytes[out] = hex_byte(hex_pair).ok_or(ShareIdError::InvalidFormat)?;
        out += 1;
        cursor += 2;
    }
    Ok(bytes)
}

// `from_str_radix` accepts a leading sign, so "+1" parses as 1 under a naive
// call. Requiring both characters to be ASCII hex digits first closes that,
// keeping FromStr injective over its accepted strings.
fn hex_byte(pair: &str) -> Option<u8> {
    let bytes = pair.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_hexdigit() || !bytes[1].is_ascii_hexdigit() {
        return None;
    }
    u8::from_str_radix(pair, 16).ok()
}

impl FromStr for ShareId {
    type Err = ShareIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = parse_canonical(s)?;

        let version = bytes[6] >> 4;
        if version != 7 {
            return Err(ShareIdError::WrongVersion(version));
        }
        if bytes[8] & 0xC0 != 0x80 {
            return Err(ShareIdError::WrongVariant);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The RFC 9562 worked example for UUIDv7, lowercased.
    const A_VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

    #[test]
    fn round_trips_through_display_and_from_str() {
        let original: ShareId = A_VALID_V7.parse().expect("a valid v7 string must parse");
        let rendered = original.to_string();
        let parsed: ShareId = rendered.parse().expect("its own rendering must parse");

        assert_eq!(original, parsed);
        assert_eq!(rendered, A_VALID_V7);
    }

    #[test]
    fn rejects_a_real_uuidv4() {
        // A well-known example UUIDv4: version nibble '4', variant nibble 'a'.
        let result: Result<ShareId, _> = "550e8400-e29b-41d4-a716-446655440000".parse();

        assert_eq!(result, Err(ShareIdError::WrongVersion(4)));
    }

    #[test]
    fn rejects_correct_version_with_wrong_variant_bits() {
        // Same as A_VALID_V7 but with the variant nibble changed from '9' to
        // '0', which no longer carries the RFC 4122 top bits '10'.
        let result: Result<ShareId, _> = "017f22e2-79b0-7cc3-08c4-dc0c0c07398f".parse();

        assert_eq!(result, Err(ShareIdError::WrongVariant));
    }

    #[test]
    fn rejects_a_leading_plus_sign() {
        let result: Result<ShareId, _> = "+1930b2f-6a1e-7c3d-8f4a-1b2c3d4e5f60".parse();

        assert_eq!(result, Err(ShareIdError::InvalidFormat));
    }

    #[test]
    fn any_accepted_string_displays_as_its_own_lowercase_form() {
        let candidates = [
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            "017F22E2-79B0-7CC3-98C4-DC0C0C07398F",
            "017f22E2-79B0-7cc3-98C4-Dc0c0C07398F",
        ];

        for input in candidates {
            let parsed: ShareId = input.parse().expect("candidate must be accepted");
            assert_eq!(parsed.to_string(), input.to_ascii_lowercase());
        }
    }
}

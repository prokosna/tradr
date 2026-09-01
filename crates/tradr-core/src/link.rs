//! Layer 0 value types for account linking (docs/11-account-linking.md,
//! CONTEXT.md's Trust table). This module holds and validates bytes; the
//! derivations that produce them -- `BLAKE3::derive_key` and `BLAKE3` over
//! a Link Secret -- belong to Layer 1, where a hash function is allowed.

use std::fmt;
use std::str::FromStr;

/// The number of bytes a `HalfSecret` occupies.
pub const HALF_SECRET_LEN: usize = 16;

/// The number of bytes a `LinkSecret` occupies.
pub const LINK_SECRET_LEN: usize = 32;

/// The number of bytes a `LinkId` occupies.
pub const LINK_ID_LEN: usize = 16;

/// The number of bytes an `InviteId` occupies.
pub const INVITE_ID_LEN: usize = 16;

/// An error constructing a link domain value from bytes or from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// The input was not exactly the expected number of bytes.
    WrongLength {
        /// The number of bytes the type requires.
        expected: usize,
        /// The number of bytes actually given.
        actual: usize,
    },
    /// The input string was not valid hex of the expected length.
    InvalidHex,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::InvalidHex => write!(f, "string is not valid hex of the expected length"),
        }
    }
}

impl std::error::Error for LinkError {}

/// 16 random bytes one side of a prospective Link contributes, so that
/// neither side decides the Link Secret alone (CONTEXT.md, "Half Secret").
/// Generated through `Rng` by Layer 1; this type only holds and validates.
#[derive(Clone, Copy)]
pub struct HalfSecret([u8; HALF_SECRET_LEN]);

impl HalfSecret {
    /// Builds a `HalfSecret` from exactly `HALF_SECRET_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkError> {
        let array: [u8; HALF_SECRET_LEN] =
            bytes.try_into().map_err(|_| LinkError::WrongLength {
                expected: HALF_SECRET_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; HALF_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for HalfSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HalfSecret(<redacted>)")
    }
}

/// The 32 bytes both sides of a Link derive: `BLAKE3::derive_key
/// ("tradr-link-v1", half_A || half_B)` (CONTEXT.md, "Link Secret"). No
/// `PartialEq`: comparing secret material byte-wise is what a
/// constant-time comparison exists to avoid, and nothing in this design
/// compares two Link Secrets -- `LinkId` is what gets compared.
#[derive(Clone, Copy)]
pub struct LinkSecret([u8; LINK_SECRET_LEN]);

impl LinkSecret {
    /// Builds a `LinkSecret` from exactly `LINK_SECRET_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkError> {
        let array: [u8; LINK_SECRET_LEN] =
            bytes.try_into().map_err(|_| LinkError::WrongLength {
                expected: LINK_SECRET_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; LINK_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkSecret(<redacted>)")
    }
}

/// A Link's identifier: the first `LINK_ID_LEN` bytes of `BLAKE3(Link
/// Secret)`, rendered as lowercase hex (CONTEXT.md, "Link ID"). What a
/// Share's Audience names, and what gets compared instead of a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId([u8; LINK_ID_LEN]);

impl LinkId {
    /// Builds a `LinkId` from exactly `LINK_ID_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkError> {
        let array: [u8; LINK_ID_LEN] = bytes.try_into().map_err(|_| LinkError::WrongLength {
            expected: LINK_ID_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; LINK_ID_LEN] {
        &self.0
    }

    /// Derives a `LinkId` from `digest`'s leading `LINK_ID_LEN` bytes.
    /// `digest` must be `BLAKE3(Link Secret)`. Hashing is the caller's
    /// job because Layer 0 has no hash function and may not acquire one.
    /// Infallible: a fixed-size digest carries no length to get wrong.
    pub fn from_link_secret_digest(digest: &[u8; 32]) -> Self {
        let mut array = [0u8; LINK_ID_LEN];
        array.copy_from_slice(&digest[..LINK_ID_LEN]);
        Self(array)
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for LinkId {
    type Err = LinkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let array = parse_hex::<LINK_ID_LEN>(s)?;
        Ok(Self(array))
    }
}

/// The identifier of one Invite, so a reply names the invite it answers
/// (CONTEXT.md, "Invite"). Generated by Layer 1 through `Rng`; unlike a
/// `LinkId`, it is derived from nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InviteId([u8; INVITE_ID_LEN]);

impl InviteId {
    /// Builds an `InviteId` from exactly `INVITE_ID_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkError> {
        let array: [u8; INVITE_ID_LEN] = bytes.try_into().map_err(|_| LinkError::WrongLength {
            expected: INVITE_ID_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; INVITE_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for InviteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for InviteId {
    type Err = LinkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let array = parse_hex::<INVITE_ID_LEN>(s)?;
        Ok(Self(array))
    }
}

// `from_str_radix` accepts a leading sign, so "+f" parses as 15 under a
// naive call. Requiring both characters to be ASCII hex digits first
// closes that, keeping FromStr injective over its accepted strings.
fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N], LinkError> {
    if s.len() != N * 2 {
        return Err(LinkError::InvalidHex);
    }
    let mut array = [0u8; N];
    for (i, out) in array.iter_mut().enumerate() {
        let hex_pair = s.get(i * 2..i * 2 + 2).ok_or(LinkError::InvalidHex)?;
        *out = hex_byte(hex_pair).ok_or(LinkError::InvalidHex)?;
    }
    Ok(array)
}

fn hex_byte(pair: &str) -> Option<u8> {
    let bytes = pair.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_hexdigit() || !bytes[1].is_ascii_hexdigit() {
        return None;
    }
    u8::from_str_radix(pair, 16).ok()
}

//! A sender-chosen identifier for one Item inside a Transfer. See
//! `docs/04-protocol.md`, "Partial files": `item_id` is attacker-controlled
//! from the receiver's side, is never used as a path component, and is
//! constrained to an opaque token rather than to a legal filename.

use std::fmt;

/// The most bytes an `ItemId` may occupy.
pub const ITEM_ID_MAX_LEN: usize = 64;

/// A sender-chosen identifier, unique within a Transfer. Deliberately never
/// a path component: see `docs/04-protocol.md`, "Partial files".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId {
    bytes: [u8; ITEM_ID_MAX_LEN],
    len: u8,
}

/// An error constructing an `ItemId` from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemIdError {
    /// The input was empty or longer than `ITEM_ID_MAX_LEN` bytes.
    WrongLength(usize),
    /// The input contained a character outside lowercase ASCII letters,
    /// digits, `-` and `_`.
    InvalidCharacter(char),
    /// The input is a Windows reserved device name.
    ReservedName(String),
}

impl fmt::Display for ItemIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "item id must be 1 to {ITEM_ID_MAX_LEN} bytes, got {len}")
            }
            Self::InvalidCharacter(c) => write!(
                f,
                "item id contains {c:?}, which is outside a-z, 0-9, '-' and '_'"
            ),
            Self::ReservedName(name) => {
                write!(f, "item id {name:?} is a Windows reserved device name")
            }
        }
    }
}

impl std::error::Error for ItemIdError {}

// Reserved regardless of case, but the alphabet check above already forces
// lowercase, so an exact lowercase match is enough.
const RESERVED_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

fn is_permitted_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
}

impl ItemId {
    /// Validates `s` against the alphabet and length rule in
    /// `docs/04-protocol.md`, "Partial files", and builds an `ItemId` from it.
    pub fn new(s: &str) -> Result<Self, ItemIdError> {
        if s.is_empty() || s.len() > ITEM_ID_MAX_LEN {
            return Err(ItemIdError::WrongLength(s.len()));
        }
        if let Some(c) = s.chars().find(|&c| !is_permitted_char(c)) {
            return Err(ItemIdError::InvalidCharacter(c));
        }
        if RESERVED_NAMES.contains(&s) {
            return Err(ItemIdError::ReservedName(s.to_string()));
        }

        // `s` is ASCII-only past the alphabet check, so byte length and
        // char count agree and the copy below is exact.
        let mut bytes = [0u8; ITEM_ID_MAX_LEN];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        Ok(Self {
            bytes,
            len: s.len() as u8,
        })
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every stored byte passed `is_permitted_char`, so it is ASCII and
        // `char::from(byte)` can never produce anything but that character.
        for &byte in &self.bytes[..self.len as usize] {
            write!(f, "{}", char::from(byte))?;
        }
        Ok(())
    }
}

//! A Device Key rendered as twelve BIP-39 words, the option not to trust
//! Google (docs/05: "Fingerprint -- the option not to trust Google"). This
//! module encodes a digest the caller computed; it never hashes.

use std::fmt;
use std::sync::LazyLock;

/// The number of words a `Fingerprint` renders as.
pub const FINGERPRINT_WORD_COUNT: usize = 12;

/// The number of rows `Fingerprint::rows` groups its words into.
pub const FINGERPRINT_ROW_COUNT: usize = 3;

/// The number of words in each row `Fingerprint::rows` returns.
pub const FINGERPRINT_WORDS_PER_ROW: usize = 4;

// The vendored BIP-39 English word list (crates/tradr-core/vendor,
// docs/05 "Where the word list comes from"): 2048 lowercase ASCII words,
// sorted ascending, one per line, one trailing newline.
const WORD_LIST_TEXT: &str = include_str!("../vendor/bip39-english/english.txt");

static WORD_LIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| WORD_LIST_TEXT.lines().collect());

/// A Device Key rendered as twelve words from the BIP-39 English list, so
/// two people can compare it aloud instead of comparing hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    indices: [u16; FINGERPRINT_WORD_COUNT],
}

impl Fingerprint {
    /// Encodes `digest`'s leading 132 bits as twelve 11-bit word indices.
    /// `digest` must be `BLAKE3("tradr-fp-v1" || identity_pub ||
    /// agreement_pub)` (docs/05 "Why 132 bits, when the words were always
    /// twelve"); hashing is the caller's job. Byte 16 contributes only its
    /// top 4 bits; the rest of the digest is not read.
    pub fn from_key_digest(digest: &[u8; 32]) -> Self {
        let mut indices = [0u16; FINGERPRINT_WORD_COUNT];
        for (i, index) in indices.iter_mut().enumerate() {
            *index = read_bits(digest, i * 11);
        }
        Self { indices }
    }

    /// Returns the twelve words in order, most significant first.
    pub fn words(&self) -> [&'static str; FINGERPRINT_WORD_COUNT] {
        std::array::from_fn(|i| WORD_LIST[self.indices[i] as usize])
    }

    /// Groups `words()` into three rows of four, without reordering them.
    pub fn rows(&self) -> [[&'static str; FINGERPRINT_WORDS_PER_ROW]; FINGERPRINT_ROW_COUNT] {
        let words = self.words();
        std::array::from_fn(|row| {
            std::array::from_fn(|col| words[row * FINGERPRINT_WORDS_PER_ROW + col])
        })
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words = self.words();
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{word}")?;
        }
        Ok(())
    }
}

// Reads the 11-bit big-endian value starting at bit offset `start` of
// `digest`, treating the bytes as one big-endian bit string.
fn read_bits(digest: &[u8; 32], start: usize) -> u16 {
    let mut value: u16 = 0;
    for offset in 0..11 {
        let bit = start + offset;
        let byte = digest[bit / 8];
        let set = (byte >> (7 - bit % 8)) & 1;
        value = (value << 1) | u16::from(set);
    }
    value
}

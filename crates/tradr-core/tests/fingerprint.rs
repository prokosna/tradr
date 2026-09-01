//! Supervisor-authored tests for the Fingerprint encoding, written first.
//! docs/05 calls it the option not to trust Google, and it works only if
//! two devices holding different keys always show different words. An
//! encoder that loses bits fails no build and no handshake, and the words
//! it prints look exactly as convincing as the right ones.

use tradr_core::{
    FINGERPRINT_ROW_COUNT, FINGERPRINT_WORD_COUNT, FINGERPRINT_WORDS_PER_ROW, Fingerprint,
};

// Packs twelve 11-bit indices the way docs/05 specifies, most significant
// bit first, so a test can name the words it expects instead of the bytes.
// Independent of the implementation: it is the specification written twice.
fn digest_from_indices(indices: [u16; FINGERPRINT_WORD_COUNT]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut bit = 0usize;
    for index in indices {
        for offset in 0..11u16 {
            if (index >> (10 - offset)) & 1 == 1 {
                digest[bit / 8] |= 0x80u8 >> (bit % 8);
            }
            bit += 1;
        }
    }
    digest
}

fn words_of(digest: &[u8; 32]) -> Vec<String> {
    Fingerprint::from_key_digest(digest)
        .words()
        .iter()
        .map(|w| (*w).to_string())
        .collect()
}

#[test]
fn an_all_zero_digest_is_twelve_copies_of_the_first_word() {
    let words = words_of(&[0u8; 32]);

    assert_eq!(words, vec!["abandon".to_string(); FINGERPRINT_WORD_COUNT]);
}

#[test]
fn a_digest_of_all_ones_is_twelve_copies_of_the_last_word() {
    // 132 bits set: sixteen full bytes and the top nibble of the next.
    let mut digest = [0u8; 32];
    digest[..16].fill(0xff);
    digest[16] = 0xf0;

    let words = words_of(&digest);

    assert_eq!(words, vec!["zoo".to_string(); FINGERPRINT_WORD_COUNT]);
}

#[test]
fn twelve_ascending_indices_read_the_list_in_order() {
    // The bytes are written out rather than packed here, so an encoder
    // that reads the indices least significant bit first fails.
    let mut digest = [0u8; 32];
    digest[..17].copy_from_slice(&[
        0x00, 0x00, 0x04, 0x01, 0x00, 0x30, 0x08, 0x01, 0x40, 0x30, 0x07, 0x01, 0x00, 0x24, 0x05,
        0x00, 0xb0,
    ]);

    let words = words_of(&digest);

    assert_eq!(
        words,
        vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident"
        ]
    );
}

#[test]
fn a_known_digest_encodes_to_a_fixed_twelve_words() {
    let digest: [u8; 32] = core::array::from_fn(|i| i as u8);

    let words = words_of(&digest);

    assert_eq!(
        words,
        vec![
            "abandon", "amount", "liar", "amount", "expire", "adjust", "cage", "candy", "arch",
            "gather", "drum", "bullet"
        ]
    );
}

#[test]
fn every_one_of_the_first_132_bits_changes_the_fingerprint() {
    // The test the whole module exists for: a dropped bit is a pair of
    // distinct keys that show one person the same twelve words.
    let base: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
    let baseline = Fingerprint::from_key_digest(&base);

    for bit in 0..132usize {
        let mut flipped = base;
        flipped[bit / 8] ^= 0x80u8 >> (bit % 8);

        assert_ne!(
            Fingerprint::from_key_digest(&flipped),
            baseline,
            "flipping bit {bit} left the fingerprint unchanged"
        );
    }
}

#[test]
fn the_last_four_bits_of_the_seventeenth_byte_are_not_read() {
    let base: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut altered = base;
    altered[16] ^= 0x0f;

    assert_eq!(
        Fingerprint::from_key_digest(&altered),
        Fingerprint::from_key_digest(&base)
    );
}

#[test]
fn nothing_past_the_seventeenth_byte_is_read() {
    let base: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut altered = base;
    for byte in altered[17..].iter_mut() {
        *byte ^= 0xff;
    }

    assert_eq!(
        Fingerprint::from_key_digest(&altered),
        Fingerprint::from_key_digest(&base)
    );
}

#[test]
fn each_of_the_2048_indices_yields_a_word_of_its_own() {
    // Reached through the encoder rather than through a list accessor, so
    // this asserts the property that matters: no two indices collide.
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..2048u16 {
        let words = words_of(&digest_from_indices([index; FINGERPRINT_WORD_COUNT]));
        let distinct: std::collections::BTreeSet<_> = words.iter().collect();

        assert_eq!(distinct.len(), 1);
        seen.insert(words[0].clone());
    }

    assert_eq!(seen.len(), 2048);
}

#[test]
fn every_word_is_three_to_eight_lowercase_ascii_letters() {
    for index in 0..2048u16 {
        let words = words_of(&digest_from_indices([index; FINGERPRINT_WORD_COUNT]));
        let word = &words[0];

        assert!(
            (3..=8).contains(&word.len()),
            "word {index} is {} letters: {word}",
            word.len()
        );
        assert!(
            word.chars().all(|c| c.is_ascii_lowercase()),
            "word {index} is not lowercase ascii: {word}"
        );
    }
}

#[test]
fn the_word_list_is_sorted_ascending() {
    let mut previous: Option<String> = None;
    for index in 0..2048u16 {
        let words = words_of(&digest_from_indices([index; FINGERPRINT_WORD_COUNT]));
        let word = words[0].clone();
        if let Some(previous) = previous {
            assert!(previous < word, "{previous} precedes {word} out of order");
        }
        previous = Some(word);
    }
}

#[test]
fn no_two_words_share_their_first_four_letters() {
    // BIP-39's own rule, and what lets a listener who catches only the
    // start of a word still have caught the word.
    let mut prefixes = std::collections::BTreeSet::new();
    for index in 0..2048u16 {
        let words = words_of(&digest_from_indices([index; FINGERPRINT_WORD_COUNT]));
        let prefix: String = words[0].chars().take(4).collect();

        assert!(prefixes.insert(prefix.clone()), "prefix {prefix} repeats");
    }
}

#[test]
fn display_is_the_twelve_words_separated_by_single_spaces() {
    let digest: [u8; 32] = core::array::from_fn(|i| i as u8);
    let fingerprint = Fingerprint::from_key_digest(&digest);

    assert_eq!(
        fingerprint.to_string(),
        "abandon amount liar amount expire adjust cage candy arch gather drum bullet"
    );
}

#[test]
fn rows_are_three_of_four_in_the_order_words_gives() {
    let digest: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));
    let fingerprint = Fingerprint::from_key_digest(&digest);

    let flattened: Vec<&str> = fingerprint
        .rows()
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect();

    assert_eq!(fingerprint.rows().len(), FINGERPRINT_ROW_COUNT);
    assert_eq!(fingerprint.rows()[0].len(), FINGERPRINT_WORDS_PER_ROW);
    assert_eq!(flattened, fingerprint.words().to_vec());
}

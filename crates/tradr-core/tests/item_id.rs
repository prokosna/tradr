//! Supervisor-authored tests for `ItemId`, written before the implementation.
//! `item_id` is chosen by the sender, so it is attacker-controlled from the
//! receiver's point of view. See CLAUDE.md section 6 and docs/04.

use tradr_core::ItemId;

/// The alphabet docs/04 permits: lowercase ASCII letters, digits, `-` and `_`.
fn valid_chars() -> Vec<char> {
    let mut chars: Vec<char> = ('a'..='z').collect();
    chars.extend('0'..='9');
    chars.push('-');
    chars.push('_');
    chars
}

#[test]
fn accepts_every_permitted_character() {
    for c in valid_chars() {
        let candidate = c.to_string();
        assert!(
            ItemId::new(&candidate).is_ok(),
            "{candidate:?} uses a permitted character and must be accepted"
        );
    }
}

#[test]
fn accepts_a_representative_identifier() {
    assert!(ItemId::new("item_7-a3f0").is_ok());
}

#[test]
fn accepts_the_length_bounds() {
    assert!(ItemId::new("a").is_ok(), "one character is the lower bound");
    assert!(
        ItemId::new(&"a".repeat(64)).is_ok(),
        "64 characters is the upper bound"
    );
}

#[test]
fn rejects_the_empty_string() {
    assert!(ItemId::new("").is_err());
}

#[test]
fn rejects_anything_longer_than_the_upper_bound() {
    assert!(ItemId::new(&"a".repeat(65)).is_err());
}

#[test]
fn rejects_uppercase() {
    // Two ids differing only in case would collide on a case-insensitive
    // filesystem, so only one spelling of an identifier is accepted at all.
    assert!(ItemId::new("A").is_err());
    assert!(ItemId::new("Item7").is_err());
}

#[test]
fn rejects_every_character_outside_the_alphabet() {
    let permitted = valid_chars();
    for byte in 0u8..=127 {
        let c = byte as char;
        if permitted.contains(&c) {
            continue;
        }
        let candidate = format!("a{c}b");
        assert!(
            ItemId::new(&candidate).is_err(),
            "{candidate:?} contains {c:?}, which is outside the alphabet"
        );
    }
}

#[test]
fn rejects_path_traversal_shapes() {
    for candidate in [
        ".",
        "..",
        "../etc/passwd",
        "..\\windows\\system32",
        "/etc/passwd",
        "a/b",
        "a\\b",
        "./a",
    ] {
        assert!(
            ItemId::new(candidate).is_err(),
            "{candidate:?} must never be accepted"
        );
    }
}

#[test]
fn rejects_control_characters_and_nul() {
    for candidate in ["a\0b", "a\nb", "a\rb", "a\tb", "\u{7f}"] {
        assert!(
            ItemId::new(candidate).is_err(),
            "{candidate:?} contains a control character"
        );
    }
}

#[test]
fn rejects_whitespace() {
    for candidate in ["a b", " a", "a ", "a\u{a0}b"] {
        assert!(ItemId::new(candidate).is_err(), "{candidate:?} has a space");
    }
}

#[test]
fn rejects_non_ascii() {
    // A full-width digit and a Cyrillic 'a' both look like permitted
    // characters and are not, which is the point of an explicit alphabet.
    for candidate in ["\u{ff10}", "\u{430}", "caf\u{e9}", "\u{1f600}"] {
        assert!(
            ItemId::new(candidate).is_err(),
            "{candidate:?} is not ASCII"
        );
    }
}

#[test]
fn rejects_windows_reserved_names() {
    // Reserved on Windows regardless of case, and dangerous even though the
    // receiver no longer names partial files after an item_id.
    for candidate in ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"] {
        assert!(
            ItemId::new(candidate).is_err(),
            "{candidate:?} is a Windows reserved name"
        );
    }
}

#[test]
fn accepts_names_that_only_resemble_reserved_ones() {
    for candidate in ["console", "com0", "com10", "lpt0", "nula", "acon"] {
        assert!(
            ItemId::new(candidate).is_ok(),
            "{candidate:?} is not reserved and must not be rejected"
        );
    }
}

#[test]
fn every_accepted_identifier_displays_as_itself() {
    // The string form is a map key and reaches logs, so two spellings must
    // never denote one identifier.
    for candidate in ["a", "item_7-a3f0", "0", "-", "_", &"z".repeat(64)] {
        let Ok(id) = ItemId::new(candidate) else {
            panic!("{candidate:?} should have been accepted");
        };
        assert_eq!(id.to_string(), candidate);
    }
}

#[test]
fn equal_identifiers_compare_equal() {
    let Ok(left) = ItemId::new("item_7") else {
        panic!("valid identifier rejected");
    };
    let Ok(right) = ItemId::new("item_7") else {
        panic!("valid identifier rejected");
    };
    assert_eq!(left, right);
}

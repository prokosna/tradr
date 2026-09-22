//! DCR-146: a peer's address, published name and observation key refuse
//! the characters a filename refuses (docs/03, "A name a person reads may
//! not reorder itself"). Written by the Supervisor before the change.

use tradr_core::{
    Candidate, CandidateError, DisplayName, DisplayNameError, ObservationKey, ObservationKeyError,
    RelPath, RelPathError, TransportId,
};

// docs/04's set, spelled out rather than imported, so a narrowed predicate
// fails here instead of agreeing with itself.
const REFUSED: [char; 11] = [
    '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}', '\u{2028}', '\u{2029}',
];

// Neighbours of the refused ranges, plus the marks docs/04 keeps and the
// zero-width space DCR-146 deliberately does not refuse.
const PERMITTED: [char; 8] = [
    '\u{200b}', '\u{200e}', '\u{200f}', '\u{2027}', '\u{202f}', '\u{2065}', '\u{206a}', '\u{05d0}',
];

fn transport() -> TransportId {
    TransportId::new("direct-quic")
}

#[test]
fn candidate_refuses_every_reordering_character() {
    for c in REFUSED {
        let address = format!("host{c}.example:21820");
        assert_eq!(
            Candidate::new(transport(), &address),
            Err(CandidateError::MisleadingDisplay(c)),
            "{c:?} should have been refused"
        );
    }
}

#[test]
fn display_name_refuses_every_reordering_character() {
    for c in REFUSED {
        let name = format!("desk{c}top");
        assert_eq!(
            DisplayName::new(&name),
            Err(DisplayNameError::MisleadingDisplay(c)),
            "{c:?} should have been refused"
        );
    }
}

#[test]
fn observation_key_refuses_every_reordering_character() {
    for c in REFUSED {
        let key = format!("tradr{c}._tradr._udp.local.");
        assert_eq!(
            ObservationKey::new(&key),
            Err(ObservationKeyError::MisleadingDisplay(c)),
            "{c:?} should have been refused"
        );
    }
}

#[test]
fn the_three_constructors_accept_what_they_do_not_refuse() {
    for c in PERMITTED {
        let s = format!("desk{c}top");
        assert!(Candidate::new(transport(), &s).is_ok(), "{c:?} candidate");
        assert!(DisplayName::new(&s).is_ok(), "{c:?} display name");
        assert!(ObservationKey::new(&s).is_ok(), "{c:?} observation key");
    }
}

#[test]
fn a_reordering_character_first_or_last_is_still_refused() {
    let first = "\u{202e}desk";
    let last = "desk\u{2069}";
    assert_eq!(
        DisplayName::new(first),
        Err(DisplayNameError::MisleadingDisplay('\u{202e}'))
    );
    assert_eq!(
        DisplayName::new(last),
        Err(DisplayNameError::MisleadingDisplay('\u{2069}'))
    );
}

#[test]
fn a_control_character_is_still_reported_as_one() {
    assert_eq!(
        DisplayName::new("desk\u{0007}\u{202e}"),
        Err(DisplayNameError::ControlCharacter('\u{0007}'))
    );
    assert_eq!(
        Candidate::new(transport(), "host\u{0007}\u{202e}"),
        Err(CandidateError::ControlCharacter('\u{0007}'))
    );
}

#[test]
fn a_name_and_a_filename_refuse_exactly_the_same_characters() {
    for code in 0x2000u32..=0x206f {
        let Some(c) = char::from_u32(code) else {
            continue;
        };
        if c.is_control() {
            continue;
        }
        let as_path = RelPath::new(&format!("a{c}b"));
        let as_name = DisplayName::new(&format!("a{c}b"));
        assert_eq!(
            matches!(as_path, Err(RelPathError::MisleadingDisplay(_))),
            matches!(as_name, Err(DisplayNameError::MisleadingDisplay(_))),
            "{c:?}: a filename and a name disagree"
        );
    }
}

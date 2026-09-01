//! Tests for the link domain's fixed-width value types (docs/11, CONTEXT.md
//! Trust table). Each negative case here was checked to genuinely fail
//! against a broken implementation before being restored (rule E1).

use tradr_core::{
    HALF_SECRET_LEN, HalfSecret, INVITE_ID_LEN, InviteId, LINK_ID_LEN, LINK_SECRET_LEN, LinkError,
    LinkId, LinkSecret,
};

#[test]
fn half_secret_from_bytes_rejects_wrong_lengths() {
    // `HalfSecret` has no `PartialEq` by design, so the `Result` itself
    // cannot be compared; only the extracted `LinkError` can.
    assert_eq!(
        HalfSecret::from_bytes(&[0u8; HALF_SECRET_LEN - 1]).unwrap_err(),
        LinkError::WrongLength {
            expected: HALF_SECRET_LEN,
            actual: HALF_SECRET_LEN - 1,
        }
    );
    assert_eq!(
        HalfSecret::from_bytes(&[0u8; HALF_SECRET_LEN + 1]).unwrap_err(),
        LinkError::WrongLength {
            expected: HALF_SECRET_LEN,
            actual: HALF_SECRET_LEN + 1,
        }
    );
}

#[test]
fn half_secret_from_bytes_accepts_exact_length() {
    let bytes = [0x42u8; HALF_SECRET_LEN];
    let secret = HalfSecret::from_bytes(&bytes).expect("exact length must construct");

    assert_eq!(secret.as_bytes(), &bytes);
}

#[test]
fn half_secret_debug_carries_none_of_its_bytes() {
    // A byte value chosen to be visible in decimal, hex or as an ASCII
    // character, so a leak through any common Debug shape is caught.
    let secret = HalfSecret::from_bytes(&[0xABu8; HALF_SECRET_LEN]).expect("must construct");

    let rendered = format!("{secret:?}");

    assert!(!rendered.contains("ab"));
    assert!(!rendered.contains("171"));
    assert_eq!(rendered, "HalfSecret(<redacted>)");
}

#[test]
fn link_secret_from_bytes_rejects_wrong_lengths() {
    assert_eq!(
        LinkSecret::from_bytes(&[0u8; LINK_SECRET_LEN - 1]).unwrap_err(),
        LinkError::WrongLength {
            expected: LINK_SECRET_LEN,
            actual: LINK_SECRET_LEN - 1,
        }
    );
    assert_eq!(
        LinkSecret::from_bytes(&[0u8; LINK_SECRET_LEN + 1]).unwrap_err(),
        LinkError::WrongLength {
            expected: LINK_SECRET_LEN,
            actual: LINK_SECRET_LEN + 1,
        }
    );
}

#[test]
fn link_secret_from_bytes_accepts_exact_length() {
    let bytes = [0x7du8; LINK_SECRET_LEN];
    let secret = LinkSecret::from_bytes(&bytes).expect("exact length must construct");

    assert_eq!(secret.as_bytes(), &bytes);
}

#[test]
fn link_secret_debug_carries_none_of_its_bytes() {
    let secret = LinkSecret::from_bytes(&[0xCDu8; LINK_SECRET_LEN]).expect("must construct");

    let rendered = format!("{secret:?}");

    assert!(!rendered.contains("cd"));
    assert!(!rendered.contains("205"));
    assert_eq!(rendered, "LinkSecret(<redacted>)");
}

#[test]
fn link_id_from_bytes_rejects_wrong_lengths() {
    assert_eq!(
        LinkId::from_bytes(&[0u8; LINK_ID_LEN - 1]),
        Err(LinkError::WrongLength {
            expected: LINK_ID_LEN,
            actual: LINK_ID_LEN - 1,
        })
    );
    assert_eq!(
        LinkId::from_bytes(&[0u8; LINK_ID_LEN + 1]),
        Err(LinkError::WrongLength {
            expected: LINK_ID_LEN,
            actual: LINK_ID_LEN + 1,
        })
    );
}

#[test]
fn invite_id_from_bytes_rejects_wrong_lengths() {
    assert_eq!(
        InviteId::from_bytes(&[0u8; INVITE_ID_LEN - 1]),
        Err(LinkError::WrongLength {
            expected: INVITE_ID_LEN,
            actual: INVITE_ID_LEN - 1,
        })
    );
    assert_eq!(
        InviteId::from_bytes(&[0u8; INVITE_ID_LEN + 1]),
        Err(LinkError::WrongLength {
            expected: INVITE_ID_LEN,
            actual: INVITE_ID_LEN + 1,
        })
    );
}

#[test]
fn link_id_from_link_secret_digest_takes_the_leading_bytes() {
    // Distinct leading and trailing halves, so an implementation reading
    // the wrong end produces a value this test's expectation disagrees
    // with rather than one that happens to match by coincidence.
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = i as u8;
    }

    let id = LinkId::from_link_secret_digest(&digest);

    assert_eq!(
        id.as_bytes(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

#[test]
fn link_id_from_link_secret_digest_ignores_bytes_past_the_cut() {
    let mut first = [0x11u8; 32];
    let mut second = [0x11u8; 32];
    first[LINK_ID_LEN] = 0x00;
    second[LINK_ID_LEN] = 0xFF;

    assert_ne!(first, second);
    assert_eq!(
        LinkId::from_link_secret_digest(&first),
        LinkId::from_link_secret_digest(&second)
    );
}

#[test]
fn link_id_round_trips_through_display_and_from_str() {
    let original = LinkId::from_bytes(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ])
    .expect("16 bytes must construct");

    let rendered = original.to_string();
    let parsed: LinkId = rendered.parse().expect("its own rendering must parse");

    assert_eq!(original, parsed);
    assert_eq!(rendered, "00112233445566778899aabbccddeeff");
}

#[test]
fn link_id_from_str_accepts_uppercase_hex() {
    let lower: LinkId = "00112233445566778899aabbccddeeff".parse().unwrap();
    let upper: LinkId = "00112233445566778899AABBCCDDEEFF".parse().unwrap();

    assert_eq!(lower, upper);
}

#[test]
fn link_id_from_str_rejects_a_right_length_non_hex_string() {
    let result: Result<LinkId, _> = "z0112233445566778899aabbccddeeff".parse();

    assert_eq!(result, Err(LinkError::InvalidHex));
}

#[test]
fn link_id_from_str_rejects_the_wrong_length() {
    let result: Result<LinkId, _> = "0011223344556677".parse();

    assert_eq!(result, Err(LinkError::InvalidHex));
}

#[test]
fn invite_id_round_trips_through_display_and_from_str() {
    let original = InviteId::from_bytes(&[
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e,
        0x0f,
    ])
    .expect("16 bytes must construct");

    let rendered = original.to_string();
    let parsed: InviteId = rendered.parse().expect("its own rendering must parse");

    assert_eq!(original, parsed);
    assert_eq!(rendered, "f0e1d2c3b4a5968778695a4b3c2d1e0f");
}

#[test]
fn invite_id_from_str_accepts_uppercase_hex() {
    let lower: InviteId = "f0e1d2c3b4a5968778695a4b3c2d1e0f".parse().unwrap();
    let upper: InviteId = "F0E1D2C3B4A5968778695A4B3C2D1E0F".parse().unwrap();

    assert_eq!(lower, upper);
}

#[test]
fn invite_id_from_str_rejects_a_right_length_non_hex_string() {
    let result: Result<InviteId, _> = "g0e1d2c3b4a5968778695a4b3c2d1e0f".parse();

    assert_eq!(result, Err(LinkError::InvalidHex));
}

#[test]
fn invite_id_from_str_rejects_the_wrong_length() {
    let result: Result<InviteId, _> = "0011223344556677".parse();

    assert_eq!(result, Err(LinkError::InvalidHex));
}

//! Supervisor-authored tests for bao verified streaming (CLAUDE.md
//! section 6). Critical Module: verification is what makes a peer's
//! `chunk_index`, `offset_in_chunk` and `payload_len` claims rather
//! than instructions. See ADR-0006 and docs/04-protocol.md, "What a
//! piece carries" and "A piece is verified before it is written".

use tradr_core::{ContentHash, ContentVerifier};
use tradr_integrity::{BaoVerifier, outboard, slice};

const MIB: u64 = 1024 * 1024;

// Deterministic and not compressible into a run of equal bytes, so a
// piece taken from the wrong offset cannot happen to match.
fn content(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u32 = 0x9e37_79b9;
    while out.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn piece(data: &[u8], offset: u64, len: u64) -> (ContentHash, Vec<u8>) {
    let (ob, hash) = outboard(data);
    let s = slice(data, &ob, offset, len).expect("the range lies inside the content");
    (hash, s)
}

#[test]
fn a_piece_at_the_start_verifies_and_yields_its_content() {
    let data = content(3 * MIB as usize);
    let (hash, s) = piece(&data, 0, MIB);

    let got = BaoVerifier
        .verify(&hash, 0, MIB, &s)
        .expect("an untampered slice must verify");
    assert_eq!(got, data[..MIB as usize]);
}

#[test]
fn a_piece_at_a_later_offset_verifies_and_yields_its_content() {
    let data = content(3 * MIB as usize);
    let (hash, s) = piece(&data, 2 * MIB, MIB);

    let got = BaoVerifier
        .verify(&hash, 2 * MIB, MIB, &s)
        .expect("an untampered slice must verify");
    assert_eq!(got, data[(2 * MIB) as usize..]);
}

#[test]
fn a_subdivided_piece_verifies() {
    let data = content(2 * MIB as usize);
    let offset = MIB + 4096;
    let (hash, s) = piece(&data, offset, 4096);

    let got = BaoVerifier
        .verify(&hash, offset, 4096, &s)
        .expect("a transport-sized piece inside a reference chunk must verify");
    assert_eq!(got, data[offset as usize..offset as usize + 4096]);
}

#[test]
fn a_flipped_content_bit_is_refused() {
    let data = content(2 * MIB as usize);
    let (hash, mut s) = piece(&data, 0, MIB);
    let last = s.len() - 1;
    s[last] ^= 0x01;

    assert!(
        BaoVerifier.verify(&hash, 0, MIB, &s).is_err(),
        "a single flipped content bit must not verify"
    );
}

#[test]
fn a_flipped_parent_node_bit_is_refused() {
    let data = content(2 * MIB as usize);
    let (hash, mut s) = piece(&data, 0, MIB);
    s[0] ^= 0x01;

    assert!(
        BaoVerifier.verify(&hash, 0, MIB, &s).is_err(),
        "a flipped bit in the tree path must not verify"
    );
}

#[test]
fn a_slice_does_not_verify_against_another_items_hash() {
    let data = content(2 * MIB as usize);
    let (_, s) = piece(&data, 0, MIB);
    let (_, other_hash) = outboard(&content(2 * MIB as usize + 1));

    assert!(
        BaoVerifier.verify(&other_hash, 0, MIB, &s).is_err(),
        "a slice must be bound to the content hash it was extracted under"
    );
}

// docs/04: the offset is an input to verification, not only to placement.
// This is the test that claim rests on, and the defect it forbids is a
// piece landing at a peer-chosen offset with nothing to refuse it.
#[test]
fn a_piece_presented_at_the_wrong_offset_is_refused() {
    let data = content(3 * MIB as usize);
    let (hash, s) = piece(&data, MIB, MIB);

    assert!(
        BaoVerifier.verify(&hash, 0, MIB, &s).is_err(),
        "chunk 1's bytes must not verify as chunk 0's"
    );
    assert!(
        BaoVerifier.verify(&hash, 2 * MIB, MIB, &s).is_err(),
        "nor as chunk 2's"
    );
}

#[test]
fn a_piece_presented_at_the_wrong_length_is_refused() {
    let data = content(3 * MIB as usize);
    let (hash, s) = piece(&data, MIB, MIB);

    assert!(
        BaoVerifier.verify(&hash, MIB, MIB / 2, &s).is_err(),
        "a shorter claimed length must not verify"
    );
    assert!(
        BaoVerifier.verify(&hash, MIB, 2 * MIB, &s).is_err(),
        "nor a longer one"
    );
}

#[test]
fn a_truncated_slice_is_refused() {
    let data = content(2 * MIB as usize);
    let (hash, s) = piece(&data, 0, MIB);

    for keep in [0, 1, 64, s.len() / 2, s.len() - 1] {
        assert!(
            BaoVerifier.verify(&hash, 0, MIB, &s[..keep]).is_err(),
            "a slice cut to {keep} bytes must not verify"
        );
    }
}

// bao decodes a range past the end of an item as a successful read of
// zero bytes, so a verifier that only asks whether decoding succeeded
// accepts a peer's claim to an offset the item does not contain. The
// yielded length is what settles it.
#[test]
fn a_range_outside_the_item_is_refused_rather_than_verifying_empty() {
    use std::io::{Cursor, Read};

    let data = content(MIB as usize);
    let (ob, hash) = outboard(&data);
    let mut hostile = Vec::new();
    bao::encode::SliceExtractor::new_outboard(Cursor::new(data), Cursor::new(ob), 8 * MIB, MIB)
        .read_to_end(&mut hostile)
        .expect("bao extracts a past-the-end range without complaint");

    assert!(
        BaoVerifier.verify(&hash, 8 * MIB, MIB, &hostile).is_err(),
        "an offset the item does not contain must be refused, not verified as empty"
    );
}

#[test]
fn extracting_a_range_outside_the_content_is_refused() {
    let data = content(MIB as usize);
    let (ob, _) = outboard(&data);

    assert!(
        slice(&data, &ob, 8 * MIB, MIB).is_err(),
        "a sender cannot extract a piece the item does not contain"
    );
}

#[test]
fn an_empty_item_has_a_hash_and_carries_no_piece() {
    let (ob, hash) = outboard(&[]);
    let s = slice(&[], &ob, 0, 0).expect("the empty range of an empty item");

    assert_eq!(
        BaoVerifier.verify(&hash, 0, 0, &s),
        Ok(Vec::new()),
        "an empty item verifies as empty rather than failing"
    );
}

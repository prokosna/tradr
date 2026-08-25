//! Supervisor-authored tests for the `DeviceId` derivation, written first.
//! A Device ID is what a peer is, so two implementations that truncate a
//! digest differently present to each other as devices nobody has met, and
//! nothing in the resulting failure says so. Layer 0 owns which bytes
//! count; the hashing belongs to whoever has a hash function.

use tradr_core::{DEVICE_ID_LEN, DeviceId};

#[test]
fn a_device_id_is_the_leading_bytes_of_the_digest() {
    // CONTEXT.md: the first 16 bytes of BLAKE3 over the identity point.
    // Written out here rather than computed, so an implementation that
    // took the trailing bytes, or reversed them, fails.
    let digest: [u8; 32] = core::array::from_fn(|i| i as u8);

    let id = DeviceId::from_identity_digest(&digest);

    assert_eq!(
        id.as_bytes(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

#[test]
fn the_derivation_takes_exactly_device_id_len_bytes() {
    let digest = [0xABu8; 32];

    let id = DeviceId::from_identity_digest(&digest);

    assert_eq!(id.as_bytes().len(), DEVICE_ID_LEN);
}

#[test]
fn two_digests_differing_only_past_the_cut_yield_one_device_id() {
    // The property that makes truncation what it is, and the reason the
    // rule may exist in only one place: everything after the cut is
    // discarded, so a second implementation that cut elsewhere would
    // disagree on inputs this one calls identical.
    let mut first = [0x11u8; 32];
    let mut second = [0x11u8; 32];
    first[DEVICE_ID_LEN] = 0x00;
    second[DEVICE_ID_LEN] = 0xFF;

    assert_ne!(first, second);
    assert_eq!(
        DeviceId::from_identity_digest(&first),
        DeviceId::from_identity_digest(&second)
    );
}

#[test]
fn two_digests_differing_before_the_cut_yield_different_device_ids() {
    let mut first = [0x11u8; 32];
    let second = [0x11u8; 32];
    first[DEVICE_ID_LEN - 1] = 0x22;

    assert_ne!(
        DeviceId::from_identity_digest(&first),
        DeviceId::from_identity_digest(&second)
    );
}

#[test]
fn the_derivation_agrees_with_building_the_same_bytes_by_hand() {
    // `from_bytes` is the other way into this type, and the two must not
    // be able to disagree about what a given digest means.
    let digest: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);

    let derived = DeviceId::from_identity_digest(&digest);
    let Ok(built) = DeviceId::from_bytes(&digest[..DEVICE_ID_LEN]) else {
        panic!("a slice of exactly DEVICE_ID_LEN bytes must construct");
    };

    assert_eq!(derived, built);
}

#[test]
fn the_derivation_cannot_fail() {
    // A fixed-size digest carries no length to get wrong, so this returns
    // a `DeviceId` and not a `Result`. The test exists because the
    // signature is the claim: a caller with a digest has no error to
    // handle, and no branch where it might invent an identity instead.
    let id: DeviceId = DeviceId::from_identity_digest(&[0u8; 32]);

    assert_eq!(id.as_bytes(), &[0u8; DEVICE_ID_LEN]);
}

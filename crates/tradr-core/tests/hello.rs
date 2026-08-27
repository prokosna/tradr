//! Tests for the Hello exchange's vocabulary (docs/04-protocol.md, "The
//! Hello exchange", DCR-051): version negotiation, `HelloNonce`,
//! `PeerHello` and `PeerHelloAck`.

use tradr_core::{
    Capabilities, DisplayName, HelloNonce, KeyBinding, PUBLIC_KEY_POINT_LEN, PeerHello,
    PeerHelloAck, PublicKeyPoint, Rng, RngError, Signature, TrustTier, UnixTime, VersionRange,
    VersionRangeError, negotiate_version,
};

fn point(byte: u8) -> PublicKeyPoint {
    PublicKeyPoint::from_bytes(&[byte; PUBLIC_KEY_POINT_LEN]).expect("65 bytes must construct")
}

fn key_binding() -> KeyBinding {
    KeyBinding::new(
        point(1),
        Signature::from_bytes(vec![9; 4]),
        UnixTime::from_secs(1_000),
    )
}

// A fake that fills a buffer with one fixed byte, so a test can assert
// exactly which nonce `generate` produced.
struct FixedRng {
    byte: u8,
}

impl Rng for FixedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(self.byte);
        Ok(())
    }
}

// --- VersionRange ---

#[test]
fn version_range_new_rejects_inverted_bounds() {
    assert_eq!(
        VersionRange::new(3, 1),
        Err(VersionRangeError::Inverted { min: 3, max: 1 })
    );
}

#[test]
fn version_range_new_rejects_zero_because_protobuf_omits_a_zero_valued_scalar() {
    // A Hello carrying no version fields decodes as { min: 0, max: 0 };
    // accepting 0 as a version would let a peer that sent nothing negotiate one.
    assert_eq!(
        VersionRange::new(0, 0),
        Err(VersionRangeError::ZeroIsNotAVersion)
    );
}

#[test]
fn version_range_new_rejects_zero_min_even_with_a_positive_max() {
    assert_eq!(
        VersionRange::new(0, 5),
        Err(VersionRangeError::ZeroIsNotAVersion)
    );
}

#[test]
fn version_range_new_accepts_a_single_supported_version() {
    let range = VersionRange::new(1, 1).expect("a single version is normal");
    assert_eq!(range.min(), 1);
    assert_eq!(range.max(), 1);
}

#[test]
fn version_range_min_and_max_report_distinct_bounds() {
    // (1, 1) alone cannot catch an accessor that swaps min and max: both
    // sides of the swap read the same value. This range makes the two
    // observably different.
    let range = VersionRange::new(3, 9).expect("valid");
    assert_eq!(range.min(), 3);
    assert_eq!(range.max(), 9);
}

// --- negotiate_version ---

#[test]
fn negotiate_version_picks_the_lower_of_the_two_maxima_when_ranges_overlap() {
    let ours = VersionRange::new(1, 5).expect("valid");
    let theirs = VersionRange::new(3, 8).expect("valid");

    assert_eq!(negotiate_version(ours, theirs), Ok(5));
}

#[test]
fn negotiate_version_when_one_range_wholly_contains_the_other() {
    let ours = VersionRange::new(1, 10).expect("valid");
    let theirs = VersionRange::new(4, 6).expect("valid");

    assert_eq!(negotiate_version(ours, theirs), Ok(6));
}

#[test]
fn negotiate_version_at_the_exact_touching_boundary() {
    let ours = VersionRange::new(1, 4).expect("valid");
    let theirs = VersionRange::new(4, 7).expect("valid");

    assert_eq!(negotiate_version(ours, theirs), Ok(4));
}

#[test]
fn negotiate_version_refuses_when_ours_is_entirely_below_theirs() {
    let ours = VersionRange::new(1, 2).expect("valid");
    let theirs = VersionRange::new(3, 5).expect("valid");

    let err = negotiate_version(ours, theirs).expect_err("no overlap");
    assert_eq!(err.ours(), ours);
    assert_eq!(err.theirs(), theirs);
}

#[test]
fn negotiate_version_refuses_when_ours_is_entirely_above_theirs() {
    let ours = VersionRange::new(6, 9).expect("valid");
    let theirs = VersionRange::new(1, 3).expect("valid");

    let err = negotiate_version(ours, theirs).expect_err("no overlap");
    assert_eq!(err.ours(), ours);
    assert_eq!(err.theirs(), theirs);
}

#[test]
fn no_common_version_ours_and_theirs_report_distinct_ranges() {
    // Both ranges here differ from each other in every field, so an
    // accessor or field returning the wrong side is observable.
    let ours = VersionRange::new(6, 9).expect("valid");
    let theirs = VersionRange::new(1, 3).expect("valid");

    let err = negotiate_version(ours, theirs).expect_err("no overlap");

    assert_eq!(err.ours().min(), 6);
    assert_eq!(err.ours().max(), 9);
    assert_eq!(err.theirs().min(), 1);
    assert_eq!(err.theirs().max(), 3);
}

#[test]
fn negotiate_version_is_symmetric() {
    let pairs = [
        (
            VersionRange::new(1, 5).unwrap(),
            VersionRange::new(3, 8).unwrap(),
        ),
        (
            VersionRange::new(1, 10).unwrap(),
            VersionRange::new(4, 6).unwrap(),
        ),
        (
            VersionRange::new(1, 4).unwrap(),
            VersionRange::new(4, 7).unwrap(),
        ),
        (
            VersionRange::new(1, 2).unwrap(),
            VersionRange::new(3, 5).unwrap(),
        ),
        (
            VersionRange::new(1, 1).unwrap(),
            VersionRange::new(1, 1).unwrap(),
        ),
    ];

    for (a, b) in pairs {
        let forward = negotiate_version(a, b);
        let backward = negotiate_version(b, a);
        assert_eq!(
            forward.is_ok(),
            backward.is_ok(),
            "negotiate({a:?}, {b:?}) and its reverse disagreed on success"
        );
        if let (Ok(f), Ok(bk)) = (forward, backward) {
            assert_eq!(
                f, bk,
                "negotiate({a:?}, {b:?}) and its reverse disagreed on the version"
            );
        }
    }
}

// --- HelloNonce ---

#[test]
fn hello_nonce_generate_draws_from_the_rng_trait() {
    let rng = FixedRng { byte: 0x7a };

    let nonce = HelloNonce::generate(&rng).expect("fake never fails");

    assert_eq!(nonce.as_bytes(), &[0x7a; 16]);
    assert_eq!(nonce.as_bytes().len(), 16);
}

// --- PeerHello ---

#[test]
fn peer_hello_round_trips_without_a_display_name() {
    let versions = VersionRange::new(1, 3).expect("valid");
    let identity_pub = point(2);
    let agreement_pub = point(3);
    let nonce = HelloNonce::from_bytes([7; 16]);
    let capabilities = Capabilities::DIRECT_QUIC;

    let hello = PeerHello::new(
        versions,
        identity_pub.clone(),
        agreement_pub.clone(),
        "header.payload.signature".to_string(),
        key_binding(),
        nonce,
        capabilities,
    );

    assert_eq!(hello.versions(), versions);
    assert_eq!(hello.identity_pub(), &identity_pub);
    assert_eq!(hello.agreement_pub(), &agreement_pub);
    assert_eq!(hello.attestation_token(), "header.payload.signature");
    assert_eq!(hello.key_binding(), &key_binding());
    assert_eq!(hello.nonce(), nonce);
    assert_eq!(hello.capabilities(), capabilities);
    assert_eq!(hello.display_name(), None);
}

#[test]
fn peer_hello_round_trips_with_a_display_name() {
    let display_name = DisplayName::new("Alice's Laptop").expect("valid");

    let hello = PeerHello::new(
        VersionRange::new(1, 1).expect("valid"),
        point(2),
        point(3),
        "token".to_string(),
        key_binding(),
        HelloNonce::from_bytes([0; 16]),
        Capabilities::empty(),
    )
    .with_display_name(display_name.clone());

    assert_eq!(hello.display_name(), Some(&display_name));
}

#[test]
fn peer_hello_debug_redacts_the_attestation_token_but_keeps_other_fields() {
    let token = "super-secret-bearer-token";
    let nonce = HelloNonce::from_bytes([9; 16]);

    let hello = PeerHello::new(
        VersionRange::new(1, 1).expect("valid"),
        point(2),
        point(3),
        token.to_string(),
        key_binding(),
        nonce,
        Capabilities::empty(),
    );

    let debug = format!("{hello:?}");

    assert!(
        !debug.contains(token),
        "debug output leaked the attestation token: {debug}"
    );
    assert!(
        debug.contains("redacted"),
        "debug output dropped the redaction placeholder: {debug}"
    );
    assert!(
        debug.contains("9, 9, 9"),
        "debug output dropped an unrelated field: {debug}"
    );
}

// --- PeerHelloAck ---

#[test]
fn peer_hello_ack_round_trips() {
    let signature = Signature::from_bytes(vec![1, 2, 3]);

    let ack = PeerHelloAck::new(3, 65536, signature.clone(), TrustTier::Linked);

    assert_eq!(ack.negotiated_version(), 3);
    assert_eq!(ack.max_frame_size(), 65536);
    assert_eq!(ack.nonce_signature(), &signature);
    assert_eq!(ack.assigned_tier(), TrustTier::Linked);
}

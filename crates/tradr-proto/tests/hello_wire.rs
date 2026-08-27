//! Tests `tradr_proto::hello`'s conversions between the wire `Hello` /
//! `HelloAck` and `tradr_core`'s native `PeerHello` / `PeerHelloAck`
//! (docs/04-protocol.md, "The Hello exchange", DCR-053). Round trips first,
//! then one hostile test per thing an untrusted peer can get wrong.

use tradr_core::{Capabilities, DisplayName, PublicKeyPoint, TrustTier};
use tradr_proto::hello::{
    HelloWireError, peer_hello_ack_from_wire, peer_hello_ack_to_wire, peer_hello_from_wire,
    peer_hello_to_wire,
};
use tradr_proto::v1;

// A `v1::Hello` where every field is valid, so tests corrupt exactly one
// field at a time and know the rest cannot be the cause of a refusal.
fn valid_hello() -> v1::Hello {
    v1::Hello {
        min_version: 1,
        max_version: 5,
        device: Some(v1::DeviceInfo {
            device_id: vec![9, 9],
            identity_pub: vec![3u8; 65],
            agreement_pub: vec![4u8; 65],
            display_name: "kitchen-laptop".to_string(),
            platform: v1::Platform::Linux as i32,
            capabilities: 0b0101,
        }),
        attestation: Some(v1::Attestation {
            id_token: "token-abc".to_string(),
            issuer: "google".to_string(),
            issued_at: 1_700_000_000,
        }),
        key_binding: Some(v1::KeyBinding {
            agreement_pub: vec![4u8; 65],
            signature: vec![7u8; 10],
            not_after: 1_800_000_000,
        }),
        nonce: vec![6u8; 16],
    }
}

fn valid_hello_ack() -> v1::HelloAck {
    v1::HelloAck {
        negotiated_version: 3,
        max_frame_size: 65536,
        nonce_signature: vec![8u8; 10],
        assigned_tier: v1::TrustTier::Linked as i32,
        visible_shares: Vec::new(),
    }
}

// ---- Round trips ----

#[test]
fn hello_round_trips_with_display_name() {
    let wire = valid_hello();
    let peer = peer_hello_from_wire(wire.clone()).expect("valid Hello must convert");
    let back = peer_hello_to_wire(&peer);

    assert_eq!(back.min_version, wire.min_version);
    assert_eq!(back.max_version, wire.max_version);
    assert_eq!(
        back.device.as_ref().unwrap().identity_pub,
        wire.device.as_ref().unwrap().identity_pub
    );
    assert_eq!(
        back.device.as_ref().unwrap().agreement_pub,
        wire.device.as_ref().unwrap().agreement_pub
    );
    assert_eq!(
        back.device.as_ref().unwrap().display_name,
        wire.device.as_ref().unwrap().display_name
    );
    assert_eq!(
        back.device.as_ref().unwrap().capabilities,
        wire.device.as_ref().unwrap().capabilities
    );
    assert_eq!(
        back.attestation.as_ref().unwrap().id_token,
        wire.attestation.as_ref().unwrap().id_token
    );
    assert_eq!(
        back.key_binding.as_ref().unwrap().agreement_pub,
        wire.key_binding.as_ref().unwrap().agreement_pub
    );
    assert_eq!(
        back.key_binding.as_ref().unwrap().signature,
        wire.key_binding.as_ref().unwrap().signature
    );
    assert_eq!(
        back.key_binding.as_ref().unwrap().not_after,
        wire.key_binding.as_ref().unwrap().not_after
    );
    assert_eq!(back.nonce, wire.nonce);
}

#[test]
fn hello_round_trips_without_display_name() {
    let mut wire = valid_hello();
    wire.device.as_mut().unwrap().display_name = String::new();

    let peer = peer_hello_from_wire(wire).expect("valid Hello must convert");
    assert_eq!(peer.display_name(), None);

    let back = peer_hello_to_wire(&peer);
    assert_eq!(back.device.unwrap().display_name, "");
}

#[test]
fn hello_ack_round_trips() {
    let wire = valid_hello_ack();
    let peer = peer_hello_ack_from_wire(wire.clone()).expect("valid HelloAck must convert");
    let back = peer_hello_ack_to_wire(&peer);

    assert_eq!(back.negotiated_version, wire.negotiated_version);
    assert_eq!(back.max_frame_size, wire.max_frame_size);
    assert_eq!(back.nonce_signature, wire.nonce_signature);
    assert_eq!(back.assigned_tier, wire.assigned_tier);
}

// ---- to_wire is infallible ----

#[test]
fn to_wire_directions_do_not_return_a_result() {
    let peer = peer_hello_from_wire(valid_hello()).expect("valid Hello must convert");
    let _: v1::Hello = peer_hello_to_wire(&peer);

    let ack = peer_hello_ack_from_wire(valid_hello_ack()).expect("valid HelloAck must convert");
    let _: v1::HelloAck = peer_hello_ack_to_wire(&ack);
}

// ---- Hostile inputs, one test each ----

#[test]
fn absent_device_is_refused() {
    let mut wire = valid_hello();
    wire.device = None;

    let err = peer_hello_from_wire(wire).expect_err("absent device must be refused");
    assert_eq!(err, HelloWireError::MissingDevice);
}

#[test]
fn absent_attestation_is_refused() {
    let mut wire = valid_hello();
    wire.attestation = None;

    let err = peer_hello_from_wire(wire).expect_err("absent attestation must be refused");
    assert_eq!(err, HelloWireError::MissingAttestation);
}

#[test]
fn absent_key_binding_is_refused() {
    let mut wire = valid_hello();
    wire.key_binding = None;

    let err = peer_hello_from_wire(wire).expect_err("absent key_binding must be refused");
    assert_eq!(err, HelloWireError::MissingKeyBinding);
}

#[test]
fn identity_pub_of_64_bytes_is_refused() {
    let mut wire = valid_hello();
    wire.device.as_mut().unwrap().identity_pub = vec![3u8; 64];

    let err = peer_hello_from_wire(wire).expect_err("64-byte identity_pub must be refused");
    assert!(matches!(err, HelloWireError::InvalidIdentityPub(_)));
}

#[test]
fn identity_pub_of_66_bytes_is_refused() {
    let mut wire = valid_hello();
    wire.device.as_mut().unwrap().identity_pub = vec![3u8; 66];

    let err = peer_hello_from_wire(wire).expect_err("66-byte identity_pub must be refused");
    assert!(matches!(err, HelloWireError::InvalidIdentityPub(_)));
}

#[test]
fn nonce_of_15_bytes_is_refused() {
    let mut wire = valid_hello();
    wire.nonce = vec![6u8; 15];

    let err = peer_hello_from_wire(wire).expect_err("15-byte nonce must be refused");
    assert_eq!(err, HelloWireError::InvalidNonce { len: 15 });
}

#[test]
fn nonce_of_17_bytes_is_refused() {
    let mut wire = valid_hello();
    wire.nonce = vec![6u8; 17];

    let err = peer_hello_from_wire(wire).expect_err("17-byte nonce must be refused");
    assert_eq!(err, HelloWireError::InvalidNonce { len: 17 });
}

#[test]
fn zero_default_version_range_is_refused() {
    let mut wire = valid_hello();
    wire.min_version = 0;
    wire.max_version = 0;

    let err = peer_hello_from_wire(wire).expect_err("zero-default version range must be refused");
    assert!(matches!(err, HelloWireError::InvalidVersionRange(_)));
}

#[test]
fn assigned_tier_unspecified_is_refused() {
    let mut wire = valid_hello_ack();
    wire.assigned_tier = v1::TrustTier::Unspecified as i32;

    let err = peer_hello_ack_from_wire(wire).expect_err("unspecified tier must be refused");
    assert!(matches!(err, HelloWireError::InvalidAssignedTier(_)));
}

#[test]
fn assigned_tier_with_no_defined_variant_is_refused() {
    let mut wire = valid_hello_ack();
    wire.assigned_tier = 99;

    let err = peer_hello_ack_from_wire(wire).expect_err("undefined tier must be refused");
    assert!(matches!(err, HelloWireError::InvalidAssignedTier(_)));
}

#[test]
fn wholly_empty_hello_is_refused() {
    let wire = v1::Hello::default();
    peer_hello_from_wire(wire).expect_err("an all-default Hello must be refused");
}

// ---- DCR-053's two disagreements ----

#[test]
fn capabilities_narrows_to_the_low_16_bits_and_succeeds() {
    let mut wire = valid_hello();
    wire.device.as_mut().unwrap().capabilities = 0xFFFF_FFFF;

    let peer = peer_hello_from_wire(wire).expect("an out-of-range capabilities must not refuse");
    assert_eq!(peer.capabilities(), Capabilities::from_bits(0xFFFF));
}

#[test]
fn display_name_of_33_bytes_is_dropped_not_refused() {
    let mut wire = valid_hello();
    wire.device.as_mut().unwrap().display_name = "a".repeat(33);

    let peer = peer_hello_from_wire(wire).expect("an over-long display_name must not refuse");
    assert_eq!(peer.display_name(), None);
}

#[test]
fn display_name_of_32_bytes_is_kept() {
    let mut wire = valid_hello();
    let name = "a".repeat(32);
    wire.device.as_mut().unwrap().display_name = name.clone();

    let peer = peer_hello_from_wire(wire).expect("a boundary-length display_name must convert");
    assert_eq!(
        peer.display_name(),
        Some(&DisplayName::new(&name).expect("32 bytes is the maximum, not over it"))
    );
}

#[test]
fn empty_display_name_is_none_not_an_error() {
    let mut wire = valid_hello();
    wire.device.as_mut().unwrap().display_name = String::new();

    let peer = peer_hello_from_wire(wire).expect("an empty display_name must not refuse");
    assert_eq!(peer.display_name(), None);
}

// ---- issuer / issued_at are discarded ----

#[test]
fn issuer_and_issued_at_never_appear_in_peer_hello() {
    let mut wire = valid_hello();
    wire.attestation.as_mut().unwrap().issuer = "not-the-real-issuer".to_string();
    wire.attestation.as_mut().unwrap().issued_at = 424_242;

    let peer = peer_hello_from_wire(wire).expect("valid Hello must convert");
    assert_eq!(peer.attestation_token(), "token-abc");

    // PeerHello's Debug is hand-written to redact the token entirely, so
    // this also confirms neither field leaked in some other form.
    let debug = format!("{peer:?}");
    assert!(!debug.contains("not-the-real-issuer"));
    assert!(!debug.contains("424242"));
}

#[test]
fn to_wire_writes_issuer_and_issued_at_as_defaults() {
    let peer = peer_hello_from_wire(valid_hello()).expect("valid Hello must convert");
    let back = peer_hello_to_wire(&peer);

    assert_eq!(back.attestation.as_ref().unwrap().issuer, "");
    assert_eq!(back.attestation.as_ref().unwrap().issued_at, 0);
}

// ---- Error Display never carries key bytes or token text ----

#[test]
fn error_display_never_carries_the_attestation_token() {
    let secret_token = "eyJhbGciOiJSUzI1NiJ9.super-secret-payload.sig";
    let mut wire = valid_hello();
    wire.attestation.as_mut().unwrap().id_token = secret_token.to_string();
    wire.nonce = vec![6u8; 15]; // Fails after the token has already been read into the message.

    let err = peer_hello_from_wire(wire).expect_err("15-byte nonce must be refused");
    assert!(!err.to_string().contains(secret_token));
}

#[test]
fn error_display_never_carries_key_or_nonce_bytes() {
    let marker: u8 = 0xEE;

    let mut bad_identity = valid_hello();
    bad_identity.device.as_mut().unwrap().identity_pub = vec![marker; 3];
    let identity_err = peer_hello_from_wire(bad_identity).expect_err("must be refused");

    let mut bad_agreement = valid_hello();
    bad_agreement.device.as_mut().unwrap().agreement_pub = vec![marker; 3];
    let agreement_err = peer_hello_from_wire(bad_agreement).expect_err("must be refused");

    let mut bad_key_binding = valid_hello();
    bad_key_binding.key_binding.as_mut().unwrap().agreement_pub = vec![marker; 3];
    let key_binding_err = peer_hello_from_wire(bad_key_binding).expect_err("must be refused");

    let mut bad_nonce = valid_hello();
    bad_nonce.nonce = vec![marker; 15];
    let nonce_err = peer_hello_from_wire(bad_nonce).expect_err("must be refused");

    for err in [identity_err, agreement_err, key_binding_err, nonce_err] {
        let text = err.to_string();
        assert!(!text.contains(&marker.to_string()));
        assert!(!text.to_lowercase().contains("ee,ee,ee"));
    }
}

#[test]
fn error_display_covers_every_variant_without_leaking() {
    let variants = [
        HelloWireError::MissingDevice,
        HelloWireError::MissingAttestation,
        HelloWireError::MissingKeyBinding,
        HelloWireError::InvalidVersionRange(
            tradr_core::VersionRange::new(5, 1).expect_err("5 > 1 is inverted"),
        ),
        HelloWireError::InvalidIdentityPub(
            PublicKeyPoint::from_bytes(&[0xAB; 3]).expect_err("3 bytes is the wrong length"),
        ),
        HelloWireError::InvalidAgreementPub(
            PublicKeyPoint::from_bytes(&[0xAB; 3]).expect_err("3 bytes is the wrong length"),
        ),
        HelloWireError::InvalidKeyBindingAgreementPub(
            PublicKeyPoint::from_bytes(&[0xAB; 3]).expect_err("3 bytes is the wrong length"),
        ),
        HelloWireError::InvalidNonce { len: 15 },
        HelloWireError::InvalidAssignedTier(
            TrustTier::try_from(0).expect_err("0 is TRUST_TIER_UNSPECIFIED"),
        ),
    ];

    for variant in variants {
        let text = variant.to_string();
        assert!(!text.contains("0xab"));
        assert!(!text.contains("171")); // 0xAB as decimal, in case bytes leaked raw
        assert!(!text.is_empty());
    }
}

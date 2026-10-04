//! Supervisor-authored tests for HPKE base mode (ADR-0025, DCR-173).
//! Critical Module: opening a Deferred Delivery. The vectors are RFC 9180
//! section A.5, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.

use p256::SecretKey;
use tradr_core::{KeyStoreError, PublicKeyPoint, Rng, RngError, SharedSecret};
use tradr_identity::hpke::{
    HpkeError, setup_base_receiver, setup_base_sender, setup_base_sender_with_ephemeral,
};

fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex in a fixed vector"))
        .collect()
}

const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const SK_EM: &str = "7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689";
const PK_RM: &str = "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006";
const SK_RM: &str = "a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b";
const ENC: &str = "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291";
const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

// (sequence number, aad, ciphertext) from RFC 9180 A.5.1.1.
const ENCRYPTIONS: [(u64, &str, &str); 6] = [
    (
        0,
        "436f756e742d30",
        "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b",
    ),
    (
        1,
        "436f756e742d31",
        "f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374",
    ),
    (
        2,
        "436f756e742d32",
        "39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592ff87c3f310c",
    ),
    (
        4,
        "436f756e742d34",
        "bc104a14fbede0cc79eeb826ea0476ce87b9c928c36e5e34dc9b6905d91473ec369a08b1a25d305dd45c6c5f80",
    ),
    (
        255,
        "436f756e742d323535",
        "8f2814a2c548b3be50259713c6724009e092d37789f6856553d61df23ebc079235f710e6af3c3ca6eaba7c7c6c",
    ),
    (
        256,
        "436f756e742d323536",
        "b45b69d419a9be7219d8c94365b89ad6951caf4576ea4774ea40e9b7047a09d6537d1aa2f7c12d6ae4b729b4d0",
    ),
];

// (exporter_context, exported value), L = 32, from RFC 9180 A.5.1.2.
const EXPORTS: [(&str, &str); 3] = [
    (
        "",
        "9b13c510416ac977b553bf1741018809c246a695f45eff6d3b0356dbefe1e660",
    ),
    (
        "00",
        "6c8b7be3a20a5684edecb4253619d9051ce8583baf850e0cb53c402bdcaf8ebb",
    ),
    (
        "54657374436f6e74657874",
        "477a50d804c7c51941f69b8e32fe8288386ee1a84905fe4938d58972f24ac938",
    ),
];

fn pk_r() -> PublicKeyPoint {
    PublicKeyPoint::from_bytes(&hex(PK_RM)).expect("65-byte point")
}

fn sk_e() -> [u8; 32] {
    hex(SK_EM).try_into().expect("32-byte scalar")
}

fn enc() -> [u8; 65] {
    hex(ENC).try_into().expect("65-byte enc")
}

// Stands in for KeyStore::agree over the vector's recipient key.
fn agree_with_sk_r(peer: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
    let sk = SecretKey::from_slice(&hex(SK_RM)).map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
    let pk = p256::PublicKey::from_sec1_bytes(peer.as_bytes())
        .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
}

#[test]
fn the_sender_encapsulates_to_the_vectors_enc() {
    let (enc_out, _ctx) =
        setup_base_sender_with_ephemeral(&pk_r(), &sk_e(), &hex(INFO)).expect("setup");
    assert_eq!(enc_out.to_vec(), hex(ENC));
}

#[test]
fn the_sender_seals_the_vectors_ciphertexts_at_each_sequence_number() {
    let (_enc, mut ctx) =
        setup_base_sender_with_ephemeral(&pk_r(), &sk_e(), &hex(INFO)).expect("setup");
    let pt = hex(PT);
    for seq in 0..=256u64 {
        let expected = ENCRYPTIONS.iter().find(|(s, _, _)| *s == seq);
        let aad = match expected {
            Some((_, aad, _)) => hex(aad),
            None => b"filler".to_vec(),
        };
        let ct = ctx.seal(&aad, &pt).expect("seal");
        if let Some((_, _, want)) = expected {
            assert_eq!(ct, hex(want), "sequence number {seq}");
        }
    }
}

#[test]
fn the_receiver_opens_the_vectors_first_ciphertext() {
    let mut ctx =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("setup");
    let (_, aad, ct) = ENCRYPTIONS[0];
    assert_eq!(ctx.open(&hex(aad), &hex(ct)).expect("open"), hex(PT));
}

#[test]
fn the_receiver_opens_every_sequence_in_order() {
    let (_enc, mut sender) =
        setup_base_sender_with_ephemeral(&pk_r(), &sk_e(), &hex(INFO)).expect("sender");
    let mut receiver =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    for seq in 0..=256u64 {
        let aad = format!("aad-{seq}").into_bytes();
        let pt = format!("record {seq}").into_bytes();
        let ct = sender.seal(&aad, &pt).expect("seal");
        assert_eq!(
            receiver.open(&aad, &ct).expect("open"),
            pt,
            "sequence number {seq}"
        );
    }
}

#[test]
fn both_sides_export_the_vectors_values() {
    let (_enc, sender) =
        setup_base_sender_with_ephemeral(&pk_r(), &sk_e(), &hex(INFO)).expect("sender");
    let receiver =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    for (context, want) in EXPORTS {
        assert_eq!(sender.export(&hex(context), 32).expect("export"), hex(want));
        assert_eq!(
            receiver.export(&hex(context), 32).expect("export"),
            hex(want)
        );
    }
}

#[test]
fn a_flipped_ciphertext_byte_does_not_open() {
    let mut receiver =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    let (_, aad, ct) = ENCRYPTIONS[0];
    let mut ct = hex(ct);
    ct[3] ^= 0x01;
    assert!(matches!(
        receiver.open(&hex(aad), &ct),
        Err(HpkeError::OpenFailed)
    ));
}

#[test]
fn different_associated_data_does_not_open() {
    let mut receiver =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    let (_, _, ct) = ENCRYPTIONS[0];
    assert!(matches!(
        receiver.open(b"Count-1", &hex(ct)),
        Err(HpkeError::OpenFailed)
    ));
}

#[test]
fn a_different_info_does_not_open() {
    let mut receiver = setup_base_receiver(&enc(), &pk_r(), b"another envelope", &agree_with_sk_r)
        .expect("receiver");
    let (_, aad, ct) = ENCRYPTIONS[0];
    assert!(matches!(
        receiver.open(&hex(aad), &hex(ct)),
        Err(HpkeError::OpenFailed)
    ));
}

#[test]
fn a_ciphertext_out_of_sequence_does_not_open() {
    let mut receiver =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    let (_, aad, ct) = ENCRYPTIONS[1];
    assert!(matches!(
        receiver.open(&hex(aad), &hex(ct)),
        Err(HpkeError::OpenFailed)
    ));
}

#[test]
fn an_enc_that_is_not_a_curve_point_is_refused() {
    let mut bad = enc();
    bad[64] ^= 0x01;
    assert!(setup_base_receiver(&bad, &pk_r(), &hex(INFO), &agree_with_sk_r).is_err());
    let mut compressed_tag = enc();
    compressed_tag[0] = 0x02;
    assert!(setup_base_receiver(&compressed_tag, &pk_r(), &hex(INFO), &agree_with_sk_r).is_err());
}

#[test]
fn a_recipient_key_that_is_not_a_curve_point_is_refused_by_the_sender() {
    let mut bytes = hex(PK_RM);
    bytes[64] ^= 0x01;
    let bad = PublicKeyPoint::from_bytes(&bytes).expect("65 bytes");
    assert!(setup_base_sender_with_ephemeral(&bad, &sk_e(), &hex(INFO)).is_err());
}

#[test]
fn a_failing_agreement_is_an_error_and_not_a_panic() {
    let failing = |_: &PublicKeyPoint| -> Result<SharedSecret, KeyStoreError> {
        Err(KeyStoreError::Backend(Box::new(std::io::Error::other(
            "no key",
        ))))
    };
    assert!(setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &failing).is_err());
}

struct Counter(std::cell::Cell<u8>);

impl Rng for Counter {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        let start = self.0.get();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8).wrapping_mul(31).wrapping_add(7);
        }
        self.0.set(start.wrapping_add(1));
        Ok(())
    }
}

struct Zeros;

impl Rng for Zeros {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(0);
        Ok(())
    }
}

#[test]
fn a_random_ephemeral_round_trips_and_differs_per_setup() {
    let rng = Counter(std::cell::Cell::new(1));
    let (enc_a, mut sender) = setup_base_sender(&pk_r(), &rng, &hex(INFO)).expect("sender a");
    let (enc_b, _) = setup_base_sender(&pk_r(), &rng, &hex(INFO)).expect("sender b");
    assert_ne!(enc_a, enc_b);
    let mut receiver =
        setup_base_receiver(&enc_a, &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    let ct = sender.seal(b"aad", b"hello").expect("seal");
    assert_eq!(receiver.open(b"aad", &ct).expect("open"), b"hello");
}

#[test]
fn an_rng_that_yields_no_valid_scalar_is_an_error_and_not_a_panic() {
    assert!(setup_base_sender(&pk_r(), &Zeros, &hex(INFO)).is_err());
}

#[test]
fn a_failed_open_does_not_advance_the_sequence_number() {
    let mut receiver =
        setup_base_receiver(&enc(), &pk_r(), &hex(INFO), &agree_with_sk_r).expect("receiver");
    let (_, aad, ct) = ENCRYPTIONS[0];
    let mut tampered = hex(ct);
    tampered[0] ^= 0x01;
    assert!(receiver.open(&hex(aad), &tampered).is_err());
    assert_eq!(receiver.open(&hex(aad), &hex(ct)).expect("open"), hex(PT));
}

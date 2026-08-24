//! Supervisor-authored tests for WI-M0-011d, written before the
//! implementation. docs/05: "an unknown `kid` is a rejection, not a
//! lookup", so what a JWKS document yields is exactly the set verification
//! may select from. Critical Module: an entry this build cannot use must
//! never silently become one it can.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use tradr_identity::{JwksError, SignatureAlgorithm, parse_jwks};

/// RFC 7518 sets 2048 bits as the floor for RS256. Spelled out here rather
/// than imported, so a wrong constant in the implementation cannot make
/// these tests agree with it.
const MIN_MODULUS_BYTES: usize = 256;

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

// A modulus of `len` bytes with a non-zero leading byte, so its
// significant length equals its full length.
fn modulus(len: usize) -> Vec<u8> {
    let mut bytes = vec![0xAB; len];
    bytes[0] = 0xC7;
    bytes
}

const EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

fn rsa_key(kid: &str) -> Value {
    json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": b64(&modulus(MIN_MODULUS_BYTES)),
        "e": b64(&EXPONENT),
    })
}

fn document(keys: Vec<Value>) -> Vec<u8> {
    json!({ "keys": keys }).to_string().into_bytes()
}

fn single(key: Value) -> Vec<u8> {
    document(vec![key])
}

// Asserts the error is `Malformed`, without pinning its wording: the
// reason string is for a human reading a log, not a value to depend on.
fn assert_malformed(result: Result<Vec<tradr_identity::Jwk>, JwksError>) {
    match result {
        Err(JwksError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

// --- What a usable entry yields ---

#[test]
fn a_single_rsa_key_parses_to_exactly_what_was_published() {
    let keys = parse_jwks(&single(rsa_key("k1"))).expect("a well-formed RS256 key must parse");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "k1");
    assert_eq!(keys[0].algorithm, SignatureAlgorithm::Rs256);
    assert_eq!(keys[0].modulus, modulus(MIN_MODULUS_BYTES));
    assert_eq!(keys[0].exponent, EXPONENT.to_vec());
}

#[test]
fn several_keys_keep_the_order_the_document_published_them_in() {
    let doc = document(vec![rsa_key("a"), rsa_key("b"), rsa_key("c")]);

    let kids: Vec<String> = parse_jwks(&doc)
        .expect("three well-formed keys must parse")
        .into_iter()
        .map(|k| k.kid)
        .collect();

    assert_eq!(kids, ["a", "b", "c"]);
}

#[test]
fn an_entry_without_use_is_accepted() {
    let mut key = rsa_key("k1");
    key.as_object_mut().expect("a JSON object").remove("use");

    let keys = parse_jwks(&single(key)).expect("RFC 7517 makes `use` optional");

    assert_eq!(keys.len(), 1);
}

#[test]
fn members_this_build_does_not_read_are_ignored() {
    let mut key = rsa_key("k1");
    let object = key.as_object_mut().expect("a JSON object");
    object.insert("x5t".to_string(), json!("thumbprint"));
    object.insert("x5c".to_string(), json!(["certificate"]));

    let keys = parse_jwks(&single(key)).expect("Google publishes both of these members");

    assert_eq!(keys.len(), 1);
}

// --- Entries this build cannot use are skipped, never rejected ---

#[test]
fn a_key_published_for_encryption_is_skipped() {
    let mut enc = rsa_key("enc");
    enc.as_object_mut()
        .expect("a JSON object")
        .insert("use".to_string(), json!("enc"));
    let doc = document(vec![enc, rsa_key("sig")]);

    let keys = parse_jwks(&doc).expect("the signing key remains usable");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "sig");
}

#[test]
fn a_key_of_another_type_is_skipped() {
    let ec = json!({
        "kty": "EC", "alg": "ES256", "use": "sig", "kid": "ec",
        "crv": "P-256", "x": b64(&[1; 32]), "y": b64(&[2; 32]),
    });
    let doc = document(vec![ec, rsa_key("rsa")]);

    let keys = parse_jwks(&doc).expect("a curve this build does not verify is not an error");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "rsa");
}

#[test]
fn a_key_published_for_an_algorithm_this_build_cannot_verify_is_skipped() {
    let mut ps = rsa_key("ps");
    ps.as_object_mut()
        .expect("a JSON object")
        .insert("alg".to_string(), json!("PS256"));
    let doc = document(vec![ps, rsa_key("rs")]);

    let keys = parse_jwks(&doc).expect("PS256 shares RSA key material but is a different scheme");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "rs");
}

#[test]
fn a_key_that_names_no_algorithm_is_skipped() {
    let mut key = rsa_key("k1");
    key.as_object_mut().expect("a JSON object").remove("alg");
    let doc = document(vec![key, rsa_key("k2")]);

    let keys = parse_jwks(&doc).expect("`alg` is optional in RFC 7517 and required here");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "k2");
}

#[test]
fn a_key_no_header_could_select_is_skipped() {
    let mut key = rsa_key("k1");
    key.as_object_mut().expect("a JSON object").remove("kid");
    let doc = document(vec![key, rsa_key("k2")]);

    let keys = parse_jwks(&doc).expect("a key with no id can never be selected by a kid");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "k2");
}

#[test]
fn a_skipped_entry_never_collides_with_a_usable_one() {
    let ec = json!({ "kty": "EC", "alg": "ES256", "use": "sig", "kid": "shared" });
    let doc = document(vec![ec, rsa_key("shared")]);

    let keys = parse_jwks(&doc).expect("a skipped entry contributes no id");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "shared");
}

// --- A document with nothing usable in it ---

#[test]
fn a_document_whose_entries_are_all_unusable_yields_no_usable_keys() {
    let ec = json!({ "kty": "EC", "alg": "ES256", "use": "sig", "kid": "ec" });
    let oct = json!({ "kty": "oct", "alg": "HS256", "kid": "oct", "k": b64(&[9; 32]) });

    assert_eq!(
        parse_jwks(&document(vec![ec, oct])),
        Err(JwksError::NoUsableKeys)
    );
}

#[test]
fn an_empty_key_set_yields_no_usable_keys() {
    assert_eq!(parse_jwks(&document(vec![])), Err(JwksError::NoUsableKeys));
}

// --- The document's own shape ---

#[test]
fn a_body_that_is_not_json_is_malformed() {
    assert_malformed(parse_jwks(b"<html>rate limited</html>"));
}

#[test]
fn an_empty_body_is_malformed() {
    assert_malformed(parse_jwks(b""));
}

#[test]
fn a_bare_array_of_keys_is_malformed() {
    let bare = json!([rsa_key("k1")]).to_string().into_bytes();

    assert_malformed(parse_jwks(&bare));
}

#[test]
fn a_document_with_no_keys_member_is_malformed() {
    let doc = json!({ "jwks": [rsa_key("k1")] }).to_string().into_bytes();

    assert_malformed(parse_jwks(&doc));
}

#[test]
fn a_keys_member_that_is_not_an_array_is_malformed() {
    let doc = json!({ "keys": rsa_key("k1") }).to_string().into_bytes();

    assert_malformed(parse_jwks(&doc));
}

#[test]
fn an_entry_that_is_not_an_object_is_malformed() {
    let doc = json!({ "keys": ["k1"] }).to_string().into_bytes();

    assert_malformed(parse_jwks(&doc));
}

// --- A usable entry that is broken makes the whole document broken.
// Dropping it instead would leave a partial set that verification then
// treats as the provider's full set, turning corruption into a `kid` that
// is published but unknown.

#[test]
fn a_usable_entry_without_a_modulus_is_malformed() {
    let mut key = rsa_key("k1");
    key.as_object_mut().expect("a JSON object").remove("n");

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn a_usable_entry_without_an_exponent_is_malformed() {
    let mut key = rsa_key("k1");
    key.as_object_mut().expect("a JSON object").remove("e");

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn a_modulus_that_is_not_a_string_is_malformed() {
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!(65537));

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn a_modulus_that_is_not_base64url_is_malformed() {
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!("not base64url!!"));

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn a_padded_modulus_is_malformed() {
    let padded = base64::engine::general_purpose::URL_SAFE.encode(modulus(MIN_MODULUS_BYTES));
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!(padded));

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn an_empty_modulus_is_malformed() {
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!(""));

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn an_empty_exponent_is_malformed() {
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("e".to_string(), json!(""));

    assert_malformed(parse_jwks(&single(key)));
}

#[test]
fn a_broken_entry_after_a_good_one_still_breaks_the_document() {
    let mut broken = rsa_key("k2");
    broken.as_object_mut().expect("a JSON object").remove("n");

    assert_malformed(parse_jwks(&document(vec![rsa_key("k1"), broken])));
}

// --- A modulus too small to be worth verifying against ---

#[test]
fn a_modulus_under_two_thousand_forty_eight_bits_is_a_weak_key() {
    let short = modulus(MIN_MODULUS_BYTES - 1);
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!(b64(&short)));

    assert_eq!(
        parse_jwks(&single(key)),
        Err(JwksError::WeakKey {
            kid: "k1".to_string(),
            modulus_bytes: MIN_MODULUS_BYTES - 1,
        })
    );
}

#[test]
fn leading_zeroes_do_not_pad_a_short_modulus_up_to_size() {
    let mut padded = vec![0u8; 8];
    padded.extend_from_slice(&modulus(MIN_MODULUS_BYTES - 8));
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!(b64(&padded)));

    assert_eq!(
        parse_jwks(&single(key)),
        Err(JwksError::WeakKey {
            kid: "k1".to_string(),
            modulus_bytes: MIN_MODULUS_BYTES - 8,
        })
    );
}

#[test]
fn a_long_enough_modulus_keeps_its_leading_zeroes() {
    let mut published = vec![0u8; 4];
    published.extend_from_slice(&modulus(MIN_MODULUS_BYTES));
    let mut key = rsa_key("k1");
    key.as_object_mut()
        .expect("a JSON object")
        .insert("n".to_string(), json!(b64(&published)));

    let keys = parse_jwks(&single(key)).expect("stripping is for measuring, not for storing");

    assert_eq!(keys[0].modulus, published);
}

// --- One id, one key ---

#[test]
fn two_usable_keys_sharing_an_id_reject_the_document() {
    let doc = document(vec![rsa_key("same"), rsa_key("same")]);

    assert_eq!(
        parse_jwks(&doc),
        Err(JwksError::DuplicateKeyId("same".to_string()))
    );
}

#[test]
fn the_first_failure_in_document_order_is_the_one_reported() {
    let mut broken = rsa_key("dup");
    broken.as_object_mut().expect("a JSON object").remove("n");

    assert_malformed(parse_jwks(&document(vec![broken, rsa_key("dup")])));
}

#[test]
fn a_key_of_another_type_is_skipped_even_when_it_names_rs256() {
    let mut forged = rsa_key("forged");
    forged
        .as_object_mut()
        .expect("a JSON object")
        .insert("kty".to_string(), json!("oct"));
    let doc = document(vec![forged, rsa_key("real")]);

    let keys = parse_jwks(&doc).expect("the RSA key remains usable");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "real");
}

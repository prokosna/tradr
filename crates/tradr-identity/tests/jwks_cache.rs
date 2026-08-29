//! Supervisor-authored tests for WI-M0-011e, written before the
//! implementation. docs/05 and DCR-022: a refetch budget enforced by the
//! caller is a rule about callers, and there will be more than one, so
//! claiming the budget is what spends it. Critical Module: the failure
//! this guards is a peer turning random `kid` values into outbound traffic.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use tradr_core::Monotonic;
use tradr_identity::{JwksCache, JwksError};

/// docs/05 sets the floor between refetches at five minutes. Spelled out
/// rather than imported, so a wrong constant in the implementation cannot
/// make these tests agree with it.
const REFETCH_FLOOR_SECS: u64 = 300;

const MODULUS_BYTES: usize = 256;
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// A fixed origin per test, so readings are exact arithmetic rather than
/// anything measured. `Instant` has no public constructor, which is why an
/// origin has to be taken rather than named.
struct Timeline {
    origin: Instant,
}

impl Timeline {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    fn at(&self, secs: u64) -> Monotonic {
        Monotonic::from_instant(self.origin + Duration::from_secs(secs))
    }
}

fn modulus(fill: u8, len: usize) -> Vec<u8> {
    let mut bytes = vec![fill; len];
    bytes[0] = 0xC7;
    bytes
}

fn rsa_key(kid: &str) -> Value {
    json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": B64.encode(modulus(0xAB, MODULUS_BYTES)),
        "e": B64.encode([0x01, 0x00, 0x01]),
    })
}

fn document(keys: Vec<Value>) -> Vec<u8> {
    json!({ "keys": keys }).to_string().into_bytes()
}

fn published(kids: &[&str]) -> Vec<u8> {
    document(kids.iter().map(|kid| rsa_key(kid)).collect())
}

fn cached_kids(cache: &JwksCache) -> Vec<String> {
    cache.keys().iter().map(|k| k.kid.clone()).collect()
}

// --- What a cache holds ---

#[test]
fn a_new_cache_holds_no_keys() {
    let cache = JwksCache::new(JWKS_URI);

    assert!(cache.keys().is_empty());
}

#[test]
fn a_cache_reports_the_uri_it_was_built_with() {
    let cache = JwksCache::new(JWKS_URI);

    assert_eq!(cache.jwks_uri(), JWKS_URI);
}

#[test]
fn installing_a_document_makes_its_keys_the_cached_ones() {
    let mut cache = JwksCache::new(JWKS_URI);

    cache
        .install(&published(&["a", "b"]))
        .expect("a well-formed document must install");

    assert_eq!(cached_kids(&cache), ["a", "b"]);
}

#[test]
fn installing_replaces_the_previous_set_rather_than_adding_to_it() {
    let mut cache = JwksCache::new(JWKS_URI);
    cache.install(&published(&["old"])).expect("first install");

    cache.install(&published(&["new"])).expect("second install");

    assert_eq!(cached_kids(&cache), ["new"]);
}

// --- A refetch can only ever add to what a device can verify.
// docs/05 makes offline verification the property that keeps Tier 0
// serverless, so a fetch that fails must not be able to empty a cache
// that was working a moment earlier.

#[test]
fn a_document_that_is_not_json_leaves_the_cache_untouched() {
    let mut cache = JwksCache::new(JWKS_URI);
    cache.install(&published(&["good"])).expect("first install");

    let outcome = cache.install(b"<html>502 Bad Gateway</html>");

    assert!(matches!(outcome, Err(JwksError::Malformed(_))));
    assert_eq!(cached_kids(&cache), ["good"]);
}

#[test]
fn a_document_with_nothing_usable_in_it_leaves_the_cache_untouched() {
    let mut cache = JwksCache::new(JWKS_URI);
    cache.install(&published(&["good"])).expect("first install");
    let ec = json!({ "kty": "EC", "alg": "ES256", "use": "sig", "kid": "ec" });

    assert_eq!(
        cache.install(&document(vec![ec])),
        Err(JwksError::NoUsableKeys)
    );
    assert_eq!(cached_kids(&cache), ["good"]);
}

#[test]
fn a_document_carrying_a_weak_key_leaves_the_cache_untouched() {
    let mut cache = JwksCache::new(JWKS_URI);
    cache.install(&published(&["good"])).expect("first install");
    let mut weak = rsa_key("weak");
    weak.as_object_mut().expect("a JSON object").insert(
        "n".to_string(),
        json!(B64.encode(modulus(0xAB, MODULUS_BYTES - 1))),
    );

    assert_eq!(
        cache.install(&document(vec![weak])),
        Err(JwksError::WeakKey {
            kid: "weak".to_string(),
            modulus_bytes: MODULUS_BYTES - 1,
        })
    );
    assert_eq!(cached_kids(&cache), ["good"]);
}

#[test]
fn a_failed_install_on_an_empty_cache_leaves_it_empty() {
    let mut cache = JwksCache::new(JWKS_URI);

    assert!(cache.install(b"not a document").is_err());
    assert!(cache.keys().is_empty());
}

// --- The refetch budget ---

#[test]
fn an_unknown_kid_on_a_cold_cache_claims_a_refetch() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);

    assert!(cache.claim_refetch_for("k1", time.at(0)));
}

#[test]
fn a_cached_kid_is_never_a_reason_to_refetch() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    cache.install(&published(&["k1"])).expect("install");

    assert!(!cache.claim_refetch_for("k1", time.at(0)));
}

#[test]
fn asking_about_a_cached_kid_does_not_spend_the_budget() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    cache.install(&published(&["k1"])).expect("install");

    assert!(!cache.claim_refetch_for("k1", time.at(0)));

    assert!(cache.claim_refetch_for("k2", time.at(1)));
}

#[test]
fn claiming_is_what_spends_the_budget_not_fetching() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);

    assert!(cache.claim_refetch_for("k1", time.at(0)));

    assert!(!cache.claim_refetch_for("k1", time.at(1)));
}

#[test]
fn a_different_unknown_kid_gets_no_budget_of_its_own() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);

    assert!(cache.claim_refetch_for("first", time.at(0)));

    assert!(!cache.claim_refetch_for("second", time.at(1)));
}

#[test]
fn a_successful_install_does_not_refund_the_budget() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    assert!(cache.claim_refetch_for("wanted", time.at(0)));

    cache.install(&published(&["other"])).expect("install");

    assert!(!cache.claim_refetch_for("wanted", time.at(1)));
}

#[test]
fn a_key_that_arrives_stops_being_a_reason_to_refetch() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    assert!(cache.claim_refetch_for("wanted", time.at(0)));
    cache.install(&published(&["wanted"])).expect("install");

    assert!(!cache.claim_refetch_for("wanted", time.at(REFETCH_FLOOR_SECS * 2)));
}

#[test]
fn the_budget_returns_only_once_the_floor_has_passed() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    assert!(cache.claim_refetch_for("k1", time.at(0)));

    assert!(!cache.claim_refetch_for("k1", time.at(REFETCH_FLOOR_SECS - 1)));
    assert!(cache.claim_refetch_for("k1", time.at(REFETCH_FLOOR_SECS)));
}

#[test]
fn the_floor_is_measured_from_the_last_claim_not_from_the_first() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    assert!(cache.claim_refetch_for("k1", time.at(0)));
    assert!(cache.claim_refetch_for("k1", time.at(REFETCH_FLOOR_SECS)));

    assert!(!cache.claim_refetch_for("k1", time.at(2 * REFETCH_FLOOR_SECS - 1)));
    assert!(cache.claim_refetch_for("k1", time.at(2 * REFETCH_FLOOR_SECS)));
}

#[test]
fn a_reading_that_has_not_advanced_leaves_the_budget_spent() {
    let time = Timeline::new();
    let mut cache = JwksCache::new(JWKS_URI);
    assert!(cache.claim_refetch_for("k1", time.at(0)));

    assert!(!cache.claim_refetch_for("k1", time.at(0)));
}

//! Supervisor-authored tests for WI-M0-008b. RFC 7636's own Appendix B
//! vector is the anchor. A predictable verifier and a `plain` challenge
//! method both leave a working flow and hand the authorization code to
//! any local process that can win the race for it, which is why the
//! randomness comes through the `Rng` trait (rule B7) and S256 is fixed.

use std::cell::Cell;

use tradr_core::{Rng, RngError};
use tradr_oidc::{OidcError, Pkce, authorization_url};

/// RFC 7636 Appendix B, verbatim. The one pair of values in these tests
/// that comes from outside this project.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const AUTH_URI: &str = "https://accounts.google.com/o/oauth2/auth";
const CLIENT_ID: &str = "475695468283-shsoa7f59bdbta9jlubfs49jonv1m7ng.apps.googleusercontent.com";
const REDIRECT: &str = "http://127.0.0.1:8731/callback";
const SCOPE: &str = "openid email profile";
const NONCE: &str = "s5_tYS3-Wq0lF4h9nRMzKxYvbTGqZzPiUu2cJdA1eLk";
const STATE: &str = "a-state-value";

/// Fills every buffer with one repeated byte. Two instances built the same
/// way are indistinguishable, which is what makes "the verifier came from
/// nowhere else" a testable claim.
struct FixedRng {
    byte: u8,
    fails: bool,
    calls: Cell<u32>,
}

impl FixedRng {
    fn of(byte: u8) -> Self {
        Self {
            byte,
            fails: false,
            calls: Cell::new(0),
        }
    }

    fn failing() -> Self {
        Self {
            byte: 0,
            fails: true,
            calls: Cell::new(0),
        }
    }
}

impl Rng for FixedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        self.calls.set(self.calls.get() + 1);
        if self.fails {
            return Err(RngError::Source(Box::new(std::io::Error::other(
                "no entropy",
            ))));
        }
        buf.fill(self.byte);
        Ok(())
    }
}

fn generated(byte: u8) -> Pkce {
    Pkce::generate(&FixedRng::of(byte)).expect("a working rng must yield a verifier")
}

// --- The transform, against the RFC's own vector ---

#[test]
fn the_rfc_appendix_b_verifier_maps_to_its_published_challenge() {
    let pkce = Pkce::from_verifier(RFC_VERIFIER).expect("the RFC's verifier is well formed");

    assert_eq!(pkce.challenge(), RFC_CHALLENGE);
    assert_eq!(pkce.verifier(), RFC_VERIFIER);
}

#[test]
fn a_challenge_is_never_the_verifier_repeated_back() {
    let pkce = generated(7);

    assert_ne!(pkce.challenge(), pkce.verifier());
}

// --- Where the randomness comes from ---

#[test]
fn a_generated_verifier_is_within_the_length_the_rfc_allows() {
    let verifier = generated(7).verifier().len();

    assert!((43..=128).contains(&verifier), "length {verifier}");
}

/// 0xFB and 0xFF are the byte values whose base64 sextets land on indexes
/// 62 and 63, the two the standard alphabet spells `+` and `/`. A fixture
/// that avoids them cannot tell a url-safe encoder from a standard one.
#[test]
fn a_generated_verifier_uses_only_the_rfc_unreserved_characters() {
    for byte in [0x00, 0x7f, 0xfb, 0xff] {
        let pkce = generated(byte);
        assert!(
            pkce.verifier()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)),
            "byte {byte:#04x} produced {}",
            pkce.verifier()
        );
    }
}

#[test]
fn the_verifier_is_drawn_from_the_injected_rng_and_nowhere_else() {
    assert_eq!(generated(9).verifier(), generated(9).verifier());
}

#[test]
fn different_randomness_gives_a_different_verifier() {
    assert_ne!(generated(1).verifier(), generated(2).verifier());
}

/// A failing entropy source is not a malformed verifier: no verifier was
/// formed. The distinction is what an operator reads in a log, and only
/// one of the two readings points at the machine that is actually broken.
#[test]
fn an_rng_that_fails_is_reported_as_an_entropy_failure() {
    assert!(matches!(
        Pkce::generate(&FixedRng::failing()),
        Err(OidcError::Entropy(_))
    ));
}

#[test]
fn generating_draws_from_the_rng_at_least_once() {
    let rng = FixedRng::of(5);

    Pkce::generate(&rng).expect("a working rng");

    assert!(rng.calls.get() >= 1);
}

// --- What counts as a verifier at all ---

#[test]
fn a_verifier_below_the_rfc_minimum_is_refused() {
    let short = "a".repeat(42);

    assert!(matches!(
        Pkce::from_verifier(&short),
        Err(OidcError::MalformedVerifier(_))
    ));
}

#[test]
fn a_verifier_above_the_rfc_maximum_is_refused() {
    let long = "a".repeat(129);

    assert!(matches!(
        Pkce::from_verifier(&long),
        Err(OidcError::MalformedVerifier(_))
    ));
}

#[test]
fn both_rfc_length_bounds_are_inclusive() {
    assert!(Pkce::from_verifier(&"a".repeat(43)).is_ok());
    assert!(Pkce::from_verifier(&"a".repeat(128)).is_ok());
}

#[test]
fn a_verifier_carrying_a_reserved_character_is_refused() {
    for bad in ["+", "/", "=", " ", "%", "\u{00e9}"] {
        let verifier = format!("{}{bad}", "a".repeat(43));
        assert!(
            matches!(
                Pkce::from_verifier(&verifier),
                Err(OidcError::MalformedVerifier(_))
            ),
            "{bad:?} should not be allowed in a verifier"
        );
    }
}

// --- The authorization url ---

fn built() -> String {
    authorization_url(
        AUTH_URI,
        CLIENT_ID,
        REDIRECT,
        SCOPE,
        NONCE,
        STATE,
        generated(7).challenge(),
    )
    .expect("a well-formed authorization url")
}

#[test]
fn the_url_carries_every_parameter_the_flow_needs() {
    let url = built();

    for expected in [
        "response_type=code",
        "client_id=",
        "redirect_uri=",
        "scope=",
        "nonce=",
        "state=",
        "code_challenge=",
        "code_challenge_method=S256",
    ] {
        assert!(url.contains(expected), "{expected} missing from {url}");
    }
}

/// `plain` is a permitted PKCE method and it defends nothing: the code
/// challenge and the verifier are the same string, so anyone who sees the
/// authorization request can complete the exchange.
#[test]
fn the_challenge_method_is_s256_and_plain_appears_nowhere() {
    let url = built();

    assert!(url.contains("code_challenge_method=S256"));
    assert!(!url.to_ascii_lowercase().contains("plain"));
}

#[test]
fn the_nonce_survives_the_round_trip_unaltered() {
    let url = built();
    let nonce = url
        .split('&')
        .find_map(|p| p.strip_prefix("nonce="))
        .expect("a nonce parameter");

    assert_eq!(nonce, NONCE);
}

#[test]
fn a_scope_containing_spaces_is_encoded_rather_than_split() {
    let url = built();

    assert!(!url.contains("openid email"));
    assert!(url.contains("openid%20email%20profile") || url.contains("openid+email+profile"));
}

#[test]
fn the_redirect_uri_is_encoded_rather_than_ending_the_query() {
    let url = built();

    assert!(!url.contains("redirect_uri=http://127.0.0.1"));
    assert!(url.contains("127.0.0.1") || url.contains("127%2E0%2E0%2E1"));
}

#[test]
fn an_authorization_uri_that_is_not_https_is_refused() {
    let outcome = authorization_url(
        "http://accounts.google.com/o/oauth2/auth",
        CLIENT_ID,
        REDIRECT,
        SCOPE,
        NONCE,
        STATE,
        generated(7).challenge(),
    );

    assert!(matches!(outcome, Err(OidcError::NotHttps(_))));
}

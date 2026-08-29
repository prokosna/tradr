//! Supervisor-authored tests for WI-M0-011f, written before the
//! implementation. DCR-024 makes JWKS retrieval a Critical Module: TLS to
//! the provider's own host is the only thing that makes a key set the
//! provider's, and an attacker whose keys a device fetches passes all
//! seven of docs/05's steps with a perfectly valid signature.

use tradr_oidc::{BodyAccumulator, OidcError, require_https, require_ok};

/// docs: the cap on a JWKS body. Google's is a couple of kilobytes and
/// this holds about fifty RSA keys. Spelled out rather than imported, so a
/// wrong constant in the implementation cannot make these tests agree.
const BODY_CAP: usize = 64 * 1024;

const GOOGLE: &str = "https://www.googleapis.com/oauth2/v3/certs";

fn assert_not_https(uri: &str) {
    match require_https(uri) {
        Err(OidcError::NotHttps(_)) => {}
        other => panic!("{uri} should not be https, got {other:?}"),
    }
}

fn assert_malformed(uri: &str) {
    match require_https(uri) {
        Err(OidcError::MalformedUri(_)) => {}
        other => panic!("{uri} should be malformed, got {other:?}"),
    }
}

fn assert_misleading(uri: &str, resolved: &str) {
    assert_eq!(
        require_https(uri),
        Err(OidcError::MisleadingAuthority {
            resolved: resolved.to_string()
        })
    );
}

// --- Which URIs may be fetched at all ---

#[test]
fn an_https_uri_is_accepted() {
    assert_eq!(require_https(GOOGLE), Ok(()));
}

#[test]
fn the_scheme_is_compared_case_insensitively() {
    assert_eq!(require_https("HTTPS://www.googleapis.com/certs"), Ok(()));
}

#[test]
fn a_plain_http_uri_is_rejected() {
    assert_not_https("http://www.googleapis.com/oauth2/v3/certs");
}

#[test]
fn a_scheme_that_merely_starts_with_http_is_rejected() {
    assert_not_https("httpss://www.googleapis.com/certs");
    assert_not_https("http+https://www.googleapis.com/certs");
}

#[test]
fn a_file_uri_is_rejected() {
    assert_not_https("file:///etc/passwd");
}

#[test]
fn a_data_uri_is_rejected() {
    assert_not_https("data:application/json,%7B%22keys%22%3A%5B%5D%7D");
}

#[test]
fn a_uri_carrying_no_scheme_is_rejected() {
    assert_malformed("//www.googleapis.com/certs");
    assert_malformed("www.googleapis.com/certs");
}

// The host a URL parser resolves is not always the host a reader sees, and
// both forms below parse without error. A `jwks_uri` is compiled in rather
// than attacker-supplied, so these are typos this project would ship -- and
// shipping one points every device's trust root at another host. Nothing
// downstream notices, since the keys fetched there sign perfectly valid tokens.

#[test]
fn an_empty_authority_does_not_become_the_first_path_segment() {
    assert_misleading("https:///oauth2/v3/certs", "oauth2");
}

#[test]
fn userinfo_may_not_stand_where_a_reader_expects_the_host() {
    assert_misleading(
        "https://www.googleapis.com@evil.example/oauth2/v3/certs",
        "evil.example",
    );
    assert_misleading(
        "https://www.googleapis.com:pw@evil.example/certs",
        "evil.example",
    );
}

#[test]
fn a_host_and_port_written_plainly_is_accepted() {
    assert_eq!(require_https("https://127.0.0.1:8443/certs"), Ok(()));
}

#[test]
fn a_host_written_in_mixed_case_is_accepted() {
    assert_eq!(require_https("https://Www.GoogleAPIs.com/certs"), Ok(()));
}

#[test]
fn something_that_is_not_a_uri_at_all_is_rejected() {
    assert_malformed("");
    assert_malformed("not a uri");
}

// --- Which responses may be read. A 3xx is not a 200, so this is also
// the second line of defence behind a client that follows no redirects:
// a redirect arriving as a response is rejected as a status, whatever
// the client would otherwise have done with it.

#[test]
fn only_two_hundred_is_accepted() {
    assert_eq!(require_ok(200), Ok(()));
}

#[test]
fn a_redirect_is_rejected() {
    for status in [301, 302, 303, 307, 308] {
        assert_eq!(require_ok(status), Err(OidcError::UnexpectedStatus(status)));
    }
}

#[test]
fn another_success_status_is_still_rejected() {
    for status in [201, 204, 206] {
        assert_eq!(require_ok(status), Err(OidcError::UnexpectedStatus(status)));
    }
}

#[test]
fn a_client_or_server_error_is_rejected() {
    for status in [400, 403, 404, 429, 500, 502, 503] {
        assert_eq!(require_ok(status), Err(OidcError::UnexpectedStatus(status)));
    }
}

// --- How much of a response may be buffered. Enforced while the body is
// read rather than after it, or an endpoint streaming without end fills
// memory before any check runs.

fn accumulate(chunks: &[&[u8]]) -> Result<Vec<u8>, OidcError> {
    let mut body = BodyAccumulator::new();
    for chunk in chunks {
        body.push(chunk)?;
    }
    Ok(body.finish())
}

#[test]
fn an_empty_body_accumulates_to_nothing() {
    assert_eq!(accumulate(&[]), Ok(Vec::new()));
}

#[test]
fn chunks_are_joined_in_the_order_they_arrive() {
    assert_eq!(
        accumulate(&[b"{\"keys\"", b":[]", b"}"]),
        Ok(b"{\"keys\":[]}".to_vec())
    );
}

#[test]
fn a_body_exactly_at_the_cap_is_accepted() {
    let at_cap = vec![b'x'; BODY_CAP];

    assert_eq!(accumulate(&[&at_cap]), Ok(at_cap.clone()));
}

#[test]
fn one_byte_past_the_cap_is_rejected() {
    let over = vec![b'x'; BODY_CAP + 1];

    assert_eq!(
        accumulate(&[&over]),
        Err(OidcError::BodyTooLarge { cap: BODY_CAP })
    );
}

#[test]
fn the_cap_counts_across_chunks_and_not_within_one() {
    let chunk = vec![b'x'; 1024];
    let chunks: Vec<&[u8]> = std::iter::repeat_n(chunk.as_slice(), BODY_CAP / 1024 + 1).collect();

    assert_eq!(
        accumulate(&chunks),
        Err(OidcError::BodyTooLarge { cap: BODY_CAP })
    );
}

#[test]
fn the_chunk_that_crosses_the_cap_is_the_one_that_fails() {
    let mut body = BodyAccumulator::new();
    let filler = vec![b'x'; BODY_CAP - 1];

    assert_eq!(body.push(&filler), Ok(()));
    assert_eq!(body.push(b"y"), Ok(()));
    assert_eq!(
        body.push(b"z"),
        Err(OidcError::BodyTooLarge { cap: BODY_CAP })
    );
}

#[test]
fn a_chunk_that_would_cross_the_cap_is_not_kept() {
    let mut body = BodyAccumulator::new();
    let filler = vec![b'x'; BODY_CAP - 1];
    assert_eq!(body.push(&filler), Ok(()));

    assert!(body.push(b"yy").is_err());

    assert_eq!(body.finish(), filler);
}

// These three parse cleanly and resolve to the right host, and two of them
// are the same slash typo from the other direction. Refusing them costs a
// profile author nothing -- no provider publishes a uri in these shapes --
// and it keeps the rule to one sentence: the text says what was resolved.

#[test]
fn a_uri_missing_a_slash_after_the_scheme_is_rejected() {
    assert!(require_https("https:/www.googleapis.com/oauth2/v3/certs").is_err());
    assert!(require_https("https:www.googleapis.com/oauth2/v3/certs").is_err());
}

#[test]
fn a_uri_with_extra_slashes_after_the_scheme_is_rejected() {
    assert!(require_https("https:////www.googleapis.com/certs").is_err());
}

#[test]
fn a_bracketed_ipv6_host_is_accepted() {
    assert_eq!(require_https("https://[::1]:8443/certs"), Ok(()));
}

#[test]
fn a_uri_whose_host_repeats_its_scheme_still_needs_the_separator() {
    // The one shape where falling back to the whole uri, instead of
    // refusing a uri carrying no `://`, would let something through: the
    // text does begin with the resolved host, because the host is `https`.
    assert!(require_https("https:https/certs").is_err());

    assert_eq!(require_https("https://https/certs"), Ok(()));
}

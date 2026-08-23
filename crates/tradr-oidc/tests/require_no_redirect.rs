//! `require_no_redirect` is the barrier that does not depend on the
//! client's redirect policy holding: nothing else in this crate would
//! notice if `Policy::none()` silently stopped applying, since
//! `require_ok` only ever sees the final status. Exercises the
//! comparison on its own, as a pure function of two uri strings.

use tradr_oidc::{OidcError, require_no_redirect};

#[test]
fn identical_urls_pass() {
    let uri = "https://www.googleapis.com/oauth2/v3/certs";
    assert_eq!(require_no_redirect(uri, uri), Ok(()));
}

#[test]
fn a_different_host_is_redirected() {
    assert_eq!(
        require_no_redirect(
            "https://www.googleapis.com/oauth2/v3/certs",
            "https://evil.example/oauth2/v3/certs"
        ),
        Err(OidcError::Redirected {
            to: "https://evil.example/oauth2/v3/certs".to_string()
        })
    );
}

#[test]
fn a_different_path_on_the_same_host_is_redirected() {
    assert_eq!(
        require_no_redirect(
            "https://www.googleapis.com/oauth2/v3/certs",
            "https://www.googleapis.com/other/path"
        ),
        Err(OidcError::Redirected {
            to: "https://www.googleapis.com/other/path".to_string()
        })
    );
}

#[test]
fn a_bare_host_against_its_slash_form_passes_as_normalisation() {
    assert_eq!(
        require_no_redirect("https://www.googleapis.com", "https://www.googleapis.com/"),
        Ok(())
    );
}

#[test]
fn a_host_that_only_differs_in_case_passes_as_normalisation() {
    assert_eq!(
        require_no_redirect(
            "https://Www.GoogleAPIs.com/certs",
            "https://www.googleapis.com/certs"
        ),
        Ok(())
    );
}

#[test]
fn an_unparseable_requested_uri_is_malformed() {
    match require_no_redirect("not a uri", "https://www.googleapis.com/certs") {
        Err(OidcError::MalformedUri(_)) => {}
        other => panic!("expected MalformedUri, got {other:?}"),
    }
}

#[test]
fn an_unparseable_responded_uri_is_malformed() {
    match require_no_redirect("https://www.googleapis.com/certs", "not a uri") {
        Err(OidcError::MalformedUri(_)) => {}
        other => panic!("expected MalformedUri, got {other:?}"),
    }
}

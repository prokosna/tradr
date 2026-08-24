//! Supervisor-authored tests for WI-M0-008c's two pure halves. The desktop
//! flow redirects to a loopback port, so the query string arriving there
//! is written by whatever reached the port first. `state` is the only
//! thing that says the response belongs to the request this process made,
//! and a token response without an `id_token` is not a signed anything.

use tradr_oidc::{OidcError, callback_redirect_uri, parse_callback, parse_token_response};

const STATE: &str = "Yb3xQ-1nZpKcE7sVfLm0Tg";
const CODE: &str = "4/0AeanS0YxamPLe-authorization-code";

fn ok_query() -> String {
    format!("code={CODE}&state={STATE}")
}

// --- Which callback belongs to this request ---

#[test]
fn a_callback_carrying_the_expected_state_yields_its_code() {
    assert_eq!(parse_callback(&ok_query(), STATE), Ok(CODE.to_string()));
}

#[test]
fn the_order_of_the_two_parameters_does_not_matter() {
    let reversed = format!("state={STATE}&code={CODE}");

    assert_eq!(parse_callback(&reversed, STATE), Ok(CODE.to_string()));
}

#[test]
fn a_leading_question_mark_is_tolerated() {
    let with_mark = format!("?{}", ok_query());

    assert_eq!(parse_callback(&with_mark, STATE), Ok(CODE.to_string()));
}

#[test]
fn a_callback_with_someone_elses_state_is_refused() {
    let other = format!("code={CODE}&state=a-state-this-process-never-sent");

    assert_eq!(parse_callback(&other, STATE), Err(OidcError::StateMismatch));
}

#[test]
fn a_callback_with_no_state_at_all_is_refused() {
    let bare = format!("code={CODE}");

    assert_eq!(parse_callback(&bare, STATE), Err(OidcError::StateMismatch));
}

#[test]
fn an_empty_expected_state_matches_nothing() {
    assert_eq!(
        parse_callback("code=c&state=", ""),
        Err(OidcError::StateMismatch)
    );
}

#[test]
fn state_is_compared_in_full_and_not_by_prefix() {
    let extended = format!("code={CODE}&state={STATE}x");

    assert_eq!(
        parse_callback(&extended, STATE),
        Err(OidcError::StateMismatch)
    );
}

// A query string may repeat a name, and a parser that takes the first or
// the last is choosing on the caller's behalf between two values an
// attacker supplied one of. Neither choice is defensible, so both are
// refused.
#[test]
fn a_repeated_parameter_is_refused_rather_than_resolved() {
    let two_codes = format!("code={CODE}&code=another&state={STATE}");
    let two_states = format!("code={CODE}&state={STATE}&state={STATE}");

    assert!(matches!(
        parse_callback(&two_codes, STATE),
        Err(OidcError::MalformedCallback(_))
    ));
    assert!(matches!(
        parse_callback(&two_states, STATE),
        Err(OidcError::MalformedCallback(_))
    ));
}

// --- What the provider says went wrong ---

// The state check runs first. An `error=` response with a foreign state
// is somebody else's failure, and reporting it as this request's would
// let any local process end this flow with a message of its choosing.
#[test]
fn a_provider_error_is_reported_only_when_the_state_matches() {
    let denied = format!("error=access_denied&state={STATE}");
    assert_eq!(
        parse_callback(&denied, STATE),
        Err(OidcError::AuthorizationDenied("access_denied".to_string()))
    );

    let foreign = "error=access_denied&state=not-ours";
    assert_eq!(
        parse_callback(foreign, STATE),
        Err(OidcError::StateMismatch)
    );
}

#[test]
fn a_callback_with_neither_code_nor_error_is_refused() {
    let empty = format!("state={STATE}");

    assert!(matches!(
        parse_callback(&empty, STATE),
        Err(OidcError::MalformedCallback(_))
    ));
}

#[test]
fn an_empty_code_is_not_a_code() {
    let blank = format!("code=&state={STATE}");

    assert!(matches!(
        parse_callback(&blank, STATE),
        Err(OidcError::MalformedCallback(_))
    ));
}

#[test]
fn a_percent_encoded_code_is_decoded() {
    let encoded = format!("code=4%2F0Aean%20S0&state={STATE}");

    assert_eq!(
        parse_callback(&encoded, STATE),
        Ok("4/0Aean S0".to_string())
    );
}

// --- What came back from the token endpoint ---

#[test]
fn a_token_response_yields_its_id_token() {
    let body =
        br#"{"access_token":"ya29.x","expires_in":3599,"id_token":"h.p.s","token_type":"Bearer"}"#;

    assert_eq!(parse_token_response(body), Ok("h.p.s".to_string()));
}

// An OAuth token response is a perfectly valid one without an `id_token`
// -- that is what a plain OAuth exchange returns. This design needs the
// OIDC one, and treating the difference as absence rather than as an
// error is how a flow ends up authenticating nobody.
#[test]
fn a_response_with_no_id_token_is_an_error_and_not_an_absence() {
    let body = br#"{"access_token":"ya29.x","expires_in":3599,"token_type":"Bearer"}"#;

    assert!(matches!(
        parse_token_response(body),
        Err(OidcError::MalformedTokenResponse(_))
    ));
}

#[test]
fn an_id_token_that_is_not_a_string_is_refused() {
    let body = br#"{"id_token":1234}"#;

    assert!(matches!(
        parse_token_response(body),
        Err(OidcError::MalformedTokenResponse(_))
    ));
}

#[test]
fn an_empty_id_token_is_refused() {
    let body = br#"{"id_token":""}"#;

    assert!(matches!(
        parse_token_response(body),
        Err(OidcError::MalformedTokenResponse(_))
    ));
}

#[test]
fn a_body_that_is_not_json_is_refused() {
    assert!(matches!(
        parse_token_response(b"<html>502</html>"),
        Err(OidcError::MalformedTokenResponse(_))
    ));
}

// The fixture is the real refusal this project spent an experiment
// re-deriving. `invalid_request` alone says only that something was
// wrong; the description names what, and an earlier version of this code
// discarded it one line after it arrived.
#[test]
fn an_error_body_keeps_both_the_code_and_the_description() {
    let body = br#"{"error":"invalid_request","error_description":"client_secret is missing."}"#;

    assert_eq!(
        parse_token_response(body),
        Err(OidcError::TokenExchangeRefused {
            error: "invalid_request".to_string(),
            description: Some("client_secret is missing.".to_string()),
        })
    );
}

#[test]
fn an_error_body_without_a_description_is_still_an_error() {
    let body = br#"{"error":"invalid_grant"}"#;

    assert_eq!(
        parse_token_response(body),
        Err(OidcError::TokenExchangeRefused {
            error: "invalid_grant".to_string(),
            description: None,
        })
    );
}

#[test]
fn a_description_that_is_not_a_string_counts_as_absent() {
    let body = br#"{"error":"invalid_grant","error_description":42}"#;

    assert_eq!(
        parse_token_response(body),
        Err(OidcError::TokenExchangeRefused {
            error: "invalid_grant".to_string(),
            description: None,
        })
    );
}

// --- Where the provider is told to send the browser ---

// Measured against Google's authorization endpoint on 2026-08-24: a
// loopback redirect is accepted at any port whether it is written as the
// IP literal or as a name, and a non-loopback host is refused. The
// literal is chosen because a name resolves through the host's own
// resolver, which is not this process's decision (RFC 8252 section 7.3).
#[test]
fn the_redirect_uri_names_the_loopback_address_and_not_a_resolvable_host() {
    let uri = callback_redirect_uri(8731);

    assert!(uri.starts_with("http://127.0.0.1:8731/"), "{uri}");
    assert!(!uri.contains("localhost"), "{uri}");
}

#[test]
fn the_redirect_uri_carries_the_port_it_was_given() {
    assert_ne!(callback_redirect_uri(1), callback_redirect_uri(2));
    assert!(callback_redirect_uri(49152).contains(":49152/"));
}

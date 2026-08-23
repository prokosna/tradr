//! Real network fetches, ignored by default so `cargo test` never depends
//! on network access. Run with `cargo test -p tradr-oidc --test
//! live_google -- --ignored`. The second test reaches the one barrier no
//! hermetic test can: a client that trusts a local server's certificate
//! would be a client weakened in production to suit a test.

#[tokio::test]
#[ignore]
async fn google_jwks_is_fetched_as_a_json_object() {
    let body = tradr_oidc::fetch_jwks("https://www.googleapis.com/oauth2/v3/certs")
        .await
        .expect("google's jwks endpoint should be reachable");

    assert!(!body.is_empty());
    let first_non_whitespace = body.iter().find(|&&b| !b.is_ascii_whitespace());
    assert_eq!(first_non_whitespace, Some(&b'{'));
}

/// `https://google.com/` redirects to its `www` host, so this is a real
/// redirect arriving at a client configured to follow none. Coming back
/// `Redirected` instead would mean the client had begun following them
/// and the second barrier caught it, which is worth knowing either way.
#[tokio::test]
#[ignore]
async fn a_redirect_arrives_as_a_status_and_is_refused() {
    let outcome = tradr_oidc::fetch_jwks("https://google.com/").await;

    assert!(
        matches!(
            outcome,
            Err(tradr_oidc::OidcError::UnexpectedStatus(status)) if (300..400).contains(&status)
        ),
        "expected a refused redirect, got {outcome:?}"
    );
}

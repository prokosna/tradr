//! The one experiment that settles whether the desktop client needs its
//! secret. Every probe done without it used a fabricated code, which the
//! token endpoint rejects on parameter validation before any PKCE state
//! could matter. This runs the real flow and then tries the exchange with
//! no `client_secret` at all. Ignored by default; needs a browser.

use std::fs::File;
use std::io::Read;
use std::net::TcpListener;

use tradr_core::{Rng, RngError};
use tradr_oidc::{
    Pkce, authorization_url, callback_redirect_uri, exchange_code, serve_one_callback,
};

const AUTH_URI: &str = "https://accounts.google.com/o/oauth2/auth";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "openid email";

/// The OS source, read directly. No production `Rng` exists yet, and this
/// file is a diagnostic rather than a path any device takes.
struct UrandomRng;

impl Rng for UrandomRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        let mut f = File::open("/dev/urandom").map_err(|e| RngError::Source(Box::new(e)))?;
        f.read_exact(buf).map_err(|e| RngError::Source(Box::new(e)))
    }
}

/// Reads the client from the environment, the way the application does
/// (DCR-028). Nothing ships with these values; a deployer registers their
/// own Google project and exports them.
fn desktop_client() -> Option<(String, String)> {
    let ids = std::env::var("TRADR_OAUTH_CLIENT_IDS")
        .ok()
        .filter(|v| !v.is_empty());
    let secret = std::env::var("TRADR_OAUTH_CLIENT_SECRET")
        .ok()
        .filter(|v| !v.is_empty());
    // The desktop entry is picked out here rather than through
    // `tradr_identity::oauth_client`, which this crate may not depend on.
    let desktop = ids.as_ref().and_then(|list| {
        list.split(',')
            .filter_map(|entry| entry.split_once(':'))
            .find(|(label, _)| label.trim().eq_ignore_ascii_case("desktop"))
            .map(|(_, id)| id.trim().to_string())
    });
    match (desktop, secret) {
        (Some(id), Some(secret)) => Some((id, secret)),
        _ => {
            println!(
                "set TRADR_OAUTH_CLIENT_IDS to desktop:<id>[,android:<id>] and \
                 TRADR_OAUTH_CLIENT_SECRET, both from your own Google Cloud project"
            );
            None
        }
    }
}

#[tokio::test]
#[ignore]
async fn a_pkce_exchange_without_the_client_secret() {
    let Some((client_id, secret)) = desktop_client() else {
        panic!("the client is not configured; see the message above");
    };

    // A fixed port by default, so an ssh forward can be set up before the
    // run rather than raced against it. TRADR_CALLBACK_PORT overrides it,
    // and 0 asks the OS for whatever is free.
    let port: u16 = std::env::var("TRADR_CALLBACK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(45837);
    let listener =
        TcpListener::bind(("127.0.0.1", port)).expect("the callback port is already in use");
    let port = listener.local_addr().expect("the bound address").port();
    let redirect = callback_redirect_uri(port);
    let pkce = Pkce::generate(&UrandomRng).expect("entropy");
    let state = Pkce::generate(&UrandomRng).expect("entropy");

    let url = authorization_url(
        AUTH_URI,
        &client_id,
        &redirect,
        SCOPE,
        "a-nonce-standing-in-for-an-attestation",
        state.verifier(),
        pkce.challenge(),
    )
    .expect("a well-formed authorization url");

    // An authorization code is single use and short lived, so everything
    // needed to retry the exchange by hand is printed before the browser
    // is involved. A verifier is ephemeral and this file is a diagnostic.
    println!("\n=== open this, sign in, and come back ===\n{url}\n");
    println!("redirect_uri  {redirect}");
    println!("code_verifier {}\n", pkce.verifier());

    let code = serve_one_callback(&listener, state.verifier()).expect("a callback carrying a code");
    println!("=== callback received ===");

    let without = exchange_code(
        TOKEN_URI,
        &client_id,
        None,
        &redirect,
        &code,
        pkce.verifier(),
    )
    .await;
    println!("WITHOUT client_secret -> {without:?}");

    match without {
        Ok(_) => println!("\n*** The secret is unnecessary. It comes out of the repository. ***\n"),
        Err(e) => {
            println!("\n*** Refused without the secret: {e} ***");
            // A code is single-use, so this second attempt cannot succeed
            // either. It is here to show which error a spent code gives,
            // so the refusal above is not mistaken for one.
            let with = exchange_code(
                TOKEN_URI,
                &client_id,
                Some(&secret),
                &redirect,
                &code,
                pkce.verifier(),
            )
            .await;
            println!("WITH client_secret, same (now spent) code -> {with:?}\n");
        }
    }
}

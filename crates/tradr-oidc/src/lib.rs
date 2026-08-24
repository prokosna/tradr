#![forbid(unsafe_code)]
//! Fetches a provider's JWKS document over HTTPS. DCR-024 makes this a
//! Critical Module: TLS to the provider's own host is the only thing that
//! makes a key set that provider's, and an attacker whose keys a device
//! fetches passes all seven of docs/05's verification steps with a
//! perfectly valid signature.

//! Also builds the authorization request that starts the desktop OIDC
//! flow, including RFC 7636's PKCE extension: the flow's redirect lands
//! on a loopback port, where any local process that wins the race for it
//! sees the authorization code, and only a code verifier that never left
//! this process can turn that code into a token.

//! WI-M0-008c completes that flow: `parse_callback` and
//! `parse_token_response` are the two pure decisions in it, `serve_one_callback`
//! is the loopback listener that supplies the first, and `exchange_code` is
//! the token endpoint call that supplies the second.

use std::collections::HashSet;
use std::fmt;
use std::io::{BufRead, Read, Write};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tradr_core::Rng;

/// The whole-body cap `BodyAccumulator` enforces. Google's JWKS is a
/// couple of kilobytes; this holds roughly fifty RSA keys.
const BODY_CAP: usize = 64 * 1024;

/// Why a JWKS fetch was refused, or could not complete. `Transport` holds
/// the client's error rendered to a string rather than boxed like
/// `RngError` and `KeyStoreError`: nothing above this crate downcasts a
/// transport failure, it only rejects the token and lets the cache's
/// rate limit decide when to retry, so comparability outweighs that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcError {
    /// The uri's scheme, exactly as the parser resolved it.
    NotHttps(String),
    /// The parser's own reason the uri could not be parsed at all.
    MalformedUri(String),
    /// The text right after `://` did not begin with the host the
    /// parser resolved.
    MisleadingAuthority { resolved: String },
    /// The response status was not exactly `200`.
    UnexpectedStatus(u16),
    /// The body would have exceeded `cap` bytes.
    BodyTooLarge { cap: usize },
    /// The response came back from a uri other than the one requested.
    Redirected { to: String },
    /// The HTTP client itself failed, rendered to a string.
    Transport(String),
    /// A candidate code verifier failed RFC 7636 section 4.1's check:
    /// wrong length, or a character outside `ALPHA / DIGIT / "-" / "." /
    /// "_" / "~"`.
    MalformedVerifier(String),
    /// The `Rng` a generated verifier would draw its entropy from failed.
    /// Not a shape problem like `MalformedVerifier`: the source itself
    /// could not produce bytes, rendered to a string.
    Entropy(String),
    /// The callback's `state` did not equal the one this process expects,
    /// in full. Includes an absent `state` and an empty `expected_state`,
    /// since the latter means this process never started a flow at all.
    StateMismatch,
    /// The callback's query string could not be turned into a code or a
    /// provider error: a repeated parameter name, or neither `code` nor
    /// `error` present with a non-empty value.
    MalformedCallback(String),
    /// The provider's callback carried an `error` parameter, reported only
    /// once `state` was confirmed to belong to this request -- otherwise a
    /// foreign process's failure could end this flow with its own message.
    AuthorizationDenied(String),
    /// The token endpoint's response was not a JSON object carrying a
    /// non-empty string `id_token`. An OAuth response without one is valid
    /// OAuth and useless OIDC, so its absence is an error, not an absence.
    MalformedTokenResponse(String),
    /// The token endpoint reported failure through an `error` member in an
    /// otherwise 200-shaped JSON body. `description` is the `error_description`
    /// member when the provider sent one as a string, `None` otherwise --
    /// its absence is not itself an error.
    TokenExchangeRefused {
        error: String,
        description: Option<String>,
    },
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHttps(scheme) => write!(f, "uri scheme {scheme} is not https"),
            Self::MalformedUri(reason) => write!(f, "malformed uri: {reason}"),
            Self::MisleadingAuthority { resolved } => write!(
                f,
                "text after :// does not begin with the resolved host {resolved}"
            ),
            Self::UnexpectedStatus(status) => write!(f, "unexpected response status {status}"),
            Self::BodyTooLarge { cap } => write!(f, "response body exceeds the {cap}-byte cap"),
            Self::Redirected { to } => write!(f, "response came from {to}, not the requested uri"),
            Self::Transport(reason) => write!(f, "transport error: {reason}"),
            Self::MalformedVerifier(reason) => write!(f, "malformed pkce verifier: {reason}"),
            Self::Entropy(reason) => write!(f, "entropy source failed: {reason}"),
            Self::StateMismatch => write!(f, "callback state does not match the expected state"),
            Self::MalformedCallback(reason) => write!(f, "malformed callback: {reason}"),
            Self::AuthorizationDenied(reason) => {
                write!(f, "authorization denied by the provider: {reason}")
            }
            Self::MalformedTokenResponse(reason) => {
                write!(f, "malformed token response: {reason}")
            }
            Self::TokenExchangeRefused { error, description } => match description {
                Some(description) => {
                    write!(f, "token exchange refused: {error} ({description})")
                }
                None => write!(f, "token exchange refused: {error}"),
            },
        }
    }
}

impl std::error::Error for OidcError {}

/// Rejects any uri that is not https, and any https uri whose authority a
/// reader and the parser would resolve differently. A `jwks_uri` is
/// compiled into a Provider Profile rather than supplied by an attacker,
/// so the two shapes rejected here are typos this project would ship
/// rather than attacks in flight -- see the module doc.
pub fn require_https(uri: &str) -> Result<(), OidcError> {
    let parsed = reqwest::Url::parse(uri).map_err(|e| OidcError::MalformedUri(e.to_string()))?;

    if parsed.scheme() != "https" {
        return Err(OidcError::NotHttps(parsed.scheme().to_string()));
    }

    // Unreachable for a successfully parsed https uri: the parser rejects
    // a special scheme with no host. Errors rather than letting the
    // comparison below become vacuously true.
    let host = parsed
        .host_str()
        .ok_or_else(|| OidcError::MalformedUri("https uri has no host".to_string()))?;

    // The parser's idea of the host is not always a reader's -- an empty
    // authority or an `@` before the real host both parse cleanly while
    // resolving somewhere else. Comparing the raw text after `://`
    // against the resolved host catches both.
    let after_authority_marker = uri
        .find("://")
        .map(|idx| &uri[idx + 3..])
        .ok_or_else(|| OidcError::MalformedUri("uri has no :// separator".to_string()))?;

    if !after_authority_marker
        .to_ascii_lowercase()
        .starts_with(&host.to_ascii_lowercase())
    {
        return Err(OidcError::MisleadingAuthority {
            resolved: host.to_string(),
        });
    }

    Ok(())
}

/// Rejects any response status other than exactly `200`. Not `2xx`: a
/// redirect delivered as a response body is refused here too, behind a
/// client that already follows none.
pub fn require_ok(status: u16) -> Result<(), OidcError> {
    if status == 200 {
        Ok(())
    } else {
        Err(OidcError::UnexpectedStatus(status))
    }
}

/// Rejects a response whose uri differs from the one requested -- a
/// check that does not depend on the client's redirect policy holding,
/// since `require_ok` never sees a redirect the client followed. Both
/// arguments are compared as parsed `Url`s, not strings, so a host
/// gaining its `/`, or a scheme lowercased, is not read as a redirect.
pub fn require_no_redirect(requested: &str, responded: &str) -> Result<(), OidcError> {
    let requested_url =
        reqwest::Url::parse(requested).map_err(|e| OidcError::MalformedUri(e.to_string()))?;
    let responded_url =
        reqwest::Url::parse(responded).map_err(|e| OidcError::MalformedUri(e.to_string()))?;

    if requested_url != responded_url {
        return Err(OidcError::Redirected {
            to: responded.to_string(),
        });
    }

    Ok(())
}

/// Buffers a response body up to `BODY_CAP` bytes, rejecting a chunk that
/// would cross the cap before appending it so a chunk that fails leaves
/// the accumulator exactly as it was.
pub struct BodyAccumulator {
    buf: Vec<u8>,
}

impl BodyAccumulator {
    /// Starts an empty accumulator.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends `chunk`, or rejects it without changing the accumulator if
    /// doing so would cross the cap.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), OidcError> {
        if self.buf.len() + chunk.len() > BODY_CAP {
            return Err(OidcError::BodyTooLarge { cap: BODY_CAP });
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// Consumes the accumulator, returning the bytes collected so far.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for BodyAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Fetches the raw bytes of a provider's JWKS document over HTTPS. Three
/// checks guard the trust root in order: `require_https`, `require_ok`,
/// then `require_no_redirect` as a second barrier behind the client's
/// own `Policy::none()`. Does no caching and no parsing: those are
/// `JwksCache::install` and `parse_jwks` in `tradr-identity`.
pub async fn fetch_jwks(uri: &str) -> Result<Vec<u8>, OidcError> {
    require_https(uri)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    let mut response = client
        .get(uri)
        .send()
        .await
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    require_ok(response.status().as_u16())?;
    require_no_redirect(uri, response.url().as_str())?;

    let mut body = BodyAccumulator::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| OidcError::Transport(e.to_string()))?
    {
        body.push(&chunk)?;
    }

    Ok(body.finish())
}

/// Octets of entropy a generated code verifier draws from `Rng`. RFC 7636
/// section 7.1 recommends 32; base64url-encoded without padding that is exactly
/// 43 characters, the RFC's minimum verifier length.
const GENERATED_VERIFIER_ENTROPY_BYTES: usize = 32;

/// RFC 7636 section 4.1's inclusive bounds on a code verifier's length.
const VERIFIER_MIN_LEN: usize = 43;
const VERIFIER_MAX_LEN: usize = 128;

/// The only code challenge transform this crate produces. RFC 7636 also
/// permits a transform under which the challenge equals the verifier
/// verbatim, so using it would hand the authorization request the very
/// secret PKCE exists to keep out of it; that transform is never wired
/// up here.
const CHALLENGE_METHOD: &str = "S256";

/// An RFC 7636 code verifier, and the S256 challenge derived from it.
/// Both fields are set once, at construction, so a `Pkce` can never hold
/// a verifier that failed the section 4.1 shape check.
pub struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    /// Draws 32 bytes of entropy from `rng` and encodes them as unpadded
    /// base64url to form a verifier, then validates the result through
    /// `from_verifier` rather than trusting the encoding. `rng` failing
    /// is an error: no other source of bytes is substituted.
    pub fn generate(rng: &dyn Rng) -> Result<Self, OidcError> {
        let mut entropy = [0u8; GENERATED_VERIFIER_ENTROPY_BYTES];
        rng.fill_bytes(&mut entropy)
            .map_err(|e| OidcError::Entropy(e.to_string()))?;

        let verifier = URL_SAFE_NO_PAD.encode(entropy);
        Self::from_verifier(&verifier)
    }

    /// Validates `verifier` against RFC 7636 section 4.1 -- length 43 to 128
    /// octets inclusive, drawn only from `ALPHA / DIGIT / "-" / "." /
    /// "_" / "~"` -- and derives its section 4.2 S256 challenge.
    pub fn from_verifier(verifier: &str) -> Result<Self, OidcError> {
        let len = verifier.len();
        if !(VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&len) {
            return Err(OidcError::MalformedVerifier(format!(
                "verifier length {len} is outside the RFC 7636 range {VERIFIER_MIN_LEN}..={VERIFIER_MAX_LEN}"
            )));
        }
        if !verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
        {
            return Err(OidcError::MalformedVerifier(
                "verifier contains a character outside RFC 7636's unreserved set".to_string(),
            ));
        }

        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);

        Ok(Self {
            verifier: verifier.to_string(),
            challenge,
        })
    }

    /// The code verifier this instance holds.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The RFC 7636 section 4.2 S256 challenge derived from the verifier.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// Builds the desktop flow's authorization request: `authorization_uri`
/// with the query parameters OIDC and RFC 7636 require, percent-encoded.
/// Refuses a non-https `authorization_uri` through `require_https`.
/// `nonce` is carried through unaltered -- an Attestation nonce this
/// crate neither computes nor inspects.
pub fn authorization_url(
    authorization_uri: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    nonce: &str,
    state: &str,
    challenge: &str,
) -> Result<String, OidcError> {
    require_https(authorization_uri)?;

    let mut url = reqwest::Url::parse(authorization_uri)
        .map_err(|e| OidcError::MalformedUri(e.to_string()))?;

    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("nonce", nonce)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", CHALLENGE_METHOD);

    Ok(url.to_string())
}

/// A host that no query string parsed here is ever sent to -- it exists
/// only so `reqwest::Url` has an authority to hang a query string off of.
const CALLBACK_QUERY_BASE: &str = "http://callback.invalid/callback?";

/// Reads `query` (tolerating a leading `?`) as the loopback redirect's
/// query string and returns its authorization `code`. In order: a name
/// repeated anywhere is refused outright; `state` must equal
/// `expected_state` in full, empty matching nothing; only then does an
/// `error` parameter become `AuthorizationDenied`. See docs/05.
pub fn parse_callback(query: &str, expected_state: &str) -> Result<String, OidcError> {
    let trimmed = query.strip_prefix('?').unwrap_or(query);
    let url = reqwest::Url::parse(&format!("{CALLBACK_QUERY_BASE}{trimmed}")).map_err(|e| {
        OidcError::MalformedCallback(format!("query string could not be parsed: {e}"))
    })?;

    let mut seen = HashSet::new();
    let mut state: Option<String> = None;
    let mut code: Option<String> = None;
    let mut error: Option<String> = None;

    for (key, value) in url.query_pairs() {
        if !seen.insert(key.to_string()) {
            return Err(OidcError::MalformedCallback(format!(
                "parameter {key} is repeated"
            )));
        }
        match key.as_ref() {
            "state" => state = Some(value.into_owned()),
            "code" => code = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }

    let state_matches = !expected_state.is_empty() && state.as_deref() == Some(expected_state);
    if !state_matches {
        return Err(OidcError::StateMismatch);
    }

    if let Some(error) = error {
        return Err(OidcError::AuthorizationDenied(error));
    }

    match code {
        Some(code) if !code.is_empty() => Ok(code),
        _ => Err(OidcError::MalformedCallback(
            "no non-empty code and no error parameter".to_string(),
        )),
    }
}

/// Parses a token endpoint's response body and returns its `id_token`. An
/// `error` member is reported as `TokenExchangeRefused` with the reason
/// given; otherwise a non-empty string `id_token` is required, since an
/// OAuth response without one is a valid OAuth response and a useless OIDC
/// one -- see the module doc.
pub fn parse_token_response(body: &[u8]) -> Result<String, OidcError> {
    let root: Value = serde_json::from_slice(body)
        .map_err(|e| OidcError::MalformedTokenResponse(format!("body is not valid json: {e}")))?;
    let object = root.as_object().ok_or_else(|| {
        OidcError::MalformedTokenResponse("response is not a json object".to_string())
    })?;

    if let Some(error) = object.get("error").and_then(Value::as_str) {
        let description = object
            .get("error_description")
            .and_then(Value::as_str)
            .map(str::to_string);
        return Err(OidcError::TokenExchangeRefused {
            error: error.to_string(),
            description,
        });
    }

    match object.get("id_token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(OidcError::MalformedTokenResponse(
            "response has no non-empty string id_token".to_string(),
        )),
    }
}

/// Builds the desktop flow's redirect uri for a loopback listener bound to
/// `port`, using the loopback IP literal rather than a resolvable name.
/// RFC 8252 section 7.3 requires this: what such a name resolves to is
/// the host's own resolver configuration, not a decision this process
/// gets to make.
pub fn callback_redirect_uri(port: u16) -> String {
    format!("http://127.0.0.1:{port}/callback")
}

/// How much of an incoming request this reads before giving up -- one
/// request line, never the full request a browser sends, and never
/// unbounded, so a client that keeps sending cannot exhaust memory.
const MAX_REQUEST_LINE_BYTES: u64 = 8 * 1024;

/// How long a connection is given to finish sending its request line. The
/// desktop flow is interactive, so nothing here waits on a client that
/// never finishes.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The page shown once the callback has been read, regardless of what
/// `parse_callback` decided -- the browser has nothing further to do with
/// either a code or an error, so it carries neither.
const CALLBACK_RESPONSE_BODY: &str =
    "<!doctype html><html><body>You can return to the app now.</body></html>";

/// Accepts one connection on `listener`, reads its request line, and runs
/// its query string through `parse_callback` against `expected_state`,
/// writing a short HTML response before returning the result. Binds
/// nothing: the caller binds first, so it knows the port before building
/// the authorization url, and passes the bound listener in here.
pub fn serve_one_callback(
    listener: &std::net::TcpListener,
    expected_state: &str,
) -> Result<String, OidcError> {
    let (stream, _) = listener
        .accept()
        .map_err(|e| OidcError::Transport(e.to_string()))?;
    stream
        .set_read_timeout(Some(CALLBACK_READ_TIMEOUT))
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    let mut request_line = String::new();
    std::io::BufReader::new((&stream).take(MAX_REQUEST_LINE_BYTES))
        .read_line(&mut request_line)
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    let query = request_line
        .split(' ')
        .nth(1)
        .and_then(|target| target.split_once('?'))
        .map(|(_, query)| query)
        .unwrap_or("");

    let result = parse_callback(query, expected_state);

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CALLBACK_RESPONSE_BODY}",
        CALLBACK_RESPONSE_BODY.len()
    );
    (&stream)
        .write_all(response.as_bytes())
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    result
}

/// Exchanges `code` for a token: POSTs the RFC 6749 and RFC 7636 grant
/// parameters, form-encoded, to `token_uri`, and returns
/// `parse_token_response`'s reading of the body. Uses the same hardened
/// client shape as `fetch_jwks` and `require_https`s `token_uri` first.
/// Does not gate on status: a refused exchange's body may arrive non-200.
pub async fn exchange_code(
    token_uri: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<String, OidcError> {
    require_https(token_uri)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }

    let mut response = client
        .post(token_uri)
        .form(&form)
        .send()
        .await
        .map_err(|e| OidcError::Transport(e.to_string()))?;

    let mut body = BodyAccumulator::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| OidcError::Transport(e.to_string()))?
    {
        body.push(&chunk)?;
    }

    parse_token_response(&body.finish())
}

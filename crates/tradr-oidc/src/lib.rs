#![forbid(unsafe_code)]
//! Fetches a provider's JWKS document over HTTPS. DCR-024 makes this a
//! Critical Module: TLS to the provider's own host is the only thing that
//! makes a key set that provider's, and an attacker whose keys a device
//! fetches passes all seven of docs/05's verification steps with a
//! perfectly valid signature.

use std::fmt;
use std::time::Duration;

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

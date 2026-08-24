//! Google's `ProviderProfile`, and the pure function that turns runtime
//! configuration into an `OAuthClient` (docs/05 "OAuth client
//! configuration", DCR-028). No I/O and no environment access: the
//! composition root reads the `TRADR_OAUTH_*` variables and passes the
//! result in, so this module stays testable without a process-global.

use std::fmt;

use crate::attestation::{NonceBinding, ProviderProfile};
use crate::id_token::SignatureAlgorithm;

const ISSUER: &str = "https://accounts.google.com";
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";
const AUTHORIZATION_URI: &str = "https://accounts.google.com/o/oauth2/auth";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Which build this device is. A Desktop client needs a secret; an Android
/// client has none (docs/05, "OAuth client configuration").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Desktop,
    Android,
}

/// This device's configured OAuth client (docs/05, "OAuth client
/// configuration"): which client it authenticates as, and which client ids
/// its own deployment accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub audiences: Vec<String>,
}

/// Why the runtime configuration could not be turned into an `OAuthClient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// `TRADR_OAUTH_CLIENT_ID` was not set. Nothing ships with one.
    MissingClientId,
    /// A Desktop client with no secret. Google's token endpoint requires it.
    MissingClientSecret,
    /// An Android client with a secret. Google issues none for that client
    /// type, so a value here means two clients' settings were pasted
    /// together.
    UnexpectedClientSecret,
    /// This device's own client id is absent from its audience set, which
    /// means every peer, including its own other devices, rejects it.
    ClientIdNotInAudiences,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClientId => write!(f, "TRADR_OAUTH_CLIENT_ID is not set"),
            Self::MissingClientSecret => {
                write!(f, "a desktop client requires TRADR_OAUTH_CLIENT_SECRET")
            }
            Self::UnexpectedClientSecret => {
                write!(f, "an android client must not have a client secret")
            }
            Self::ClientIdNotInAudiences => {
                write!(f, "the client id must appear in TRADR_OAUTH_AUDIENCES")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// Builds this device's `OAuthClient` from runtime configuration, treating
/// an empty string as unset. `audiences` is a comma-separated list; each
/// entry is trimmed, empty entries are dropped, and duplicates are dropped
/// while keeping first-seen order. An absent or empty list defaults to
/// `[client_id]` (docs/05, "OAuth client configuration").
pub fn oauth_client(
    platform: Platform,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    audiences: Option<&str>,
) -> Result<OAuthClient, ProviderError> {
    let client_id = client_id
        .filter(|value| !value.is_empty())
        .ok_or(ProviderError::MissingClientId)?
        .to_string();
    let client_secret = client_secret
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    match platform {
        Platform::Desktop if client_secret.is_none() => {
            return Err(ProviderError::MissingClientSecret);
        }
        Platform::Android if client_secret.is_some() => {
            return Err(ProviderError::UnexpectedClientSecret);
        }
        _ => {}
    }

    let mut parsed: Vec<String> = Vec::new();
    for entry in audiences.unwrap_or("").split(',') {
        let entry = entry.trim();
        if !entry.is_empty() && !parsed.iter().any(|existing| existing == entry) {
            parsed.push(entry.to_string());
        }
    }
    let audiences = if parsed.is_empty() {
        vec![client_id.clone()]
    } else {
        parsed
    };

    if !audiences.contains(&client_id) {
        return Err(ProviderError::ClientIdNotInAudiences);
    }

    Ok(OAuthClient {
        client_id,
        client_secret,
        audiences,
    })
}

/// Google's provider profile built from `client`. The issuer, key set,
/// nonce binding and permitted algorithms are a trust decision compiled in
/// here; only the client itself is configuration (docs/05, "Provider
/// profiles").
pub fn google(client: OAuthClient) -> ProviderProfile {
    ProviderProfile {
        client_id: client.client_id,
        client_secret: client.client_secret,
        authorization_uri: AUTHORIZATION_URI.to_string(),
        token_uri: TOKEN_URI.to_string(),
        issuer: ISSUER.to_string(),
        client_ids: client.audiences,
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
        jwks_uri: JWKS_URI.to_string(),
    }
}

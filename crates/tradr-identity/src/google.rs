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
    /// `TRADR_OAUTH_CLIENT_IDS` was not set, or was empty or whitespace
    /// only. Nothing ships with one.
    MissingClientIds,
    /// An entry in `TRADR_OAUTH_CLIENT_IDS` had no `label:id` shape, or its
    /// id was empty after trimming. Carries the offending entry.
    MalformedClientIds(String),
    /// The same platform label appeared twice in `TRADR_OAUTH_CLIENT_IDS`.
    /// Carries the label, lower-cased.
    DuplicatePlatform(String),
    /// No entry in `TRADR_OAUTH_CLIENT_IDS` named this build's own
    /// platform, so it has no client to authenticate as.
    PlatformNotConfigured,
    /// A Desktop client with no secret. Google's token endpoint requires it.
    MissingClientSecret,
    /// An Android client with a secret. Google issues none for that client
    /// type, so a value here means two clients' settings were pasted
    /// together.
    UnexpectedClientSecret,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClientIds => write!(f, "TRADR_OAUTH_CLIENT_IDS is not set"),
            Self::MalformedClientIds(entry) => {
                write!(
                    f,
                    "'{entry}' is not a label:id entry in TRADR_OAUTH_CLIENT_IDS"
                )
            }
            Self::DuplicatePlatform(label) => {
                write!(f, "'{label}' appears twice in TRADR_OAUTH_CLIENT_IDS")
            }
            Self::PlatformNotConfigured => {
                write!(
                    f,
                    "TRADR_OAUTH_CLIENT_IDS names no client for this platform"
                )
            }
            Self::MissingClientSecret => {
                write!(f, "a desktop client requires TRADR_OAUTH_CLIENT_SECRET")
            }
            Self::UnexpectedClientSecret => {
                write!(f, "an android client must not have a client secret")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

// This build's platform, as the label matched case-insensitively against
// `TRADR_OAUTH_CLIENT_IDS` entries.
fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::Desktop => "desktop",
        Platform::Android => "android",
    }
}

/// One `label:id` entry, already trimmed on both sides.
struct Entry {
    label: String,
    id: String,
}

fn parse_entry(raw: &str) -> Result<Entry, ProviderError> {
    let (label, id) = raw
        .split_once(':')
        .ok_or_else(|| ProviderError::MalformedClientIds(raw.to_string()))?;
    let label = label.trim().to_lowercase();
    let id = id.trim();
    if id.is_empty() {
        return Err(ProviderError::MalformedClientIds(raw.to_string()));
    }
    Ok(Entry {
        label,
        id: id.to_string(),
    })
}

/// Builds this device's `OAuthClient` from runtime configuration
/// (docs/05, "OAuth client configuration"). `client_ids` is the one string
/// shared by every device in the deployment, `label:id` pairs separated by
/// commas; `client_secret` is this platform's own, present only for
/// Desktop.
pub fn oauth_client(
    platform: Platform,
    client_ids: Option<&str>,
    client_secret: Option<&str>,
) -> Result<OAuthClient, ProviderError> {
    let client_ids = client_ids
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ProviderError::MissingClientIds)?;

    let mut entries: Vec<Entry> = Vec::new();
    for raw in client_ids.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        entries.push(parse_entry(raw)?);
    }
    if entries.is_empty() {
        return Err(ProviderError::MissingClientIds);
    }

    let mut seen_labels: Vec<String> = Vec::new();
    let mut audiences: Vec<String> = Vec::new();
    for entry in &entries {
        if seen_labels.contains(&entry.label) {
            return Err(ProviderError::DuplicatePlatform(entry.label.clone()));
        }
        seen_labels.push(entry.label.clone());
        if !audiences.contains(&entry.id) {
            audiences.push(entry.id.clone());
        }
    }

    let label = platform_label(platform);
    let client_id = entries
        .iter()
        .find(|entry| entry.label == label)
        .map(|entry| entry.id.clone())
        .ok_or(ProviderError::PlatformNotConfigured)?;

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

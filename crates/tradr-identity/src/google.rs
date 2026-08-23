//! Google's `ProviderProfile`, and the pure function behind the runtime
//! override (docs/05 "Provider profiles", "OAuth client configuration",
//! DCR-027). No I/O and no environment access: the composition root reads
//! `TRADR_OAUTH_CLIENT_ID` / `TRADR_OAUTH_CLIENT_SECRET` and passes the
//! result in, so this module stays testable without a process-global.

use std::fmt;

use crate::attestation::{NonceBinding, ProviderProfile};
use crate::id_token::SignatureAlgorithm;

const ISSUER: &str = "https://accounts.google.com";
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";
const AUTHORIZATION_URI: &str = "https://accounts.google.com/o/oauth2/auth";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const DESKTOP_CLIENT_ID: &str =
    "475695468283-shsoa7f59bdbta9jlubfs49jonv1m7ng.apps.googleusercontent.com";
const ANDROID_CLIENT_ID: &str =
    "475695468283-v4q25lmqo6kjova3crhiutnl59jnrckk.apps.googleusercontent.com";

/// Not a credential. Google does not treat an installed application's secret
/// as confidential -- it is extractable from any shipped binary -- and PKCE
/// is what protects the flow (docs/05, "OAuth client configuration").
const DESKTOP_CLIENT_SECRET: &str = "REDACTED-SEE-DCR-028-THE-CLIENT-IS-CONFIGURATION";

/// Which build this device is. Selects which of Google's two OAuth clients
/// it authenticates as (docs/05, "Why step 3 compares against a set").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Desktop,
    Android,
}

/// A runtime override of the client this device authenticates as (docs/05,
/// "OAuth client configuration"). Both fields are required together: Google
/// issues no client type that needs one without the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthOverride {
    pub client_id: String,
    pub client_secret: String,
}

/// Why an override could not be built from the two runtime values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// One of `TRADR_OAUTH_CLIENT_ID` / `TRADR_OAUTH_CLIENT_SECRET` was set
    /// and the other was not. Google's token endpoint rejects this pairing
    /// too, but as a failed exchange with nothing in it naming the cause.
    HalfOverridden,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HalfOverridden => {
                write!(f, "client id and client secret must be set together")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// Builds an override from the two runtime values, treating an empty string
/// as unset. Refuses a half-set pair rather than silently authenticating as
/// the default client or as a client with no secret.
pub fn oauth_override(
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> Result<Option<OAuthOverride>, ProviderError> {
    let id = client_id.filter(|value| !value.is_empty());
    let secret = client_secret.filter(|value| !value.is_empty());
    match (id, secret) {
        (None, None) => Ok(None),
        (Some(id), Some(secret)) => Ok(Some(OAuthOverride {
            client_id: id.to_string(),
            client_secret: secret.to_string(),
        })),
        _ => Err(ProviderError::HalfOverridden),
    }
}

/// Google's provider profile for `platform`. `client_ids` always carries
/// both platforms' ids, since a device must accept peers on the other one
/// (docs/05, "Why step 3 compares against a set"). `over`, when present,
/// extends that set and becomes this device's own `client_id` and
/// `client_secret`, changing nothing a peer is verified against.
pub fn google(platform: Platform, over: Option<OAuthOverride>) -> ProviderProfile {
    let mut client_ids = vec![DESKTOP_CLIENT_ID.to_string(), ANDROID_CLIENT_ID.to_string()];
    let (mut client_id, mut client_secret) = match platform {
        Platform::Desktop => (
            DESKTOP_CLIENT_ID.to_string(),
            Some(DESKTOP_CLIENT_SECRET.to_string()),
        ),
        Platform::Android => (ANDROID_CLIENT_ID.to_string(), None),
    };

    if let Some(over) = over {
        if !client_ids.contains(&over.client_id) {
            client_ids.push(over.client_id.clone());
        }
        client_id = over.client_id;
        client_secret = Some(over.client_secret);
    }

    ProviderProfile {
        client_id,
        client_secret,
        authorization_uri: AUTHORIZATION_URI.to_string(),
        token_uri: TOKEN_URI.to_string(),
        issuer: ISSUER.to_string(),
        client_ids,
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
        jwks_uri: JWKS_URI.to_string(),
    }
}

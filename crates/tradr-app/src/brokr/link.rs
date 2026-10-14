use std::fmt;
use std::path::Path;

use tradr_core::SecretStore;

use super::settings::{JoinToken, SettingsError, load_join_token, load_settings};

const PREFIX: &str = "tradr://brokr?";

/// A Brokr address and join token bundled as a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokrLink {
    url: String,
    token: JoinToken,
}

impl BrokrLink {
    /// Creates a new Brokr link from an address and join token.
    pub fn new(url: String, token: JoinToken) -> Self {
        Self { url, token }
    }

    /// The Brokr base address.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The join token required to register with the Brokr.
    pub fn token(&self) -> &JoinToken {
        &self.token
    }

    /// Parses a Brokr link from text.
    pub fn parse(text: &str) -> Result<Self, BrokrLinkError> {
        let trimmed = text.trim();
        if trimmed.contains('#') {
            return Err(BrokrLinkError::NotABrokrLink);
        }
        let Some(prefix) = trimmed.get(..PREFIX.len()) else {
            return Err(BrokrLinkError::NotABrokrLink);
        };
        if !prefix.eq_ignore_ascii_case(PREFIX) {
            return Err(BrokrLinkError::NotABrokrLink);
        }

        let Some(query) = trimmed.get(PREFIX.len()..) else {
            return Err(BrokrLinkError::NotABrokrLink);
        };
        let mut url: Option<String> = None;
        let mut token: Option<String> = None;

        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                "url" => {
                    if url.is_some() {
                        return Err(BrokrLinkError::RepeatedAddress);
                    }
                    url = Some(v.into_owned());
                }
                "token" => {
                    if token.is_some() {
                        return Err(BrokrLinkError::RepeatedToken);
                    }
                    token = Some(v.into_owned());
                }
                _ => {}
            }
        }

        let url = match url {
            Some(u) if !u.is_empty() => u,
            _ => return Err(BrokrLinkError::MissingAddress),
        };

        let token = match token {
            Some(t) if !t.is_empty() => JoinToken::new(t),
            _ => return Err(BrokrLinkError::MissingToken),
        };

        Ok(Self { url, token })
    }

    /// Formats this Brokr link as a URI string.
    pub fn to_link(&self) -> String {
        form_urlencoded::Serializer::for_suffix(String::from(PREFIX), PREFIX.len())
            .append_pair("url", &self.url)
            .append_pair("token", self.token.as_str())
            .finish()
    }
}

/// Why parsing a Brokr link failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokrLinkError {
    /// The text does not start with the required scheme and host.
    NotABrokrLink,
    /// The link query did not provide a non-empty Brokr address.
    MissingAddress,
    /// The link query did not provide a non-empty join token.
    MissingToken,
    /// The link query provided the Brokr address multiple times.
    RepeatedAddress,
    /// The link query provided the join token multiple times.
    RepeatedToken,
}

impl fmt::Display for BrokrLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotABrokrLink => {
                write!(
                    f,
                    "This is not a Brokr link. A Brokr link starts with tradr://brokr?"
                )
            }
            Self::MissingAddress => write!(f, "The link has no Brokr address."),
            Self::MissingToken => write!(f, "The link has no join token."),
            Self::RepeatedAddress => write!(f, "The link gives the Brokr address more than once."),
            Self::RepeatedToken => write!(f, "The link gives the join token more than once."),
        }
    }
}

impl std::error::Error for BrokrLinkError {}

/// Loads the configured Brokr link from settings and secrets, if both are present.
pub fn stored_link(
    dir: &Path,
    store: &dyn SecretStore,
) -> Result<Option<BrokrLink>, SettingsError> {
    let settings = match load_settings(dir)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let token = match load_join_token(store)? {
        Some(t) => t,
        None => return Ok(None),
    };
    Ok(Some(BrokrLink::new(settings.url, token)))
}

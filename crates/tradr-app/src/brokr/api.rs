use std::fmt;
use std::pin::Pin;

use futures_util::Stream;
use tradr_core::{BoxFuture, KeyStoreError};

/// What a Brokr call resolves to.
pub type BrokrFuture<'a, T> = BoxFuture<'a, Result<T, BrokrError>>;

/// A delivery's bytes as the Brokr streams them.
pub type ByteStream<'a> = Pin<Box<dyn Stream<Item = Result<Vec<u8>, BrokrError>> + Send + 'a>>;

/// Why a Brokr call, or a step around one, failed. No variant carries a
/// session token or a join token.
#[derive(Debug)]
pub enum BrokrError {
    /// The Brokr could not be reached, or the connection broke mid-answer.
    Network(String),
    /// The session token was refused; the device registers again.
    Unauthorized,
    /// The Brokr answered with a refusal and its reason.
    Rejected(String),
    /// The Brokr's answer did not have the shape the API promises.
    Malformed(String),
    /// This device's key store could not sign.
    Key(KeyStoreError),
    /// This device's own storage failed, so the delivery stays on the Brokr.
    Local(String),
}

impl fmt::Display for BrokrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(m) => write!(f, "brokr unreachable: {m}"),
            Self::Unauthorized => write!(f, "brokr refused the session"),
            Self::Rejected(m) => write!(f, "brokr refused the request: {m}"),
            Self::Malformed(m) => write!(f, "brokr answered something unexpected: {m}"),
            Self::Key(e) => write!(f, "key store error: {e}"),
            Self::Local(m) => write!(f, "local storage error: {m}"),
        }
    }
}

impl std::error::Error for BrokrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(e) => Some(e),
            _ => None,
        }
    }
}

/// The bearer token a registration answers with. Its `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct Session(String);

impl Session {
    /// Wraps the token a Brokr issued.
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// The token, for the adapter that puts it on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Session(<redacted>)")
    }
}

/// `GET /v1/info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokrInfo {
    /// The API version.
    pub version: u32,
    /// This deployment's salt for `account_tag`, lowercase hex.
    pub account_salt: String,
    /// How long a delivery is held.
    pub delivery_ttl_days: u32,
    /// The largest delivery accepted.
    pub delivery_max_bytes: u64,
    /// The most the Brokr stores in total.
    pub storage_max_bytes: u64,
}

/// `POST /v1/challenge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The nonce to sign, lowercase hex of 32 bytes.
    pub nonce: String,
}

/// `POST /v1/register`, every field lowercase hex except `join_token`.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    /// The registering device's Device ID.
    pub device_id: String,
    /// The device's identity public key, 65 bytes.
    pub identity_pub: String,
    /// The deployment's shared join token.
    pub join_token: String,
    /// `BLAKE3(account_id || account_salt)`.
    pub account_tag: String,
    /// `BLAKE3(link_secret)` for each Link.
    pub link_tags: Vec<String>,
    /// The challenge nonce being answered.
    pub nonce: String,
    /// The signature over `"tradr-brokr-v1" || nonce`, 64 raw bytes `r || s`.
    pub signature: String,
}

impl fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("device_id", &self.device_id)
            .field("link_tags", &self.link_tags.len())
            .finish_non_exhaustive()
    }
}

/// One element of `GET /v1/deliveries/inbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEntry {
    /// The delivery's id.
    pub id: String,
    /// The sender's Device ID as the Brokr recorded it, lowercase hex.
    pub sender_device_id: String,
    /// The delivery's size in bytes.
    pub size: u64,
    /// When it was uploaded, in the Brokr's milliseconds.
    pub uploaded_at: i64,
}

/// A Brokr as the device sees it. An implementation owns the transport, the
/// address and the encoding; nothing of them appears here.
pub trait BrokrApi: Send + Sync {
    /// `GET /v1/info`.
    fn info(&self) -> BrokrFuture<'_, BrokrInfo>;

    /// `POST /v1/challenge`.
    fn challenge(&self) -> BrokrFuture<'_, Challenge>;

    /// `POST /v1/register`, answering the session token.
    fn register(&self, request: RegisterRequest) -> BrokrFuture<'_, Session>;

    /// `GET /v1/deliveries/inbox`.
    fn inbox<'a>(&'a self, session: &'a Session) -> BrokrFuture<'a, Vec<InboxEntry>>;

    /// `GET /v1/deliveries/:id`, as a stream of the body's bytes.
    fn download<'a>(&'a self, session: &'a Session, id: &'a str)
    -> BrokrFuture<'a, ByteStream<'a>>;

    /// `DELETE /v1/deliveries/:id`.
    fn acknowledge<'a>(&'a self, session: &'a Session, id: &'a str) -> BrokrFuture<'a, ()>;
}

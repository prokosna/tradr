//! Runs docs/05's seven steps against a peer's Attestation on a live
//! connection (WI-M6-001). Every call site that used to hand a constant
//! `SameAccount` closure to `perform_handshake`/`listen_for_transfers` now
//! builds one of these and calls `classify` instead. No cryptography of
//! its own: `tradr_identity::verify_attestation` already runs every step.

use std::sync::{Arc, Mutex, MutexGuard};

use tradr_core::{BoxFuture, Clock, DeviceId, PublicKeyPoint, TrustTier};
use tradr_identity::{
    AccountId, AttestationPolicy, JwksCache, LinkPolicy, LinkVerification, Platform,
    ProviderProfile, Verification, google, oauth_client, verify_attestation,
    verify_link_attestation,
};
use tradr_oidc::fetch_jwks;

use crate::attestation::{FUTURE_SKEW_LIMIT_SECS, STALENESS_LIMIT_SECS};
use crate::sign_in::OAuthConfig;

/// Fetches a provider's published JWKS document. Abstracted so tests can
/// count and control outbound requests without reaching a real network
/// (CLAUDE.md section 6: JWKS retrieval is a Critical Module).
pub trait JwksFetch: Send + Sync {
    /// Fetches the document at `jwks_uri`, or the reason it could not be.
    fn fetch<'a>(&'a self, jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>>;
}

/// The production `JwksFetch`: an HTTPS GET via `tradr_oidc::fetch_jwks`,
/// which enforces TLS to the provider's own host.
pub struct HttpsJwksFetch;

impl JwksFetch for HttpsJwksFetch {
    fn fetch<'a>(&'a self, jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move { fetch_jwks(jwks_uri).await.map_err(|e| e.to_string()) })
    }
}

/// What a live connection needs of this device's own Attestation: the
/// `id_token` obtained by sign-in, read fresh for each connection rather
/// than captured once at startup.
pub trait OwnAttestation: Send + Sync {
    /// This device's own `id_token`, or `None` before a sign-in completes.
    fn id_token(&self) -> Option<String>;
}

/// Classifies a peer's Attestation into a `TrustTier`, holding the JWKS
/// cache a connection's fetch warms for the connections after it.
pub struct PeerTrust {
    profile: ProviderProfile,
    fetch: Arc<dyn JwksFetch>,
    cache: Mutex<JwksCache>,
}

impl PeerTrust {
    /// Builds a `PeerTrust` for `profile`, with an empty cache and `fetch`
    /// as its way of warming it.
    pub fn new(profile: ProviderProfile, fetch: Arc<dyn JwksFetch>) -> Self {
        let cache = JwksCache::new(&profile.jwks_uri);
        Self {
            profile,
            fetch,
            cache: Mutex::new(cache),
        }
    }

    // A poisoned mutex still holds a usable cache; recovering it here
    // keeps a panic in one classification from failing every one after it.
    fn lock_cache(&self) -> MutexGuard<'_, JwksCache> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Installs a JWKS document into the cache directly, so sign-in's own
    /// fetch can warm the cache a peer connection will read from.
    pub fn install(&self, document: &[u8]) -> Result<(), String> {
        self.lock_cache()
            .install(document)
            .map_err(|e| e.to_string())
    }

    /// Runs docs/05's seven steps against `token`, presented by a peer
    /// whose channel bound `identity_pub`/`agreement_pub`. Classifies the
    /// token's account against `own_account` and `linked_accounts`, and
    /// fetches a fresh JWKS document at most once when the token names an
    /// unrecognised `kid`.
    pub async fn classify(
        &self,
        token: &str,
        identity_pub: &PublicKeyPoint,
        agreement_pub: &PublicKeyPoint,
        own_account: Option<&AccountId>,
        linked_accounts: &[AccountId],
        clock: &(dyn Clock + Sync),
    ) -> Result<TrustTier, String> {
        // A device with no account of its own has nothing to classify a
        // peer against, and must not be made to fetch on a peer's say-so.
        let own_account = own_account
            .ok_or_else(|| "sign in on this device before classifying a peer".to_string())?;

        let policy = AttestationPolicy {
            profiles: std::slice::from_ref(&self.profile),
            own_account,
            linked_accounts,
            staleness_limit_secs: STALENESS_LIMIT_SECS,
            future_skew_limit_secs: FUTURE_SKEW_LIMIT_SECS,
            ephemeral_receive: false,
        };

        let outcome = {
            let mut cache = self.lock_cache();
            verify_attestation(
                &policy,
                &mut cache,
                token,
                identity_pub,
                agreement_pub,
                clock,
            )
            .map_err(|e| e.to_string())?
        };

        let tier = match outcome {
            Verification::Verified(tier) => tier,
            Verification::JwksNeeded { jwks_uri } => {
                let document = self.fetch.fetch(&jwks_uri).await?;
                let refetched = {
                    let mut cache = self.lock_cache();
                    cache.install(&document).map_err(|e| e.to_string())?;
                    verify_attestation(
                        &policy,
                        &mut cache,
                        token,
                        identity_pub,
                        agreement_pub,
                        clock,
                    )
                    .map_err(|e| e.to_string())?
                };
                match refetched {
                    Verification::Verified(tier) => tier,
                    Verification::JwksNeeded { .. } => {
                        return Err(
                            "the provider's keys changed again right after a fetch; refusing a second one"
                                .to_string(),
                        );
                    }
                }
            }
        };

        Ok(tier)
    }

    /// Runs docs/05's steps 1 to 5 against `token`, joined to `authenticated`
    /// -- the `DeviceId` the channel itself authenticated, never one
    /// recomputed from a message -- and answers with the account rather
    /// than a `TrustTier`: step 6 is inexpressible here, since the account
    /// is what a link exists to admit. Shares `self.cache` with `classify`.
    pub async fn verify_link(
        &self,
        token: &str,
        identity_pub: &PublicKeyPoint,
        agreement_pub: &PublicKeyPoint,
        authenticated: DeviceId,
        clock: &(dyn Clock + Sync),
    ) -> Result<AccountId, String> {
        let policy = LinkPolicy {
            profiles: std::slice::from_ref(&self.profile),
            staleness_limit_secs: STALENESS_LIMIT_SECS,
            future_skew_limit_secs: FUTURE_SKEW_LIMIT_SECS,
        };

        let outcome = {
            let mut cache = self.lock_cache();
            verify_link_attestation(
                &policy,
                &mut cache,
                token,
                identity_pub,
                agreement_pub,
                authenticated,
                clock,
            )
            .map_err(|e| e.to_string())?
        };

        let account = match outcome {
            LinkVerification::Verified(account) => account,
            LinkVerification::JwksNeeded { jwks_uri } => {
                let document = self.fetch.fetch(&jwks_uri).await?;
                let refetched = {
                    let mut cache = self.lock_cache();
                    cache.install(&document).map_err(|e| e.to_string())?;
                    verify_link_attestation(
                        &policy,
                        &mut cache,
                        token,
                        identity_pub,
                        agreement_pub,
                        authenticated,
                        clock,
                    )
                    .map_err(|e| e.to_string())?
                };
                match refetched {
                    LinkVerification::Verified(account) => account,
                    LinkVerification::JwksNeeded { .. } => {
                        return Err(
                            "the provider's keys changed again right after a fetch; refusing a second one"
                                .to_string(),
                        );
                    }
                }
            }
        };

        Ok(account)
    }
}

/// The outcome of building this device's `PeerTrust`, kept as managed
/// state so a clone with no configured OAuth client ids reports the error
/// on first use rather than panicking at startup.
pub struct PeerTrustState(Result<Arc<PeerTrust>, String>);

impl PeerTrustState {
    /// The device's `PeerTrust`, built once at startup.
    pub fn peer_trust(&self) -> Result<Arc<PeerTrust>, String> {
        self.0.clone()
    }
}

// Builds the Google profile the same way attestation.rs already does for
// the paste-a-bundle flow, so a live connection classifies against the
// identical provider set.
fn build_peer_trust(oauth: &OAuthConfig) -> Result<Arc<PeerTrust>, String> {
    let client = oauth_client(Platform::Desktop, oauth.client_ids, oauth.client_secret)
        .map_err(|e| e.to_string())?;
    let profile = google(client);
    Ok(Arc::new(PeerTrust::new(profile, Arc::new(HttpsJwksFetch))))
}

/// Builds the `PeerTrustState` to be managed by the app, from this
/// build's OAuth configuration.
pub(crate) fn init_peer_trust_state(oauth: &OAuthConfig) -> PeerTrustState {
    PeerTrustState(build_peer_trust(oauth))
}

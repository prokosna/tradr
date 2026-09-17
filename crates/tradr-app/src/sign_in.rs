//! Holds the shell-free half of sign-in: everything decided once an ID
//! token is in hand, including JWKS warming, token verification, and
//! account classification. The Android bridge stays in the composition
//! root.

#[cfg(not(target_os = "android"))]
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "android"))]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
#[cfg(not(target_os = "android"))]
use std::thread;
#[cfg(not(target_os = "android"))]
use std::time::Duration;

use serde::Serialize;

#[cfg(not(target_os = "android"))]
use tradr_core::Rng;
use tradr_core::{BoxFuture, Clock, PublicIdentity, TrustTier};
#[cfg(not(target_os = "android"))]
use tradr_identity::OsRng;
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{
    AccountId, AttestationPolicy, LinkRegistry, Platform, ProviderProfile, classify_with_profile,
    google, oauth_client, parse_jwks, verify_id_token,
};
#[cfg(not(target_os = "android"))]
use tradr_oidc::{
    Pkce, authorization_url, callback_redirect_uri, exchange_code, serve_one_callback,
};

use crate::attestation::{FUTURE_SKEW_LIMIT_SECS, STALENESS_LIMIT_SECS};
use crate::peer_trust::{OwnAttestation, PeerTrust};

const ENV_CLIENT_IDS: &str = "TRADR_OAUTH_CLIENT_IDS";
const ENV_CLIENT_SECRET: &str = "TRADR_OAUTH_CLIENT_SECRET";

/// This device's configured OAuth client (DCR-030). Both fields are
/// `None` on a fresh clone: build.rs bakes an empty string when
/// `.tradr-deployment.env` is absent, and the composition root maps that
/// to `None` before managing this.
pub struct OAuthConfig {
    pub client_ids: Option<String>,
    pub client_secret: Option<String>,
}

impl OAuthConfig {
    /// Normalises the OAuth client configuration by trimming whitespace and
    /// mapping empty values to `None`.
    pub fn new(client_ids: Option<String>, client_secret: Option<String>) -> Self {
        let normalize =
            |val: Option<String>| val.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Self {
            client_ids: normalize(client_ids),
            client_secret: normalize(client_secret),
        }
    }

    /// Reads the OAuth client configuration from environment variables.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var(ENV_CLIENT_IDS).ok(),
            std::env::var(ENV_CLIENT_SECRET).ok(),
        )
    }
}

/// Builds this build's `ProviderProfile` from runtime OAuth configuration,
/// selecting the platform at compile time (DCR-116).
pub fn provider_profile(oauth: &OAuthConfig) -> Result<ProviderProfile, String> {
    #[cfg(target_os = "android")]
    let platform = Platform::Android;
    #[cfg(not(target_os = "android"))]
    let platform = Platform::Desktop;

    let client = oauth_client(
        platform,
        oauth.client_ids.as_deref(),
        oauth.client_secret.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    Ok(google(client))
}

/// Which account this device belongs to, once a sign-in completes.
#[derive(Debug, Clone, Serialize)]
pub struct SignInOutcome {
    issuer: String,
    subject: String,
    tier: String,
}

// The outcome plus the id_token that earned it, held together so the two
// can never fall out of sync with each other.
struct SignedIn {
    outcome: SignInOutcome,
    id_token: String,
}

/// The most recently completed sign-in, plus whether one is running right
/// now. Kept as managed state, distinct from `IdentityState`, since both
/// change at runtime while the Device Key does not. Also holds the
/// `id_token` the flow obtained (WI-M0-016): it is this device's own
/// Attestation, and a peer needs it to verify this device.
pub struct SignInState {
    signed_in: Mutex<Option<SignedIn>>,
    in_progress: AtomicBool,
}

/// Marks a sign-in as finished when dropped -- on the success path, on an
/// error `?` returns early on, and on a panic unwind alike -- so a single
/// abandoned attempt can never block every attempt after it.
pub struct InProgressGuard<'a>(&'a AtomicBool);

impl Drop for InProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl SignInState {
    /// Starts idle, with no sign-in on record.
    pub fn empty() -> Self {
        Self {
            signed_in: Mutex::new(None),
            in_progress: AtomicBool::new(false),
        }
    }

    /// Claims the single sign-in slot, or None if one is already running.
    /// compare_exchange makes the check and the set one atomic step, so
    /// two concurrent presses cannot both believe they won it.
    pub fn begin(&self) -> Option<InProgressGuard<'_>> {
        self.in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| InProgressGuard(&self.in_progress))
    }

    fn set_signed_in(&self, outcome: SignInOutcome, id_token: String) {
        *self.recover() = Some(SignedIn { outcome, id_token });
    }

    // A poisoned mutex still holds a usable value; recovering it here
    // keeps a panic in one call from making every later call fail too.
    fn recover(&self) -> std::sync::MutexGuard<'_, Option<SignedIn>> {
        self.signed_in
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The sign-in most recently completed, read by the shell so a
    /// reloaded screen can show it again without repeating the flow.
    pub fn outcome(&self) -> Option<SignInOutcome> {
        self.recover().as_ref().map(|s| s.outcome.clone())
    }

    /// This device's own account, from its own sign-in.
    pub fn own_account(&self) -> Option<AccountId> {
        self.recover()
            .as_ref()
            .map(|s| AccountId::new(&s.outcome.issuer, &s.outcome.subject))
    }

    /// The `id_token` the sign-in flow obtained -- this device's own
    /// Attestation, kept for `crate::attestation::bundle_for` to
    /// hand to a peer.
    pub fn id_token(&self) -> Option<String> {
        self.recover().as_ref().map(|s| s.id_token.clone())
    }
}

impl OwnAttestation for SignInState {
    // Read fresh on every connection (WI-M6-001): a listener started
    // before sign-in must see today's token, not an empty one captured at
    // process start.
    fn id_token(&self) -> Option<String> {
        self.id_token()
    }
}

/// Octets of entropy behind the OAuth `state` parameter, rendered as
/// lowercase hex.
#[cfg(not(target_os = "android"))]
const STATE_ENTROPY_BYTES: usize = 16;

/// How long a sign-in may wait for the browser's callback. Generous for a
/// human signing in, short enough that an attempt someone abandons frees
/// its thread and its port on its own rather than for the life of the
/// process.
#[cfg(not(target_os = "android"))]
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[cfg(not(target_os = "android"))]
// Runs serve_one_callback with a bound on how long it may block: accept()
// has no timeout of its own, so once `timeout` elapses with nobody having
// connected, a second thread wakes it by connecting to the same loopback
// port -- the only way to make an abandoned accept() return at all.
// `timed_out` decides the result below, not that connection's own parse.
fn serve_one_callback_with_timeout(
    listener: TcpListener,
    port: u16,
    expected_state: String,
    timeout: Duration,
) -> Result<String, String> {
    let (finished_tx, finished_rx) = mpsc::channel::<()>();
    let timed_out = Arc::new(AtomicBool::new(false));
    let waker_timed_out = Arc::clone(&timed_out);

    thread::spawn(move || {
        if let Err(mpsc::RecvTimeoutError::Timeout) = finished_rx.recv_timeout(timeout) {
            waker_timed_out.store(true, Ordering::SeqCst);
            if let Err(e) = TcpStream::connect(("127.0.0.1", port)) {
                eprintln!("sign_in: could not wake the abandoned callback listener: {e}");
            }
        }
    });

    let result = serve_one_callback(&listener, &expected_state);
    // Dropping the sender (rather than sending on it) wakes a still-waiting
    // receiver immediately with Disconnected, distinct from its Timeout
    // outcome, so the waker thread never mistakes "we finished" for
    // "nobody came" even when the two race close together.
    drop(finished_tx);

    if timed_out.load(Ordering::SeqCst) {
        return Err("sign-in was not completed in time; try again".to_string());
    }
    result.map_err(|e| e.to_string())
}

/// Returns the ID token obtained from the desktop sign-in flow,
/// blocking on a person to authenticate in the browser.
#[cfg(not(target_os = "android"))]
pub async fn obtain_id_token_desktop(
    profile: &ProviderProfile,
    nonce: &str,
) -> Result<String, String> {
    // Bind before building the url, so the port is known first.
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect_uri = callback_redirect_uri(port);

    let pkce = Pkce::generate(&OsRng).map_err(|e| e.to_string())?;

    let mut state_bytes = [0u8; STATE_ENTROPY_BYTES];
    OsRng
        .fill_bytes(&mut state_bytes)
        .map_err(|e| e.to_string())?;
    let state_value: String = state_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let auth_url = authorization_url(
        &profile.authorization_uri,
        &profile.client_id,
        &redirect_uri,
        "openid email",
        nonce,
        &state_value,
        pkce.challenge(),
    )
    .map_err(|e| e.to_string())?;

    // A browser that fails to open must not leave the person stuck: the
    // url goes into the error text so they can paste it themselves,
    // rather than waiting on a callback nothing will ever reach.
    if let Err(e) = open::that(&auth_url) {
        return Err(format!(
            "could not open a browser automatically ({e}); open this url to continue: {auth_url}"
        ));
    }

    // Blocks on accept, so it must not run on an async runtime worker,
    // and is bounded so a person who changes their mind cannot park it
    // forever.
    let expected_state = state_value.clone();
    let code = tokio::task::spawn_blocking(move || {
        serve_one_callback_with_timeout(listener, port, expected_state, CALLBACK_TIMEOUT)
    })
    .await
    .map_err(|e| e.to_string())??;

    exchange_code(
        &profile.token_uri,
        &profile.client_id,
        profile.client_secret.as_deref(),
        &redirect_uri,
        &code,
        pkce.verifier(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Everything sign-in decides once an ID token is in hand. The JWKS cache
/// it warms is the one a later peer connection reads from rather than a
/// cache of its own.
pub async fn finish_sign_in(
    profile: &ProviderProfile,
    public_identity: &PublicIdentity,
    id_token: String,
    peer_trust: &PeerTrust,
    sign_in_state: &SignInState,
    clock: &(dyn Clock + Sync),
) -> Result<SignInOutcome, String> {
    let jwks_document = peer_trust.warm(&profile.jwks_uri).await?;
    let keys = parse_jwks(&jwks_document).map_err(|e| e.to_string())?;

    let claims = verify_id_token(profile, &keys, &id_token).map_err(|e| e.to_string())?;

    // The moment this device learns which account it belongs to.
    let account = AccountId::new(&claims.iss, &claims.sub);

    // The security checks above -- signature, audience, nonce binding,
    // staleness -- do not depend on own_account at all. Only the tier
    // does, and for our own token the tier is definitionally SameAccount,
    // which is what the check below verifies rather than assumes.
    let policy = AttestationPolicy {
        profiles: std::slice::from_ref(profile),
        own_account: &account,
        linked_accounts: &[],
        staleness_limit_secs: STALENESS_LIMIT_SECS,
        future_skew_limit_secs: FUTURE_SKEW_LIMIT_SECS,
        ephemeral_receive: false,
    };
    let tier = classify_with_profile(
        profile,
        &policy,
        &claims,
        public_identity.identity_pub(),
        public_identity.agreement_pub(),
        clock.now(),
    )
    .map_err(|e| e.to_string())?;

    if tier != TrustTier::SameAccount {
        return Err(format!(
            "token names this device's own account but classified as {tier:?}, not SameAccount"
        ));
    }

    let outcome = SignInOutcome {
        issuer: claims.iss,
        subject: claims.sub,
        tier: format!("{tier:?}"),
    };

    sign_in_state.set_signed_in(outcome.clone(), id_token);

    Ok(outcome)
}

// Builds the closure `perform_handshake` calls once the peer's Hello
// arrives: reads `own_account` fresh at call time and delegates to
// `PeerTrust::classify`. A free function rather than four inlined copies,
// since every call site builds the identical closure over its own
// `trust`/`sign_in` pair.
pub fn peer_verifier(
    trust: Arc<PeerTrust>,
    sign_in: Arc<SignInState>,
    links: Arc<std::sync::Mutex<LinkRegistry>>,
    clock: Arc<dyn Clock + Send + Sync>,
) -> impl FnOnce(AttestationRequest) -> BoxFuture<'static, Result<TrustTier, String>> {
    move |req: AttestationRequest| {
        Box::pin(async move {
            let own_account = sign_in.own_account();
            // Read out and drop the guard before classifying: the registry
            // must never stay locked across `PeerTrust::classify`'s await,
            // and a `std::sync::Mutex` guard held across one is now a
            // compile error rather than a rule to remember.
            let linked_accounts = links
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .linked_accounts();
            trust
                .classify(
                    req.token(),
                    req.identity_pub(),
                    req.agreement_pub(),
                    own_account.as_ref(),
                    &linked_accounts,
                    &*clock,
                )
                .await
        })
    }
}

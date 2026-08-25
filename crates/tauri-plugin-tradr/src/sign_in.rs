//! Joins the sign-in flow WI-M0-008c and WI-M0-011* built but nothing ever
//! called (WI-M0-014b): PKCE, the loopback callback and the token exchange
//! live in `tradr-oidc`; the nonce, the JWKS parse and the token
//! verification live in `tradr-identity`. Writes no cryptography of its own.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use tauri::State;

use tradr_core::{Clock, Rng, TrustTier};
use tradr_identity::{
    AccountId, AttestationPolicy, OsRng, Platform, SystemClock, attestation_nonce,
    classify_with_profile, google, oauth_client, parse_jwks, verify_id_token,
};
use tradr_oidc::{
    Pkce, authorization_url, callback_redirect_uri, exchange_code, fetch_jwks, serve_one_callback,
};

use crate::identity::IdentityState;

/// How old an `id_token`'s `iat` may be before `classify_with_profile`
/// rejects it (docs/05, "Handling expiry").
const STALENESS_LIMIT_SECS: u64 = 30 * 24 * 60 * 60;

/// Octets of entropy behind the OAuth `state` parameter, rendered as
/// lowercase hex.
const STATE_ENTROPY_BYTES: usize = 16;

/// How long a sign-in may wait for the browser's callback. Generous for a
/// human signing in, short enough that an attempt someone abandons frees
/// its thread and its port on its own rather than for the life of the
/// process.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// This device's configured OAuth client (DCR-030). Both fields are
/// `None` on a fresh clone: build.rs bakes an empty string when
/// `.tradr-deployment.env` is absent, and the composition root maps that
/// to `None` before managing this.
pub(crate) struct OAuthConfig {
    pub(crate) client_ids: Option<&'static str>,
    pub(crate) client_secret: Option<&'static str>,
}

/// Which account this device belongs to, once a sign-in completes.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SignInOutcome {
    issuer: String,
    subject: String,
    tier: String,
}

/// The most recently completed sign-in, plus whether one is running right
/// now. Kept as managed state, distinct from `IdentityState`, since both
/// change at runtime while the Device Key does not.
pub(crate) struct SignInState {
    outcome: Mutex<Option<SignInOutcome>>,
    in_progress: AtomicBool,
}

/// Marks a sign-in as finished when dropped -- on the success path, on an
/// error `?` returns early on, and on a panic unwind alike -- so a single
/// abandoned attempt can never block every attempt after it.
struct InProgressGuard<'a>(&'a AtomicBool);

impl Drop for InProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl SignInState {
    /// Starts idle, with no sign-in on record.
    pub(crate) fn empty() -> Self {
        Self {
            outcome: Mutex::new(None),
            in_progress: AtomicBool::new(false),
        }
    }

    // Claims the single sign-in slot, or None if one is already running.
    // compare_exchange makes the check and the set one atomic step, so
    // two concurrent presses cannot both believe they won it.
    fn begin(&self) -> Option<InProgressGuard<'_>> {
        self.in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| InProgressGuard(&self.in_progress))
    }

    fn set_outcome(&self, outcome: SignInOutcome) {
        *self.recover() = Some(outcome);
    }

    // A poisoned mutex still holds a usable value; recovering it here
    // keeps a panic in one call from making every later call fail too.
    fn recover(&self) -> std::sync::MutexGuard<'_, Option<SignInOutcome>> {
        self.outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Returns the most recently completed sign-in, so the screen can show it
/// again after a reload without repeating the flow.
#[tauri::command]
pub fn sign_in_status(state: State<'_, SignInState>) -> Option<SignInOutcome> {
    state.recover().clone()
}

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

/// Runs the desktop sign-in flow end to end and classifies the result.
/// Errors on anything but `TrustTier::SameAccount`: a token naming this
/// device's own account classifying otherwise means the nonce binding or
/// the audience check did not do what docs/05 says.
#[tauri::command]
pub async fn sign_in(
    identity_state: State<'_, IdentityState>,
    oauth: State<'_, OAuthConfig>,
    sign_in_state: State<'_, SignInState>,
) -> Result<SignInOutcome, String> {
    let _guard = sign_in_state
        .begin()
        .ok_or_else(|| "a sign-in is already in progress".to_string())?;

    let client = oauth_client(Platform::Desktop, oauth.client_ids, oauth.client_secret)
        .map_err(|e| e.to_string())?;
    let profile = google(client);

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

    let public_identity = identity_state.public_identity()?;
    let nonce = attestation_nonce(profile.nonce_binding, &public_identity);

    let auth_url = authorization_url(
        &profile.authorization_uri,
        &profile.client_id,
        &redirect_uri,
        "openid email",
        &nonce,
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
    let code = tauri::async_runtime::spawn_blocking(move || {
        serve_one_callback_with_timeout(listener, port, expected_state, CALLBACK_TIMEOUT)
    })
    .await
    .map_err(|e| e.to_string())??;

    let id_token = exchange_code(
        &profile.token_uri,
        &profile.client_id,
        profile.client_secret.as_deref(),
        &redirect_uri,
        &code,
        pkce.verifier(),
    )
    .await
    .map_err(|e| e.to_string())?;

    let jwks_document = fetch_jwks(&profile.jwks_uri)
        .await
        .map_err(|e| e.to_string())?;
    let keys = parse_jwks(&jwks_document).map_err(|e| e.to_string())?;

    let claims = verify_id_token(&profile, &keys, &id_token).map_err(|e| e.to_string())?;

    // The moment this device learns which account it belongs to.
    let account = AccountId::new(&claims.iss, &claims.sub);

    // The security checks above -- signature, audience, nonce binding,
    // staleness -- do not depend on own_account at all. Only the tier
    // does, and for our own token the tier is definitionally SameAccount,
    // which is what the check below verifies rather than assumes.
    let policy = AttestationPolicy {
        profiles: std::slice::from_ref(&profile),
        own_account: &account,
        linked_accounts: &[],
        staleness_limit_secs: STALENESS_LIMIT_SECS,
        ephemeral_receive: false,
    };
    let tier = classify_with_profile(
        &profile,
        &policy,
        &claims,
        public_identity.identity_pub(),
        public_identity.agreement_pub(),
        SystemClock.now(),
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

    sign_in_state.set_outcome(outcome.clone());

    Ok(outcome)
}

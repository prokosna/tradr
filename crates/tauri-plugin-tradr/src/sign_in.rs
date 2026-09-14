//! Owns the shell-specific halves of the sign-in flow: the browser, the
//! loopback callback, and the Android bridge. Everything a token means
//! once obtained lives in `tradr_app::sign_in`.

#[cfg(not(target_os = "android"))]
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
#[cfg(not(target_os = "android"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "android"))]
use std::sync::mpsc;
#[cfg(not(target_os = "android"))]
use std::thread;
#[cfg(not(target_os = "android"))]
use std::time::Duration;

use tauri::State;

use tradr_app::sign_in::{
    OAuthConfig, SignInOutcome, SignInState, finish_sign_in, provider_profile,
};
#[cfg(not(target_os = "android"))]
use tradr_core::Rng;
#[cfg(not(target_os = "android"))]
use tradr_identity::OsRng;
use tradr_identity::{ProviderProfile, SystemClock, attestation_nonce};
#[cfg(not(target_os = "android"))]
use tradr_oidc::{
    Pkce, authorization_url, callback_redirect_uri, exchange_code, serve_one_callback,
};

use crate::identity::IdentityState;
use crate::peer_trust::PeerTrustState;

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

/// Returns the most recently completed sign-in, so the screen can show it
/// again after a reload without repeating the flow.
#[tauri::command]
pub fn sign_in_status(state: State<'_, Arc<SignInState>>) -> Option<SignInOutcome> {
    state.outcome()
}

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

#[cfg(not(target_os = "android"))]
async fn obtain_id_token_desktop(profile: &ProviderProfile, nonce: &str) -> Result<String, String> {
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
    let code = tauri::async_runtime::spawn_blocking(move || {
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

#[cfg(target_os = "android")]
async fn obtain_id_token_android<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    profile: &ProviderProfile,
    nonce: &str,
) -> Result<String, String> {
    use tauri::Manager;
    let handle_state = app
        .try_state::<crate::android::AndroidPluginHandle<R>>()
        .ok_or_else(|| "android plugin handle not found".to_string())?;
    crate::android::sign_in(&handle_state.0, &profile.client_id, nonce).await
}

/// Runs the sign-in flow end to end and classifies the result.
/// Errors on anything but `TrustTier::SameAccount`: a token naming this
/// device's own account classifying otherwise means the nonce binding or
/// the audience check did not do what docs/05 says.
#[tauri::command]
pub async fn sign_in<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    identity_state: State<'_, IdentityState>,
    oauth: State<'_, OAuthConfig>,
    sign_in_state: State<'_, Arc<SignInState>>,
    peer_trust_state: State<'_, PeerTrustState>,
) -> Result<SignInOutcome, String> {
    let _guard = sign_in_state
        .begin()
        .ok_or_else(|| "a sign-in is already in progress".to_string())?;

    let profile = provider_profile(&oauth)?;

    let public_identity = identity_state.public_identity()?;

    let nonce = attestation_nonce(profile.nonce_binding, &public_identity);

    #[cfg(not(target_os = "android"))]
    let id_token = obtain_id_token_desktop(&profile, &nonce).await?;

    #[cfg(target_os = "android")]
    let id_token = obtain_id_token_android(&app, &profile, &nonce).await?;

    let peer_trust = peer_trust_state.peer_trust()?;
    finish_sign_in(
        &profile,
        &public_identity,
        id_token,
        &peer_trust,
        &sign_in_state,
        &SystemClock,
    )
    .await
}

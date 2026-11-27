//! Owns the shell-specific half of the sign-in flow: the Android bridge.
//! Everything a token means once obtained lives in `tradr_app::sign_in`.

use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager, State};

use tradr_app::kept_sign_in::{keep_token, load_kept_token, renewal_due};
use tradr_app::paths::attestation_path;
use tradr_app::peer_trust::PeerTrust;
use tradr_app::sign_in::{
    OAuthConfig, SignInOutcome, SignInState, finish_renewal, finish_sign_in, provider_profile,
    resume_sign_in,
};
#[cfg(not(target_os = "android"))]
use tradr_app::sign_in::{obtain_id_token_desktop, renew_id_token_desktop};
use tradr_core::{Clock, PublicIdentity};
use tradr_identity::ProviderProfile;
use tradr_identity::{SystemClock, attestation_nonce};

use crate::identity::IdentityState;
use crate::peer_trust::PeerTrustState;

/// Returns the most recently completed sign-in, so the screen can show it
/// again after a reload without repeating the flow.
#[tauri::command]
pub fn sign_in_status(state: State<'_, Arc<SignInState>>) -> Option<SignInOutcome> {
    state.outcome()
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
    app: tauri::AppHandle<R>,
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
    let id_token = obtain_id_token_desktop(&profile, &nonce, None).await?;

    #[cfg(target_os = "android")]
    let id_token = obtain_id_token_android(&app, &profile, &nonce).await?;

    let peer_trust = peer_trust_state.peer_trust()?;
    let outcome = finish_sign_in(
        &profile,
        &public_identity,
        id_token.clone(),
        &peer_trust,
        &sign_in_state,
        &SystemClock,
    )
    .await?;

    let keep_result = crate::paths::app_data_dir(&app)
        .and_then(|dir| keep_token(&attestation_path(&dir), &id_token));
    if let Err(e) = keep_result {
        eprintln!("sign_in: could not keep the sign-in: {e}");
    }

    Ok(outcome)
}

pub(crate) async fn resume_kept_sign_in<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    sign_in_state: Arc<SignInState>,
    public_identity: Result<PublicIdentity, String>,
    profile: Result<ProviderProfile, String>,
    peer_trust: Result<Arc<PeerTrust>, String>,
) {
    let _guard = match sign_in_state.begin() {
        Some(guard) => guard,
        None => return,
    };

    let dir = match crate::paths::app_data_dir(&app) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("sign_in: kept sign-in not used: {e}");
            return;
        }
    };
    let path = attestation_path(&dir);
    let id_token = match load_kept_token(&path) {
        Ok(Some(token)) => token,
        Ok(None) => return,
        Err(e) => {
            eprintln!("sign_in: kept sign-in not used: {e}");
            return;
        }
    };

    let profile = match profile {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sign_in: kept sign-in not used: {e}");
            return;
        }
    };
    let public_identity = match public_identity {
        Ok(id) => id,
        Err(e) => {
            eprintln!("sign_in: kept sign-in not used: {e}");
            return;
        }
    };
    let peer_trust = match peer_trust {
        Ok(trust) => trust,
        Err(e) => {
            eprintln!("sign_in: kept sign-in not used: {e}");
            return;
        }
    };

    match resume_sign_in(
        &profile,
        &public_identity,
        id_token,
        &peer_trust,
        &sign_in_state,
        &SystemClock,
    )
    .await
    {
        Ok(outcome) => {
            if let Err(e) = app.emit("sign-in-restored", &outcome) {
                eprintln!("sign_in: emit sign-in-restored failed: {e}");
            }
        }
        Err(e) => {
            eprintln!("sign_in: kept sign-in not used: {e}");
        }
    }
}

/// How often the running app checks whether the kept sign-in is due for renewal.
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Renews the kept sign-in quietly while the app runs: once now, then every
/// six hours. Attempts run one after another, so a failed one is not retried
/// before the next tick.
pub(crate) async fn keep_sign_in_fresh<R: tauri::Runtime>(app: tauri::AppHandle<R>) {
    let mut ticker = tokio::time::interval(RENEWAL_CHECK_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(e) = renew_if_due(&app).await {
            eprintln!("sign_in: renewal not done, keeping the current sign-in: {e}");
        }
    }
}

#[cfg(not(target_os = "android"))]
async fn obtain_renewed_token<R: tauri::Runtime>(
    _app: &tauri::AppHandle<R>,
    profile: &ProviderProfile,
    nonce: &str,
    login_hint: &str,
) -> Result<String, String> {
    renew_id_token_desktop(profile, nonce, login_hint).await
}

#[cfg(target_os = "android")]
async fn obtain_renewed_token<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    profile: &ProviderProfile,
    nonce: &str,
    _login_hint: &str,
) -> Result<String, String> {
    let handle_state = app
        .try_state::<crate::android::AndroidPluginHandle<R>>()
        .ok_or_else(|| "android plugin handle not found".to_string())?;
    crate::android::silent_sign_in(&handle_state.0, &profile.client_id, nonce).await
}

async fn renew_if_due<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<(), String> {
    let sign_in_state = app.state::<Arc<SignInState>>();
    let Some(_guard) = sign_in_state.begin() else {
        return Ok(());
    };
    let (Some(iat), Some(account)) = (sign_in_state.iat(), sign_in_state.own_account()) else {
        return Ok(());
    };
    if !renewal_due(iat, SystemClock.now()) {
        return Ok(());
    }

    let profile = provider_profile(&app.state::<OAuthConfig>())?;
    let public_identity = app.state::<IdentityState>().public_identity()?;
    let nonce = attestation_nonce(profile.nonce_binding, &public_identity);

    let id_token = obtain_renewed_token(app, &profile, &nonce, account.sub()).await?;

    let peer_trust = app.state::<PeerTrustState>().peer_trust()?;
    finish_renewal(
        &profile,
        &public_identity,
        id_token.clone(),
        &peer_trust,
        &sign_in_state,
        &account,
        &SystemClock,
    )
    .await?;

    let dir = crate::paths::app_data_dir(app)?;
    keep_token(&attestation_path(&dir), &id_token)
}

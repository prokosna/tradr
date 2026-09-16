//! Owns the shell-specific half of the sign-in flow: the Android bridge.
//! Everything a token means once obtained lives in `tradr_app::sign_in`.

use std::sync::Arc;

use tauri::State;

#[cfg(not(target_os = "android"))]
use tradr_app::sign_in::obtain_id_token_desktop;
use tradr_app::sign_in::{
    OAuthConfig, SignInOutcome, SignInState, finish_sign_in, provider_profile,
};
#[cfg(target_os = "android")]
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

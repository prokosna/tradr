//! Shell binding for the paste-a-bundle Attestation exchange. The work
//! lives in `tradr_app::attestation`; what is left here is the `State`
//! resolution a shell does, which is the split WI-M8-002 exists to make.

use std::sync::Arc;

use tauri::State;

use tradr_app::attestation::{AttestationBundle, VerifiedPeer, bundle_for, verify_peer_bundle};
use tradr_app::sign_in::{OAuthConfig, SignInState, provider_profile};

use crate::identity::IdentityState;
use crate::link_registry::LinkRegistryState;

/// Returns what a peer needs to verify this device: the `id_token` this
/// device's own sign-in obtained, and its two public keys as lowercase
/// hex. Errors when no sign-in has completed, since there is no
/// `id_token` to hand over before then.
#[tauri::command]
pub fn attestation_bundle(
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
) -> Result<AttestationBundle, String> {
    let id_token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in before showing this device's Attestation".to_string())?;
    let identity = identity_state.public_identity()?;

    Ok(bundle_for(&identity, id_token))
}

/// Parses a peer's pasted Attestation bundle and runs docs/05's seven
/// steps against it, fetching a `JwksNeeded` uri at most once. Requires a
/// completed sign-in of this device's own, since classifying a peer's
/// account needs one to classify against.
#[tauri::command]
pub async fn verify_peer_attestation(
    bundle: String,
    oauth: State<'_, OAuthConfig>,
    sign_in_state: State<'_, Arc<SignInState>>,
    link_registry: State<'_, LinkRegistryState>,
) -> Result<VerifiedPeer, String> {
    let own_account = sign_in_state
        .own_account()
        .ok_or_else(|| "sign in on this device before verifying a peer".to_string())?;
    let linked_accounts = link_registry.linked_accounts()?;
    let profile = provider_profile(&oauth)?;

    verify_peer_bundle(&bundle, &profile, &own_account, &linked_accounts).await
}

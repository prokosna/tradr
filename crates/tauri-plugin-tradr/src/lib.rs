#![forbid(unsafe_code)]
//! Composition root: binds the other crates to tradr-core's traits; hosts the Kotlin glue.
//!
//! WI-M0-005 and WI-M0-005b also live here: both of ADR-0001's call directions,
//! plus the ACTION_SEND intent channel, run once from this plugin's setup hook,
//! so the evidence needs no interaction with the frontend.

use std::sync::Arc;

use tauri::{
    Manager, Runtime,
    plugin::{Builder, TauriPlugin},
};

#[cfg(target_os = "android")]
mod android;
mod attestation;
pub mod commands;
pub mod desktop;
pub mod handshake;
mod identity;
pub mod lifecycle;
pub mod link_exchange;
pub mod listener;
#[cfg(target_os = "android")]
pub mod mobile;
pub mod peer_trust;
pub mod share;
mod sign_in;
pub mod transfer;

use sign_in::{OAuthConfig, SignInState};

/// Builds the plugin. Its setup hook opens the Device Key store once and
/// manages `client_ids`/`client_secret`, this build's OAuth configuration
/// (DCR-030) -- `None` in either means a fresh clone. On Android it also
/// demonstrates both ADR-0001 call directions with Kotlin; on every other
/// target that part is a no-op, since there is no Kotlin side to call into.
pub fn init<R: Runtime>(
    client_ids: Option<&'static str>,
    client_secret: Option<&'static str>,
) -> TauriPlugin<R> {
    Builder::new("tradr")
        .invoke_handler(tauri::generate_handler![
            identity::device_identity,
            sign_in::sign_in,
            sign_in::sign_in_status,
            attestation::attestation_bundle,
            attestation::verify_peer_attestation,
            commands::get_peers,
            commands::get_visible_shares,
            commands::list_peer_directory,
            commands::download_file,
            commands::send_files,
            commands::add_static_peer,
            commands::remove_static_peer,
            commands::list_static_peers,
            commands::publish_sharing_shortcuts,
            commands::pick_share_root,
            commands::request_permissions,
            commands::check_permissions,
            commands::show_incoming_transfer_notification,
        ])
        .setup(move |app, _api| {
            let identity_state = identity::init_identity_state(app);
            let sign_in_state = Arc::new(SignInState::empty());
            let oauth_config = OAuthConfig {
                client_ids,
                client_secret,
            };
            let peer_trust_state = peer_trust::init_peer_trust_state(&oauth_config);

            lifecycle::init_lifecycle(
                app,
                &identity_state,
                sign_in_state.clone(),
                &peer_trust_state,
            )?;

            app.manage(identity_state);
            app.manage(oauth_config);
            app.manage(sign_in_state);
            app.manage(peer_trust_state);

            #[cfg(target_os = "android")]
            {
                let handle = android::demonstrate_bidirectional_calls(_api)?;
                app.manage(android::AndroidPluginHandle(handle));
            }
            Ok(())
        })
        .build()
}

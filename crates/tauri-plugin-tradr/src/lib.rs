#![forbid(unsafe_code)]
//! Composition root: binds the other crates to tradr-core's traits; hosts the Kotlin glue.
//!
//! WI-M0-005 and WI-M0-005b also live here: both of ADR-0001's call directions,
//! plus the ACTION_SEND intent channel, run once from this plugin's setup hook,
//! so the evidence needs no interaction with the frontend.

use tauri::{
    Manager, Runtime,
    plugin::{Builder, TauriPlugin},
};

#[cfg(target_os = "android")]
mod android;
mod attestation;
mod identity;
mod sign_in;

use sign_in::OAuthConfig;

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
        ])
        .setup(move |app, _api| {
            let state = identity::init_identity_state(app);
            app.manage(state);
            app.manage(OAuthConfig {
                client_ids,
                client_secret,
            });
            app.manage(sign_in::SignInState::empty());

            #[cfg(target_os = "android")]
            android::demonstrate_bidirectional_calls(_api)?;
            Ok(())
        })
        .build()
}

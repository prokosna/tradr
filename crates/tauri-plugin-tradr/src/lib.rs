#![deny(unsafe_code)]
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
#[cfg(target_os = "android")]
mod android_fd;
mod attestation;
pub mod brokr_commands;
pub mod commands;
pub mod desktop;
mod identity;
pub mod lifecycle;
pub mod link_commands;
pub mod link_registry;
#[cfg(target_os = "android")]
pub mod mobile;
pub mod own_name;
mod paths;
pub mod peer_trust;
pub mod receive_folder;
pub mod received;
pub mod received_actions;
mod sign_in;

use own_name::OwnDisplayName;
use tradr_app::sign_in::{OAuthConfig, SignInState, provider_profile};

/// Builds the plugin. Its setup hook opens the Device Key store once and
/// manages `client_ids`/`client_secret`, this build's OAuth configuration
/// -- `None` in either means a fresh clone. On Android it also
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
            sign_in::confirm_account_switch,
            sign_in::cancel_account_switch,
            attestation::attestation_bundle,
            attestation::verify_peer_attestation,
            commands::get_peers,
            commands::refresh_peers,
            commands::get_visible_shares,
            commands::list_peer_directory,
            commands::download_file,
            commands::upload_to_peer,
            commands::make_peer_directory,
            commands::delete_peer_entry,
            commands::rename_peer_entry,
            commands::send_files,
            commands::add_static_peer,
            commands::remove_static_peer,
            commands::list_static_peers,
            commands::publish_sharing_shortcuts,
            commands::pick_share_root,
            commands::pick_files_to_send,
            commands::request_permissions,
            commands::check_permissions,
            commands::receive_service_status,
            commands::show_incoming_transfer_notification,
            link_commands::open_link_invite,
            link_commands::reply_to_link_invite,
            link_commands::approve_link,
            link_commands::decline_link,
            link_commands::preview_link_invite,
            link_commands::pending_link_proposal,
            link_commands::list_links,
            link_commands::remove_link,
            link_commands::set_link_full_access,
            receive_folder::receive_folder,
            received::received_history,
            received::clear_received_history,
            received_actions::received_actions,
            received_actions::open_received,
            received_actions::reveal_received,
            received_actions::share_received,
            brokr_commands::set_brokr,
            brokr_commands::brokr_status,
            brokr_commands::collect_brokr_now,
            brokr_commands::clear_brokr,
            brokr_commands::connect_brokr_link,
            brokr_commands::brokr_link,
            brokr_commands::list_known_devices,
            brokr_commands::forget_known_device,
            brokr_commands::send_deferred,
            brokr_commands::list_deliveries,
        ])
        .setup(move |app, _api| {
            #[cfg(target_os = "android")]
            let adopted = Arc::new(tradr_app::adopted::AdoptedFiles::new());
            #[cfg(target_os = "android")]
            app.manage(adopted.clone());
            #[cfg(target_os = "android")]
            let handle = android::demonstrate_bidirectional_calls(_api, adopted)?;

            let identity_state = identity::init_identity_state(app);
            let sign_in_state = Arc::new(SignInState::empty());
            let oauth_config = OAuthConfig::new(
                client_ids.map(str::to_string),
                client_secret.map(str::to_string),
            );
            let peer_trust_state = peer_trust::init_peer_trust_state(&oauth_config);
            let link_registry_state = link_registry::init_link_registry_state(app);
            let link_invite_state = Arc::new(tradr_app::link_invite::LinkInviteState::new());

            #[cfg(target_os = "android")]
            let own_display_name = match android::device_name(&handle) {
                Ok(raw) => tradr_app::network::display_name_from_device_name(&raw),
                Err(e) => {
                    eprintln!("failed to get device name from android: {e}");
                    None
                }
            };
            #[cfg(not(target_os = "android"))]
            let own_display_name = tradr_app::network::local_display_name();

            lifecycle::init_lifecycle(
                app,
                &identity_state,
                sign_in_state.clone(),
                &peer_trust_state,
                &link_registry_state,
                link_invite_state.clone(),
                own_display_name.clone(),
            )?;

            let public_identity = identity_state.public_identity();
            let profile = provider_profile(&oauth_config);
            let peer_trust = peer_trust_state.peer_trust();
            let sign_in_for_resume = sign_in_state.clone();
            let app_handle = app.clone();
            let app_for_renewal = app.clone();

            app.manage(identity_state);
            app.manage(oauth_config);
            app.manage(sign_in_state);
            app.manage(peer_trust_state);
            app.manage(link_registry_state);
            app.manage(link_invite_state);
            app.manage(Arc::new(tradr_app::account_switch::PendingSwitch::default()));
            app.manage(OwnDisplayName(own_display_name));

            tauri::async_runtime::spawn(async move {
                sign_in::resume_kept_sign_in(
                    app_handle,
                    sign_in_for_resume,
                    public_identity,
                    profile,
                    peer_trust,
                )
                .await;
                sign_in::keep_sign_in_fresh(app_for_renewal).await;
            });

            #[cfg(target_os = "android")]
            {
                app.manage(android::AndroidPluginHandle(handle));
            }
            Ok(())
        })
        .build()
}

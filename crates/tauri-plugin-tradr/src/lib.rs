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
pub mod ble_advertising;
pub mod ble_android;
pub mod ble_gatt_android;
pub mod ble_source;
pub mod commands;
pub mod desktop;
mod identity;
pub mod lifecycle;
pub mod link_commands;
pub mod link_registry;
#[cfg(target_os = "android")]
pub mod mobile;
mod paths;
pub mod peer_trust;
mod sign_in;

use tradr_app::sign_in::{OAuthConfig, SignInState, provider_profile};

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
            commands::pick_files_to_send,
            commands::request_permissions,
            commands::check_permissions,
            commands::show_incoming_transfer_notification,
            link_commands::open_link_invite,
            link_commands::reply_to_link_invite,
            link_commands::approve_link,
            link_commands::decline_link,
            link_commands::preview_link_invite,
            link_commands::pending_link_proposal,
            link_commands::list_links,
            link_commands::remove_link,
        ])
        .setup(move |app, _api| {
            let identity_state = identity::init_identity_state(app);
            let sign_in_state = Arc::new(SignInState::empty());
            let oauth_config = OAuthConfig::new(
                client_ids.map(str::to_string),
                client_secret.map(str::to_string),
            );
            let peer_trust_state = peer_trust::init_peer_trust_state(&oauth_config);
            let link_registry_state = link_registry::init_link_registry_state(app);
            let link_invite_state = Arc::new(tradr_app::link_invite::LinkInviteState::new());

            let (_listener, ble_discovery, ble_advertising) = match lifecycle::init_lifecycle(
                app,
                &identity_state,
                sign_in_state.clone(),
                &peer_trust_state,
                &link_registry_state,
                link_invite_state.clone(),
            )? {
                Some(handles) => (Some(handles.listener), handles.ble, handles.ble_advertising),
                None => (None, None, None),
            };

            let public_identity = identity_state.public_identity();
            let profile = provider_profile(&oauth_config);
            let peer_trust = peer_trust_state.peer_trust();
            let sign_in_for_resume = sign_in_state.clone();
            let app_handle = app.clone();

            app.manage(identity_state);
            app.manage(oauth_config);
            app.manage(sign_in_state);
            app.manage(peer_trust_state);
            app.manage(link_registry_state);
            app.manage(link_invite_state);

            tauri::async_runtime::spawn(sign_in::resume_kept_sign_in(
                app_handle,
                sign_in_for_resume,
                public_identity,
                profile,
                peer_trust,
            ));

            #[cfg(target_os = "linux")]
            if let Some(discovery) = ble_discovery {
                ble_source::spawn_ble_discovery(
                    discovery,
                    Box::pin(async {
                        tradr_discovery::BluerScanner::new()
                            .await
                            .map(|s| Box::new(s) as Box<dyn tradr_discovery::BleScanner>)
                    }),
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(advertising) = ble_advertising {
                ble_advertising::spawn_ble_advertising(
                    advertising,
                    Box::pin(async {
                        tradr_discovery::BluerAdvertiser::new()
                            .await
                            .map(|a| Box::new(a) as Box<dyn tradr_discovery::BleAdvertiser>)
                    }),
                );
            }

            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            if let Some(discovery) = ble_discovery {
                ble_source::spawn_ble_discovery(
                    discovery,
                    Box::pin(async { Err(tradr_discovery::BleError::Unsupported) }),
                );
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            if let Some(advertising) = ble_advertising {
                ble_advertising::spawn_ble_advertising(
                    advertising,
                    Box::pin(async { Err(tradr_discovery::BleError::Unsupported) }),
                );
            }

            #[cfg(target_os = "android")]
            {
                let handle = android::demonstrate_bidirectional_calls(_api)?;
                if let Some(discovery) = ble_discovery {
                    let handle_for_scan = handle.clone();
                    ble_source::spawn_ble_discovery(
                        discovery,
                        Box::pin(async move {
                            ble_android::AndroidBleScanner::new(handle_for_scan, false)
                                .await
                                .map(|s| Box::new(s) as Box<dyn tradr_discovery::BleScanner>)
                        }),
                    );
                }
                if let Some(advertising) = ble_advertising {
                    let handle_for_adv = handle.clone();
                    ble_advertising::spawn_ble_advertising(
                        advertising,
                        Box::pin(async move {
                            Ok(
                                Box::new(ble_android::AndroidBleAdvertiser::new(handle_for_adv))
                                    as Box<dyn tradr_discovery::BleAdvertiser>,
                            )
                        }),
                    );
                }
                if let Some(listener) = _listener {
                    lifecycle::spawn_ble_gatt_listener(handle.clone(), listener);
                }
                app.manage(android::AndroidPluginHandle(handle));
            }
            Ok(())
        })
        .build()
}

#![forbid(unsafe_code)]
//! Android mobile implementation for platform permission requests.

use tauri::{Runtime, plugin::PluginHandle};

use crate::commands::{
    PermissionResponse, RequestPermissionsArgs, ShowIncomingTransferNotificationArgs,
};

/// Requests permissions from the Android platform via TradrPlugin.
pub async fn request_permissions<R: Runtime>(
    handle: &PluginHandle<R>,
    permissions: Option<Vec<String>>,
) -> Result<PermissionResponse, String> {
    let args = RequestPermissionsArgs { permissions };
    handle
        .run_mobile_plugin_async("requestPermissions", args)
        .await
        .map_err(|e| format!("failed to request permissions: {e}"))
}

/// Checks permission states from the Android platform via TradrPlugin.
pub async fn check_permissions<R: Runtime>(
    handle: &PluginHandle<R>,
) -> Result<PermissionResponse, String> {
    handle
        .run_mobile_plugin_async("checkPermissions", ())
        .await
        .map_err(|e| format!("failed to check permissions: {e}"))
}

/// Shows an incoming transfer notification via TradrPlugin.
pub async fn show_incoming_transfer_notification<R: Runtime>(
    handle: &PluginHandle<R>,
    transfer_id: Option<String>,
    sender_name: Option<String>,
) -> Result<(), String> {
    let args = ShowIncomingTransferNotificationArgs {
        transfer_id,
        sender_name,
    };
    handle
        .run_mobile_plugin_async("showIncomingTransferNotification", args)
        .await
        .map_err(|e| format!("failed to show incoming transfer notification: {e}"))
}

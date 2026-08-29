#![forbid(unsafe_code)]
//! Android mobile implementation for platform permission requests.

use tauri::{Runtime, plugin::PluginHandle};

use crate::commands::{PermissionResponse, RequestPermissionsArgs};

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

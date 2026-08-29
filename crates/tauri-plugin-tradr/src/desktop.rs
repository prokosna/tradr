#![forbid(unsafe_code)]
//! Desktop implementation for platform permission requests.

use std::collections::HashMap;

use crate::commands::{PermissionResponse, PermissionState};

/// Desktop platforms do not require Android runtime permissions, returning Granted for requested items.
pub async fn request_permissions(
    permissions: Option<Vec<String>>,
) -> Result<PermissionResponse, String> {
    let mut response = HashMap::new();
    if let Some(perms) = permissions {
        for perm in perms {
            response.insert(perm, PermissionState::Granted);
        }
    } else {
        response.insert("all".to_string(), PermissionState::Granted);
    }
    Ok(response)
}

/// Checks permissions on desktop platforms, returning Granted.
pub async fn check_permissions() -> Result<PermissionResponse, String> {
    let mut response = HashMap::new();
    response.insert("all".to_string(), PermissionState::Granted);
    Ok(response)
}

/// Displays an incoming transfer notification on desktop platforms (no-op).
pub async fn show_incoming_transfer_notification(
    _transfer_id: Option<String>,
    _sender_name: Option<String>,
) -> Result<(), String> {
    Ok(())
}

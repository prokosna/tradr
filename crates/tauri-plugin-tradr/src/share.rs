//! Shared file definitions for platform intent payloads (WI-M2-002, WI-M2-003).

use serde::{Deserialize, Serialize};

/// A shared file entry received from the platform share sheet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedFilePayload {
    /// Display name of the file.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Absolute filesystem path in the application cache directory.
    pub cache_path: Option<String>,
    /// Detached raw file descriptor integer for large files.
    pub fd: Option<i32>,
}

/// What the platform pushes each time the app receives a share intent:
/// its action, its declared MIME type, optional text payload, optional target device,
/// and any attached files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShareIntent {
    /// Intent action string.
    pub action: String,
    /// MIME type if provided.
    pub mime_type: Option<String>,
    /// Plain text payload if provided.
    pub extra_text: Option<String>,
    /// Target device identifier if the share was initiated toward a specific peer.
    #[serde(default)]
    pub target_device: Option<String>,
    /// List of shared files attached to the intent.
    #[serde(default)]
    pub files: Vec<SharedFilePayload>,
}

/// Discovered peer representation for publishing sharing shortcuts to the platform share sheet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerShortcut {
    /// The peer's 16-byte Device ID, rendered as hex.
    pub device_id: String,
    /// The peer's advertised display name.
    pub display_name: String,
    /// The peer's platform, if known.
    #[serde(default)]
    pub platform: Option<String>,
}

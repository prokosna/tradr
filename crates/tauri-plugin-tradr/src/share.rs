//! Shared file definitions for platform intent payloads (WI-M2-002).

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
/// its action, its declared MIME type, optional text payload, and any attached files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShareIntent {
    /// Intent action string.
    pub action: String,
    /// MIME type if provided.
    pub mime_type: Option<String>,
    /// Plain text payload if provided.
    pub extra_text: Option<String>,
    /// List of shared files attached to the intent.
    #[serde(default)]
    pub files: Vec<SharedFilePayload>,
}

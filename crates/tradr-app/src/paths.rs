//! Application directory paths shared across front ends (DCR-124).

use std::path::{Path, PathBuf};

/// Matches the identifier in `apps/tradr/src-tauri/tauri.conf.json`;
/// `crates/tradr-app/tests/paths.rs` fails if the two ever differ.
pub const APP_IDENTIFIER: &str = "com.tradr.app";

/// Must equal what `tauri::Manager::path().app_data_dir()` computes on desktop,
/// which is `dirs::data_dir()` joined with the identifier.
pub fn app_data_dir() -> Result<PathBuf, String> {
    dirs::data_dir()
        .map(|d| d.join(APP_IDENTIFIER))
        .ok_or_else(|| "could not resolve the platform data directory".to_string())
}

/// Takes the directory rather than resolving one because Android resolves
/// its app data directory through the platform, so the caller supplies it.
pub fn device_keys_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("keys")
}

/// Where this device's own most recently obtained ID token is kept (DCR-150).
pub fn attestation_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("attestation")
}

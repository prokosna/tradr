//! Platform-specific app data directory resolution (DCR-124).
//! The split is here rather than in tradr-app because desktop must resolve
//! the directory the way the CLI does, ignoring AppHandle so both front ends
//! share one device, while Android's answer is the platform's.

use std::path::PathBuf;
#[cfg(target_os = "android")]
use tauri::Manager;
use tauri::{AppHandle, Runtime};

#[cfg(not(target_os = "android"))]
pub(crate) fn app_data_dir<R: Runtime>(_app: &AppHandle<R>) -> Result<PathBuf, String> {
    tradr_app::paths::app_data_dir()
}

#[cfg(target_os = "android")]
pub(crate) fn app_data_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    // docs/02: the platform answers there and no second front end runs on Android to disagree.
    app.path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the app data directory: {e}"))
}

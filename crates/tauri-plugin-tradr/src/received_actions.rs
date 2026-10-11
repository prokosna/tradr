//! Operations performed on received files by the host operating system (docs/12, ADR-0026).

use std::path::PathBuf;
use std::sync::Arc;

use tauri::State;
use tradr_app::received_history::ReceivedHistory;
use tradr_core::{RelPath, RootId, VfsError};
use tradr_vfs::NativeVfs;

use crate::lifecycle::downloads_root_id;

/// Failure when resolving or performing an action on a received file entry.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceivedActionError {
    /// The specified row is not present in received history.
    UnknownRow,
    /// The target file is no longer present in storage.
    Gone,
    /// An underlying operation failed.
    Failed(String),
}

impl std::fmt::Display for ReceivedActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRow => write!(f, "This row is no longer in the list."),
            Self::Gone => write!(f, "This file is no longer where it was saved."),
            Self::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ReceivedActionError {}

#[cfg(target_os = "android")]
const OFFERED_ACTIONS: &[&str] = &["open", "share"];

#[cfg(target_os = "ios")]
const OFFERED_ACTIONS: &[&str] = &[];

#[cfg(not(any(target_os = "android", target_os = "ios")))]
const OFFERED_ACTIONS: &[&str] = &["open", "reveal"];

/// Returns the actions offered for received files on this platform.
pub fn offered_actions() -> &'static [&'static str] {
    OFFERED_ACTIONS
}

/// Resolves the filesystem path for a received file given its row identifier.
pub fn locate_received(
    history: &ReceivedHistory,
    vfs: &NativeVfs,
    root: RootId,
    id: u64,
) -> Result<PathBuf, ReceivedActionError> {
    let rows = history
        .rows()
        .map_err(|e| ReceivedActionError::Failed(e.to_string()))?;
    let row = rows
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(ReceivedActionError::UnknownRow)?;
    let rel = RelPath::new(&row.path).map_err(|e| ReceivedActionError::Failed(e.to_string()))?;
    vfs.host_file_path(root, &rel).map_err(|e| match e {
        VfsError::NotFound => ReceivedActionError::Gone,
        other => ReceivedActionError::Failed(other.to_string()),
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn perform_open(path: &std::path::Path) -> Result<(), String> {
    tauri_plugin_opener::open_path(path, None::<&str>).map_err(|e| e.to_string())
}

#[cfg(target_os = "ios")]
fn perform_open(_path: &std::path::Path) -> Result<(), String> {
    Err("This device cannot do that.".to_string())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn perform_reveal(path: &std::path::Path) -> Result<(), String> {
    tauri_plugin_opener::reveal_item_in_dir(path).map_err(|e| e.to_string())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn perform_reveal(_path: &std::path::Path) -> Result<(), String> {
    Err("This device cannot do that.".to_string())
}

#[cfg(not(target_os = "android"))]
fn perform_share(_path: &std::path::Path) -> Result<(), String> {
    Err("This device cannot do that.".to_string())
}

/// Returns the actions offered for received files on this platform.
#[tauri::command]
pub fn received_actions() -> Result<Vec<String>, String> {
    Ok(offered_actions().iter().map(|&s| s.to_string()).collect())
}

/// Opens the received file in its default application.
#[tauri::command]
pub async fn open_received<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    id: u64,
    history: State<'_, Arc<ReceivedHistory>>,
    vfs: State<'_, Arc<NativeVfs>>,
) -> Result<(), String> {
    let path =
        locate_received(&history, &vfs, downloads_root_id(), id).map_err(|e| e.to_string())?;
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let handle_state = app
            .try_state::<crate::android::AndroidPluginHandle<R>>()
            .ok_or_else(|| "android plugin handle not found".to_string())?;
        let path_str = path
            .to_str()
            .ok_or_else(|| "Failed to convert file path to string".to_string())?;
        crate::android::open_received_file(&handle_state.0, path_str).await
    }
    #[cfg(not(target_os = "android"))]
    {
        perform_open(&path)
    }
}

/// Reveals the received file in its directory in the file manager.
#[tauri::command]
pub fn reveal_received(
    id: u64,
    history: State<'_, Arc<ReceivedHistory>>,
    vfs: State<'_, Arc<NativeVfs>>,
) -> Result<(), String> {
    let path =
        locate_received(&history, &vfs, downloads_root_id(), id).map_err(|e| e.to_string())?;
    perform_reveal(&path)
}

/// Shares the received file via the platform sharing mechanism.
#[tauri::command]
pub async fn share_received<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    id: u64,
    history: State<'_, Arc<ReceivedHistory>>,
    vfs: State<'_, Arc<NativeVfs>>,
) -> Result<(), String> {
    let path =
        locate_received(&history, &vfs, downloads_root_id(), id).map_err(|e| e.to_string())?;
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let handle_state = app
            .try_state::<crate::android::AndroidPluginHandle<R>>()
            .ok_or_else(|| "android plugin handle not found".to_string())?;
        let path_str = path
            .to_str()
            .ok_or_else(|| "Failed to convert file path to string".to_string())?;
        crate::android::share_received_file(&handle_state.0, path_str).await
    }
    #[cfg(not(target_os = "android"))]
    {
        perform_share(&path)
    }
}

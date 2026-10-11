//! Shared download folder resolution and verification for Android (docs/08, DCR-182, DCR-183).

use std::path::{Path, PathBuf};

use tauri::State;

/// Derives the shared download directory from the app-specific path on primary storage (docs/08, DCR-182, DCR-183).
pub fn shared_download_dir(app_specific: &Path) -> Option<PathBuf> {
    let components: Vec<_> = app_specific.components().collect();
    for (i, window) in components.windows(2).enumerate() {
        if window[0].as_os_str() == "Android" && window[1].as_os_str() == "data" {
            if i == 0 {
                return None;
            }
            let mut root = PathBuf::new();
            for c in &components[..i] {
                root.push(c);
            }
            if root.as_os_str().is_empty() {
                return None;
            }
            root.push("Download");
            return Some(root);
        }
    }
    None
}

/// Verifies filesystem write, rename, and delete permissions on the target directory (docs/08, DCR-182).
pub fn probe_receive_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let partial = dir.join(".tradr-probe.tradr-partial");
    std::fs::write(&partial, b"tradr")?;
    let probe = dir.join(".tradr-probe");
    std::fs::rename(&partial, &probe)?;
    std::fs::remove_file(&probe)?;
    Ok(())
}

/// Chooses the shared download folder if writable, falling back to app-specific storage (docs/08, DCR-182).
pub fn choose_receive_dir(app_specific: PathBuf) -> PathBuf {
    if let Some(shared) = shared_download_dir(&app_specific) {
        match probe_receive_dir(&shared) {
            Ok(()) => shared,
            Err(e) => {
                eprintln!("receive_folder: probe failed on {}: {e}", shared.display());
                app_specific
            }
        }
    } else {
        app_specific
    }
}

/// Holds the active folder for received files in Tauri state (docs/08, DCR-182).
#[derive(Debug, Clone)]
pub struct ReceiveFolder(pub PathBuf);

/// Returns the path of the folder saving received files to display in the UI (docs/08, DCR-182).
#[tauri::command]
pub fn receive_folder(folder: State<'_, ReceiveFolder>) -> String {
    folder.0.to_string_lossy().into_owned()
}

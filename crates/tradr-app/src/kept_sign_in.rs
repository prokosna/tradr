//! Keeps and loads this device's own ID token on disk across runs (DCR-150).

use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// How long a kept ID token may be reused before interactive sign-in is required (DCR-150).
pub const SIGN_IN_REUSE_LIMIT_SECS: u64 = 21 * 24 * 60 * 60;

/// Loads the kept ID token from disk, ignoring empty or missing files (DCR-150).
pub fn load_kept_token(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "failed to read kept token at {}: {err}",
            path.display()
        )),
    }
}

/// Writes the ID token to a temporary sibling file and renames it over the target path (DCR-150).
pub fn keep_token(path: &Path, id_token: &str) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create directory {}: {e}", parent.display()))?;
    }

    let (mut file, temp_path) = create_temp_sibling(path)?;

    let write_res = file
        .write_all(id_token.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = write_res {
        return fail_and_cleanup(
            &temp_path,
            format!("could not write kept token to {}: {e}", temp_path.display()),
        );
    }

    if let Err(e) = std::fs::rename(&temp_path, path) {
        return fail_and_cleanup(
            &temp_path,
            format!(
                "could not rename temporary file {} to {}: {e}",
                temp_path.display(),
                path.display()
            ),
        );
    }

    Ok(())
}

fn create_temp_sibling(path: &Path) -> Result<(std::fs::File, PathBuf), String> {
    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    for _ in 0..100 {
        let count = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut name = path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        name.push(format!(".tmp-{}-{}", std::process::id(), count));
        let temp_path = path.with_file_name(name);

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);

        match opts.open(&temp_path) {
            Ok(file) => return Ok((file, temp_path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "could not create temporary file {}: {e}",
                    temp_path.display()
                ));
            }
        }
    }

    Err(format!(
        "could not find a fresh temporary file name beside {}",
        path.display()
    ))
}

fn fail_and_cleanup(temp_path: &Path, original_err: String) -> Result<(), String> {
    match std::fs::remove_file(temp_path) {
        Ok(()) => Err(original_err),
        Err(cleanup_err) => Err(format!(
            "{original_err}, and removing the temporary file {} also failed: {cleanup_err}",
            temp_path.display()
        )),
    }
}

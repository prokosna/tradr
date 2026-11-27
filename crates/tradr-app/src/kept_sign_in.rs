//! Keeps and loads this device's own ID token on disk across runs.

use std::path::Path;

use tradr_core::UnixTime;

use crate::atomic::{Access, write_atomic_with};

/// How long a kept ID token may be reused before interactive sign-in is required.
pub const SIGN_IN_REUSE_LIMIT_SECS: u64 = 21 * 24 * 60 * 60;

/// Age at which the kept ID token is renewed in the background, a week
/// ahead of the reuse limit so a few failed attempts still leave time.
pub const RENEWAL_AFTER_SECS: u64 = 14 * 24 * 60 * 60;

/// Whether a token issued at `iat` is old enough to renew at `now`. A token
/// dated in the future is not due: renewing it could not make it fresher.
pub fn renewal_due(iat: UnixTime, now: UnixTime) -> bool {
    now.elapsed_since(iat)
        .is_ok_and(|age| age >= RENEWAL_AFTER_SECS)
}

/// Loads the kept ID token from disk, ignoring empty or missing files.
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

/// Writes the ID token to a temporary sibling file and renames it over the target path.
pub fn keep_token(path: &Path, id_token: &str) -> Result<(), String> {
    write_atomic_with(path, id_token.as_bytes(), Access::OwnerOnly)
        .map_err(|e| format!("could not keep the sign-in at {}: {e}", path.display()))
}

//! The lowest rung of the Linux storage ladder (docs/05-security.md,
//! "Descending the Linux ladder"): a `0600` file per slot inside a
//! directory the composition root chooses. The only path arithmetic
//! here is joining a validated slot name onto that directory, which
//! invariant I5's `tradr-vfs` confinement does not reach.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tradr_core::{SecretStore, SecretStoreError, StorageLevel};

/// How many fresh names `create_fresh_temp_file` will try before giving
/// up. A collision only happens against a stale name from a crashed
/// earlier run, since a live writer never reuses one; this bounds the
/// search rather than looping forever against a directory that is
/// somehow never free of them.
const MAX_TEMP_ATTEMPTS: u32 = 8;

/// `0600`: owner read-write, nothing for group or other.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// `0700`: owner read-write-execute, nothing for group or other.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// The lowest rung of the Linux storage ladder: one `0600` file per slot,
/// inside a directory supplied at construction. `docs/02-architecture.md`,
/// "Where a Device Key is actually held", names this crate as the sole
/// implementation of the file rung.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// Builds a store rooted at `dir`. Nothing is read or written yet;
    /// `dir` itself is created lazily, on the first `store`.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

/// A slot name failed the bare-name check `store`, `load`, and `remove`
/// all apply before touching the filesystem.
#[derive(Debug)]
struct InvalidSlot {
    slot: String,
}

impl std::fmt::Display for InvalidSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "slot {:?} is not a bare name: must be non-empty ASCII lowercase letters, digits, or '-'",
            self.slot
        )
    }
}

impl std::error::Error for InvalidSlot {}

// A slot becomes a filename by a plain join, so a rejected byte here is
// the only thing standing between a caller and a path escaping `dir`
// (invariant I5). Every real caller passes a constant, which is exactly
// when this check costs nothing.
fn validate_slot(slot: &str) -> Result<(), SecretStoreError> {
    let is_bare_name = !slot.is_empty()
        && slot
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if is_bare_name {
        Ok(())
    } else {
        Err(SecretStoreError::Backend(Box::new(InvalidSlot {
            slot: slot.to_string(),
        })))
    }
}

fn backend_err(source: std::io::Error) -> SecretStoreError {
    SecretStoreError::Backend(Box::new(source))
}

/// A write or a rename failed after a fresh temporary file had already
/// been created, and removing that file to keep the failure from leaving
/// anything behind also failed. Carries both rather than discarding the
/// second so neither is swallowed (rule F6).
#[derive(Debug)]
struct CleanupFailed {
    original: std::io::Error,
    cleanup: std::io::Error,
}

impl std::fmt::Display for CleanupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, and removing the temporary file left behind by that failure also failed: {}",
            self.original, self.cleanup
        )
    }
}

impl std::error::Error for CleanupFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

// The mode is passed to O_CREAT itself, which only applies it when the
// call is the one creating the file: a name that already exists keeps
// its old mode regardless of what is asked for here. Trying fresh names
// under create_new until one succeeds is what makes a freshly-created
// file, and therefore FILE_MODE, guaranteed rather than assumed.
fn create_fresh_temp_file(dir: &Path) -> Result<(File, PathBuf), SecretStoreError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let candidate = dir.join(format!(".tmp-{}-{unique}", std::process::id()));

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(FILE_MODE);

        match opts.open(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(backend_err(source)),
        }
    }
    Err(backend_err(std::io::Error::other(
        "could not find a fresh temporary file name",
    )))
}

// Removes the temp file a failed write or rename left behind, so the
// directory is never left holding more than the slot files themselves
// (docs/05-security.md's file rung). Surfaces a failed removal instead of
// discarding it, rather than reporting only the original failure.
fn fail_and_cleanup(temp_path: &Path, original: std::io::Error) -> SecretStoreError {
    match fs::remove_file(temp_path) {
        Ok(()) => backend_err(original),
        Err(cleanup) => SecretStoreError::Backend(Box::new(CleanupFailed { original, cleanup })),
    }
}

impl SecretStore for FileStore {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        validate_slot(slot)?;

        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(DIR_MODE);
        builder.create(&self.dir).map_err(backend_err)?;

        #[cfg(unix)]
        {
            // DirBuilder's mode is likewise only applied at creation: a
            // directory that was already there keeps whatever mode it had, so
            // it is narrowed here explicitly rather than trusted.
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(DIR_MODE))
                .map_err(backend_err)?;
        }

        let (mut temp_file, temp_path) = create_fresh_temp_file(&self.dir)?;

        let written = temp_file
            .write_all(secret)
            .and_then(|()| temp_file.sync_all());
        drop(temp_file);
        if let Err(source) = written {
            return Err(fail_and_cleanup(&temp_path, source));
        }

        // A rename within one directory replaces the destination
        // atomically, so the slot file is either the old value or the new
        // one, never a partial write, and it inherits the temp file's
        // freshly-applied FILE_MODE regardless of what the slot held before.
        fs::rename(&temp_path, self.dir.join(slot))
            .map_err(|source| fail_and_cleanup(&temp_path, source))
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        validate_slot(slot)?;

        match File::open(self.dir.join(slot)) {
            Ok(mut opened) => {
                let mut bytes = Vec::new();
                opened.read_to_end(&mut bytes).map_err(backend_err)?;
                Ok(Some(bytes))
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(backend_err(source)),
        }
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        validate_slot(slot)?;

        match fs::remove_file(self.dir.join(slot)) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(backend_err(source)),
        }
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

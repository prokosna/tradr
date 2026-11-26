use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAX_TEMP_ATTEMPTS: u32 = 100;

/// Who may read the file once written.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Default,
    OwnerOnly,
}

fn create_temp_sibling(path: &Path, access: Access) -> std::io::Result<(std::fs::File, PathBuf)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".tmp-{}-{count}", std::process::id()));
        let temp = path.with_file_name(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        if access == Access::OwnerOnly {
            #[cfg(unix)]
            opts.mode(0o600);
        }
        match opts.open(&temp) {
            Ok(file) => return Ok((file, temp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "no fresh temporary file name was free",
    ))
}

/// Writes `bytes` to a fresh sibling, syncs it and renames it over `path`, so
/// a reader sees the old file or the new one and never a partial one.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with(path, bytes, Access::Default)
}

pub(crate) fn write_atomic_with(path: &Path, bytes: &[u8], access: Access) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let (mut file, temp) = create_temp_sibling(path, access)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = written.and_then(|()| std::fs::rename(&temp, path));
    if let Err(first_err) = result {
        if let Err(cleanup_err) = std::fs::remove_file(&temp) {
            eprintln!(
                "atomic: failed to remove temporary file {}: {cleanup_err}",
                temp.display()
            );
        }
        return Err(first_err);
    }
    Ok(())
}

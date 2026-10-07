use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_TEMP_ATTEMPTS: u32 = 100;

fn create_temp_sibling(path: &Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = match path.file_name() {
            Some(n) => n.to_os_string(),
            None => std::ffi::OsString::new(),
        };
        name.push(format!(".tmp-{}-{count}", std::process::id()));
        let temp = path.with_file_name(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => return Ok((file, temp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "no fresh temporary file name was free",
    ))
}

pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let (mut file, temp) = create_temp_sibling(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = written.and_then(|()| std::fs::rename(&temp, path));
    if let Err(first_err) = result {
        if let Err(cleanup_err) = std::fs::remove_file(&temp) {
            eprintln!("atomic: failed to clean up temp file: {cleanup_err}");
        }
        return Err(first_err);
    }
    Ok(())
}

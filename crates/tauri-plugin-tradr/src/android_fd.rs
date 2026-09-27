use std::fs::File;
use std::os::fd::{FromRawFd, OwnedFd};

#[allow(unsafe_code)]
pub(crate) fn adopt_detached_fd(raw: i32) -> Result<File, String> {
    if raw < 0 {
        return Err("negative file descriptor cannot be adopted".to_string());
    }
    // SAFETY: Kotlin obtained the descriptor via ParcelFileDescriptor.detachFd(),
    // giving up its ownership. Rust calls this once per descriptor at arrival,
    // never on numbers supplied by the frontend.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw) }))
}

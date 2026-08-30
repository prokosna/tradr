#![forbid(unsafe_code)]
//! Share Root boundary enforcement, posix and saf backends.

#[cfg(unix)]
pub mod posix;
pub mod saf;
pub mod sanitization;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub use posix::{
    PosixReadHandle as NativeReadHandle, PosixVfs as NativeVfs,
    PosixWriteHandle as NativeWriteHandle,
};
#[cfg(windows)]
pub use windows::{
    WindowsReadHandle as NativeReadHandle, WindowsVfs as NativeVfs,
    WindowsWriteHandle as NativeWriteHandle,
};

pub use saf::{SafBridge, SafNode, SafVfs};
pub use sanitization::{
    SanitizationError, check_deny_list, check_deny_list_write, is_denied, partial_file_rel_path,
    resolve_collision, sanitize_destination_path,
};

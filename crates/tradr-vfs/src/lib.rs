#![forbid(unsafe_code)]
//! Share Root boundary enforcement, posix and saf backends.

pub mod posix;
pub mod sanitization;

pub use posix::{PosixReadHandle, PosixVfs, PosixWriteHandle};
pub use sanitization::{
    SanitizationError, partial_file_rel_path, resolve_collision, sanitize_destination_path,
};

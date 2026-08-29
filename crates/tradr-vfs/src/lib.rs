#![forbid(unsafe_code)]
//! Share Root boundary enforcement, posix and saf backends.

pub mod posix;
pub mod saf;
pub mod sanitization;

pub use posix::{PosixReadHandle, PosixVfs, PosixWriteHandle};
pub use saf::{SafBridge, SafNode, SafVfs};
pub use sanitization::{
    SanitizationError, check_deny_list, check_deny_list_write, is_denied, partial_file_rel_path,
    resolve_collision, sanitize_destination_path,
};

#![forbid(unsafe_code)]
//! Implementations of `tradr-core`'s `SecretStore` trait: the Linux
//! storage ladder docs/05-security.md lists under "Key storage" -- the
//! Secret Service over D-Bus and a `0600` file. `tradr-identity` keeps
//! the ladder policy; this crate keeps the I/O.

mod file;
#[cfg(target_os = "linux")]
mod secret_service;

pub use file::FileStore;
#[cfg(target_os = "linux")]
pub use secret_service::SecretServiceStore;

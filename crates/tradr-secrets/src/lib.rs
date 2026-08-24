#![forbid(unsafe_code)]
//! Implementations of `tradr-core`'s `SecretStore` trait: the Linux
//! storage ladder docs/05-security.md lists under "Key storage" -- the
//! Secret Service over D-Bus, the kernel keyring, and a `0600` file. This
//! Work Item (WI-M0-007d) adds the file rung; WI-M0-007e adds the rest.
//! `tradr-identity` keeps the ladder policy; this crate keeps the I/O.

mod file;

pub use file::FileStore;

#![forbid(unsafe_code)]
//! Shell-free application logic independent of any UI or frontend shell.
//! This crate must never name Tauri to keep the application core portable (D9).

pub mod attestation;
pub mod broadcast_secrets;
pub mod browse;
pub mod capabilities;
pub mod handshake;
pub mod link_exchange;
pub mod link_invite;
pub mod listener;
pub mod peer_trust;
pub mod peers;
pub mod send;
pub mod share;
pub mod sign_in;
pub mod transfer;

//! Noise_IK over a byte stream (WI-M7-007a).

mod handshake;
mod resolver;

use std::fmt;

use tradr_core::{KeyStoreError, RngError};

pub use handshake::{AwaitingReply, AwaitingResponse, Initiator, NoiseSession, Responder};

/// The maximum plaintext length in bytes: 65535 minus the 16-byte Poly1305 tag.
pub const MAX_PLAINTEXT_LEN: usize = 65519;

/// An error arising from a Noise handshake or session operation.
#[derive(Debug)]
pub enum NoiseError {
    /// The device key store failed to perform an operation.
    KeyStore(KeyStoreError),
    /// The randomness source failed to provide entropy.
    Rng(RngError),
    /// A handshake or session message was malformed, truncated, out of order, or unauthenticated.
    Refused,
    /// The plaintext payload exceeds `MAX_PLAINTEXT_LEN`.
    PayloadTooLarge(usize),
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyStore(err) => write!(f, "key store error: {err}"),
            Self::Rng(err) => write!(f, "rng error: {err}"),
            Self::Refused => write!(f, "noise message refused"),
            Self::PayloadTooLarge(len) => write!(f, "payload too large: {len} bytes"),
        }
    }
}

impl std::error::Error for NoiseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyStore(err) => Some(err),
            Self::Rng(err) => Some(err),
            Self::Refused | Self::PayloadTooLarge(_) => None,
        }
    }
}

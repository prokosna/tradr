//! Noise_XX over a byte stream with identity join (ADR-0020).

mod channel;
mod handshake;
mod link;
mod resolver;

use std::fmt;

use tradr_core::{KeyBindingRefused, KeyStoreError, RngError};

pub use channel::{BLE_GATT_MAX_FRAME_SIZE, NoiseChannel, NoiseChannelConfig};
pub use handshake::{
    AwaitingConfirmation, AwaitingReply, AwaitingResponse, Initiator, NoiseSession, ReadyToConfirm,
    Responder,
};
pub use link::{LinkSink, LinkSource};

/// The length of the identity join payload in bytes (ADR-0020).
pub const IDENTITY_JOIN_LEN: usize = 137;

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
    /// The local key binding does not match this device's agreement key.
    LocalKeyBinding,
    /// The peer's key binding was refused by the verifier.
    PeerKeyBinding(KeyBindingRefused),
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyStore(err) => write!(f, "key store error: {err}"),
            Self::Rng(err) => write!(f, "rng error: {err}"),
            Self::Refused => write!(f, "noise message refused"),
            Self::PayloadTooLarge(len) => write!(f, "payload too large: {len} bytes"),
            Self::LocalKeyBinding => {
                write!(f, "local key binding does not cover our agreement key")
            }
            Self::PeerKeyBinding(refusal) => write!(f, "peer key binding refused: {refusal}"),
        }
    }
}

impl std::error::Error for NoiseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyStore(err) => Some(err),
            Self::Rng(err) => Some(err),
            Self::PeerKeyBinding(err) => Some(err),
            Self::Refused | Self::PayloadTooLarge(_) | Self::LocalKeyBinding => None,
        }
    }
}

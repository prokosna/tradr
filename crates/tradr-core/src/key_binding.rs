//! Layer 1 port and vocabulary for joining a Noise agreement key to a Device ID
//! (docs/05-security.md; ADR-0020). A Noise handshake authenticates agreement
//! keys while `SecureChannel::peer` returns a `DeviceId` from the identity key;
//! this port verifies that binding without naming concrete crypto (rule B1, B2).

use std::fmt;

use crate::clock::UnixTime;
use crate::device_id::DeviceId;
use crate::hello::KeyBinding;
use crate::key_store::PublicKeyPoint;

/// Why a key binding verification refused to accept a binding
/// (docs/04-protocol.md, "What each side checks, and in what order").
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBindingRefused {
    /// The binding covers a different agreement key than the authenticated one.
    NotForThisAgreementKey,
    /// The signature over the key binding is invalid.
    SignatureInvalid,
    /// The binding has expired.
    Expired {
        /// The expiry time of the binding.
        not_after: UnixTime,
        /// The current time when checked.
        now: UnixTime,
    },
    /// The identity key cannot be parsed as a valid public key point.
    MalformedIdentityKey,
}

impl fmt::Display for KeyBindingRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotForThisAgreementKey => {
                write!(
                    f,
                    "key binding does not cover the authenticated agreement key"
                )
            }
            Self::SignatureInvalid => {
                write!(f, "key binding signature does not verify")
            }
            Self::Expired { not_after, now } => {
                write!(
                    f,
                    "key binding expired at {}, now is {}",
                    not_after.as_secs(),
                    now.as_secs()
                )
            }
            Self::MalformedIdentityKey => {
                write!(f, "identity key is not a valid public key point")
            }
        }
    }
}

impl std::error::Error for KeyBindingRefused {}

/// Verifies the binding between an identity key and an agreement key.
///
/// Implemented in `tradr-identity` using P-256 and injected into `tradr-transport`
/// so the transport crate depends on no cryptographic algorithms directly (ADR-0020).
pub trait KeyBindingVerifier: Send + Sync {
    /// Verifies that `identity_pub` signed `binding` over `authenticated_agreement_pub`,
    /// and that the binding is not expired, returning the derived `DeviceId`.
    fn device_id_for_agreement_key(
        &self,
        identity_pub: &PublicKeyPoint,
        binding: &KeyBinding,
        authenticated_agreement_pub: &PublicKeyPoint,
    ) -> Result<DeviceId, KeyBindingRefused>;
}

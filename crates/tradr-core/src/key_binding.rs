//! Why a `KeyBinding` between an identity key and an agreement key was
//! refused (docs/04, Hello check 3).

use std::fmt;

use crate::clock::UnixTime;

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

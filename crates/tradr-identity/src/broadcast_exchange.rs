//! The Account Broadcast Key exchange driver (docs/11-account-linking.md,
//! "The exchange, and why it needs no roles"). Two steps, consumed by value,
//! performing no I/O beyond the registry and secret store it is handed.
//! A Critical Module (CLAUDE.md section 6): an offer on a lower tier leaks
//! this account's broadcast secret to another account.

use std::fmt;

use tradr_core::{
    BroadcastKeyOffer, CollisionOutcome, Rng, SecretStore, TrustTier, UnixTime, resolve_collision,
};

use crate::broadcast_key::{BroadcastKeyRegistry, BroadcastKeyRegistryError};

/// The outcome of completing an Account Broadcast Key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// The stored key won the collision order; nothing was written.
    Kept,
    /// No key was stored and the locally drawn offer won; both halves were written.
    Generated,
    /// The peer's offer won the collision order; both halves were written.
    Adopted,
}

/// Why an Account Broadcast Key exchange was refused or failed.
#[non_exhaustive]
#[derive(Debug)]
pub enum ExchangeError {
    /// The channel was granted a trust tier other than `SameAccount`.
    TierNotSameAccount {
        /// The trust tier that was actually granted.
        granted: TrustTier,
    },
    /// The broadcast key registry or underlying secret store failed.
    Registry(BroadcastKeyRegistryError),
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TierNotSameAccount { granted } => {
                write!(f, "channel trust tier is {granted:?}, expected SameAccount")
            }
            Self::Registry(err) => write!(f, "registry error: {err}"),
        }
    }
}

impl std::error::Error for ExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TierNotSameAccount { .. } => None,
            Self::Registry(err) => Some(err),
        }
    }
}

impl From<BroadcastKeyRegistryError> for ExchangeError {
    fn from(err: BroadcastKeyRegistryError) -> Self {
        Self::Registry(err)
    }
}

/// Awaiting the peer's `BroadcastKeyOffer` to resolve collision.
#[derive(Debug)]
pub struct AwaitingPeerOffer {
    local_offer: BroadcastKeyOffer,
    drawn: bool,
}

/// Opens an Account Broadcast Key exchange for a channel at `tier`.
pub fn open(
    tier: TrustTier,
    registry: &BroadcastKeyRegistry,
    secrets: &dyn SecretStore,
    rng: &dyn Rng,
    now: UnixTime,
) -> Result<(AwaitingPeerOffer, BroadcastKeyOffer), ExchangeError> {
    if tier != TrustTier::SameAccount {
        return Err(ExchangeError::TierNotSameAccount { granted: tier });
    }

    let (local_offer, drawn) = match registry.offer(secrets)? {
        Some(stored) => (stored, false),
        None => (registry.draw(rng, now)?, true),
    };

    let state = AwaitingPeerOffer { local_offer, drawn };
    Ok((state, local_offer))
}

impl AwaitingPeerOffer {
    /// Resolves the peer's offer against the local offer and persists when needed.
    pub fn on_peer_offer(
        self,
        peer: BroadcastKeyOffer,
        registry: &mut BroadcastKeyRegistry,
        secrets: &dyn SecretStore,
    ) -> Result<ExchangeOutcome, ExchangeError> {
        match resolve_collision(&self.local_offer, &peer) {
            CollisionOutcome::KeepLocal => {
                if self.drawn {
                    registry.adopt(&self.local_offer, secrets)?;
                    Ok(ExchangeOutcome::Generated)
                } else {
                    Ok(ExchangeOutcome::Kept)
                }
            }
            CollisionOutcome::AdoptRemote => {
                registry.adopt(&peer, secrets)?;
                Ok(ExchangeOutcome::Adopted)
            }
        }
    }
}

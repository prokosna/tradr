//! Layer 0 value type for the Account Broadcast Key and the collision rule
//! (docs/11-account-linking.md, "Distributing the Account Broadcast Key").
//! A Critical Module (CLAUDE.md section 6): the collision rule is what
//! converges all devices of an account onto a single key across restarts.

use std::cmp::Ordering;
use std::fmt;

use crate::clock::UnixTime;

/// The number of bytes an `AccountBroadcastKey` occupies.
pub const ACCOUNT_BROADCAST_KEY_LEN: usize = 32;

/// An error constructing an `AccountBroadcastKey` from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastKeyError {
    /// The input was not exactly `ACCOUNT_BROADCAST_KEY_LEN` bytes.
    WrongLength {
        /// The number of bytes the type requires.
        expected: usize,
        /// The number of bytes actually given.
        actual: usize,
    },
}

impl fmt::Display for BroadcastKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for BroadcastKeyError {}

/// The 32 random bytes all devices of an account share for BLE discovery
/// (CONTEXT.md, "Account Broadcast Key"). No derived `PartialEq`, `Eq`,
/// `PartialOrd` or `Ord`: comparing secret material byte-wise is what
/// `resolve_collision` specifically defines for this type.
#[derive(Clone, Copy)]
pub struct AccountBroadcastKey([u8; ACCOUNT_BROADCAST_KEY_LEN]);

impl AccountBroadcastKey {
    /// Builds an `AccountBroadcastKey` from exactly `ACCOUNT_BROADCAST_KEY_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BroadcastKeyError> {
        let array: [u8; ACCOUNT_BROADCAST_KEY_LEN] =
            bytes
                .try_into()
                .map_err(|_| BroadcastKeyError::WrongLength {
                    expected: ACCOUNT_BROADCAST_KEY_LEN,
                    actual: bytes.len(),
                })?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; ACCOUNT_BROADCAST_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for AccountBroadcastKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountBroadcastKey(<redacted>)")
    }
}

/// The outcome of resolving an Account Broadcast Key collision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionOutcome {
    /// The local key wins and is retained.
    KeepLocal,
    /// The remote key wins and must be adopted.
    AdoptRemote,
}

/// Resolves which Account Broadcast Key to keep on collision (docs/11).
///
/// The earlier `created_at` wins; on a tie, the smaller 32-byte value
/// under unsigned lexicographical comparison. An exact tie produces
/// `KeepLocal`.
pub fn resolve_collision(
    local: &AccountBroadcastKey,
    local_created_at: UnixTime,
    remote: &AccountBroadcastKey,
    remote_created_at: UnixTime,
) -> CollisionOutcome {
    match local_created_at.cmp(&remote_created_at) {
        Ordering::Less => CollisionOutcome::KeepLocal,
        Ordering::Greater => CollisionOutcome::AdoptRemote,
        Ordering::Equal => match local.as_bytes().cmp(remote.as_bytes()) {
            Ordering::Greater => CollisionOutcome::AdoptRemote,
            Ordering::Less | Ordering::Equal => CollisionOutcome::KeepLocal,
        },
    }
}

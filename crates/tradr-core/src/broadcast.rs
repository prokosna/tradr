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

/// `1` and not `0` because `0` is what proto3 produces for an omitted scalar,
/// so it can never be a value a device writes.
pub const FIRST_KEY_GENERATION: u32 = 1;

/// A generation separates a rotation from a device that has merely joined, which a
/// creation time cannot. The increment saturates rather than wrapping because `0`
/// is the one value `BroadcastKeyOffer::new` refuses, so a wrap would make the next
/// rotation unconstructible.
pub fn next_generation(current: Option<u32>) -> u32 {
    match current {
        None => FIRST_KEY_GENERATION,
        Some(generation) => generation.saturating_add(1),
    }
}

/// An error constructing a `BroadcastKeyOffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastKeyOfferError {
    /// Generation 0 was provided, which is refused because proto3 produces 0
    /// when a scalar field is omitted.
    ZeroIsNotAGeneration,
    /// The creation time was at or before the Unix epoch.
    CreatedAtNotAfterEpoch {
        /// The creation time in seconds since the Unix epoch that was refused.
        seconds: i64,
    },
}

impl fmt::Display for BroadcastKeyOfferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroIsNotAGeneration => write!(f, "generation 0 is not a valid generation"),
            Self::CreatedAtNotAfterEpoch { seconds } => {
                write!(f, "creation time {seconds} is not after the Unix epoch")
            }
        }
    }
}

impl std::error::Error for BroadcastKeyOfferError {}

/// The key, the generation it belongs to, and when it was made, travelling as one
/// value: the collision rule orders the triple, and a caller pairing one device's bytes
/// with another's creation time is the mistake the type removes (docs/11-account-linking.md,
/// "The order the collision rule applies"). No derived `PartialEq`, `Eq`, `PartialOrd`
/// or `Ord`: `resolve_collision` is the one ordering this design licenses.
#[derive(Clone, Copy)]
pub struct BroadcastKeyOffer {
    key: AccountBroadcastKey,
    generation: u32,
    created_at: UnixTime,
}

impl BroadcastKeyOffer {
    /// Builds a new `BroadcastKeyOffer` after validating generation and creation time.
    pub fn new(
        key: AccountBroadcastKey,
        generation: u32,
        created_at: UnixTime,
    ) -> Result<Self, BroadcastKeyOfferError> {
        if generation == 0 {
            return Err(BroadcastKeyOfferError::ZeroIsNotAGeneration);
        }
        if created_at.as_secs() <= 0 {
            return Err(BroadcastKeyOfferError::CreatedAtNotAfterEpoch {
                seconds: created_at.as_secs(),
            });
        }
        Ok(Self {
            key,
            generation,
            created_at,
        })
    }

    /// Returns the offered broadcast key.
    pub fn key(&self) -> &AccountBroadcastKey {
        &self.key
    }

    /// Returns the generation of the offered key.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Returns the creation time of the offered key.
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }
}

impl fmt::Debug for BroadcastKeyOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BroadcastKeyOffer")
            .field("key", &self.key)
            .field("generation", &self.generation)
            .field("created_at", &self.created_at)
            .finish()
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
/// Applies the total ordering: higher generation wins; on tie, earlier
/// creation time wins; on tie, smaller 32-byte value under unsigned
/// lexicographical comparison wins; on exact tie, `KeepLocal`.
pub fn resolve_collision(
    local: &BroadcastKeyOffer,
    remote: &BroadcastKeyOffer,
) -> CollisionOutcome {
    match local.generation().cmp(&remote.generation()) {
        Ordering::Greater => CollisionOutcome::KeepLocal,
        Ordering::Less => CollisionOutcome::AdoptRemote,
        Ordering::Equal => match local.created_at().cmp(&remote.created_at()) {
            Ordering::Less => CollisionOutcome::KeepLocal,
            Ordering::Greater => CollisionOutcome::AdoptRemote,
            Ordering::Equal => match local.key().as_bytes().cmp(remote.key().as_bytes()) {
                Ordering::Less | Ordering::Equal => CollisionOutcome::KeepLocal,
                Ordering::Greater => CollisionOutcome::AdoptRemote,
            },
        },
    }
}

//! Ephemeral Identifiers (EIDs) and window matching for BLE proximity
//! discovery (docs/03-discovery-and-transport.md, ADR-0018).

use std::fmt;

use tradr_core::UnixTime;

/// The number of bytes an Ephemeral Identifier (EID) occupies.
pub const EID_LEN: usize = 8;

/// The rotation period of an EID in seconds (15 minutes).
pub const EID_WINDOW_SECS: i64 = 900;

/// The number of bytes a Broadcast Secret occupies.
pub const BROADCAST_SECRET_LEN: usize = 32;

/// The context string `BroadcastSecret::eid` hands to `blake3::derive_key`
/// (ADR-0018).
const EID_CONTEXT: &str = "tradr-eid-v1";

/// The context string `BroadcastSecret::bootstrap` hands to `blake3::derive_key`
/// (ADR-0018).
const BOOTSTRAP_CONTEXT: &str = "tradr-bootstrap-v1";

/// An error constructing an EID domain value from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EidError {
    /// The input was not exactly the expected number of bytes.
    WrongLength {
        /// The number of bytes the type requires.
        expected: usize,
        /// The number of bytes actually given.
        actual: usize,
    },
}

impl fmt::Display for EidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for EidError {}

/// A 15-minute time window used to rotate EIDs (ADR-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EidWindow(i64);

impl EidWindow {
    /// Builds an `EidWindow` from a raw window index.
    pub fn from_index(index: i64) -> Self {
        Self(index)
    }

    /// Returns the window index.
    pub fn index(self) -> i64 {
        self.0
    }

    /// Returns the `EidWindow` containing `time`, flooring via `div_euclid`.
    pub fn containing(time: UnixTime) -> Self {
        Self(time.as_secs().div_euclid(EID_WINDOW_SECS))
    }
}

/// An 8-byte Ephemeral Identifier broadcast over BLE (ADR-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eid([u8; EID_LEN]);

impl Eid {
    /// Builds an `Eid` from exactly `EID_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EidError> {
        let array: [u8; EID_LEN] = bytes.try_into().map_err(|_| EidError::WrongLength {
            expected: EID_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; EID_LEN] {
        &self.0
    }
}

/// A 32-byte secret used to derive rotating EIDs (ADR-0018).
#[derive(Clone, Copy)]
pub struct BroadcastSecret([u8; BROADCAST_SECRET_LEN]);

impl BroadcastSecret {
    /// Builds a `BroadcastSecret` from exactly `BROADCAST_SECRET_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EidError> {
        let array: [u8; BROADCAST_SECRET_LEN] =
            bytes.try_into().map_err(|_| EidError::WrongLength {
                expected: BROADCAST_SECRET_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self(array))
    }

    /// Derives the bootstrap secret from an account identifier (ADR-0018).
    pub fn bootstrap(account_id: &[u8]) -> Self {
        let bytes = blake3::derive_key(BOOTSTRAP_CONTEXT, account_id);
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; BROADCAST_SECRET_LEN] {
        &self.0
    }

    /// Derives the 8-byte EID for `window` using `blake3::derive_key` (ADR-0018).
    pub fn eid(&self, window: EidWindow) -> Eid {
        let mut key_material = [0u8; BROADCAST_SECRET_LEN + 8];
        key_material[..BROADCAST_SECRET_LEN].copy_from_slice(&self.0);
        key_material[BROADCAST_SECRET_LEN..].copy_from_slice(&window.index().to_be_bytes());
        let derived = blake3::derive_key(EID_CONTEXT, &key_material);
        let mut eid_bytes = [0u8; EID_LEN];
        eid_bytes.copy_from_slice(&derived[..EID_LEN]);
        Eid(eid_bytes)
    }

    /// Matches `observed` against candidate EIDs in the `t-1`, `t`, and `t+1` windows.
    pub fn matches(&self, observed: &Eid, now: UnixTime) -> Option<EidWindow> {
        let t = EidWindow::containing(now).index();
        for offset in [-1, 0, 1] {
            let window = EidWindow::from_index(t.saturating_add(offset));
            if &self.eid(window) == observed {
                return Some(window);
            }
        }
        None
    }
}

impl fmt::Debug for BroadcastSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BroadcastSecret(<redacted>)")
    }
}

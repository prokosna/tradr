use std::fmt;
use std::path::PathBuf;

use super::atomic::write_atomic;

const COLLECTED_FILE: &str = "collected.json";

/// Why reading or writing remembered deliveries failed.
#[derive(Debug)]
pub enum PlacedError {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// Stored JSON did not match a JSON array of delivery identifiers.
    Malformed(String),
}

impl fmt::Display for PlacedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "placed deliveries storage error: {e}"),
            Self::Malformed(m) => write!(f, "placed deliveries record is unreadable: {m}"),
        }
    }
}

impl std::error::Error for PlacedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Malformed(_) => None,
        }
    }
}

/// Tracks delivery identifiers placed locally whose acknowledgements remain in doubt.
#[derive(Debug, Clone)]
pub struct PlacedDeliveries {
    dir: PathBuf,
}

impl PlacedDeliveries {
    /// Builds a tracker rooted at the given directory without touching the filesystem.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Reports whether the delivery identifier has been placed locally.
    pub fn contains(&self, id: &str) -> Result<bool, PlacedError> {
        let ids = self.read_ids()?;
        Ok(ids.iter().any(|existing| existing == id))
    }

    /// Persists a delivery identifier so future passes acknowledge without redownload.
    pub fn remember(&self, id: &str) -> Result<(), PlacedError> {
        let mut ids = self.read_ids()?;
        if ids.iter().any(|existing| existing == id) {
            return Ok(());
        }
        ids.push(id.to_string());
        self.write_ids(&ids)
    }

    /// Removes a delivery identifier after its acknowledgement lands.
    pub fn forget(&self, id: &str) -> Result<(), PlacedError> {
        let mut ids = self.read_ids()?;
        let initial_len = ids.len();
        ids.retain(|existing| existing != id);
        if ids.len() == initial_len {
            return Ok(());
        }
        self.write_ids(&ids)
    }

    /// Drops remembered deliveries no longer waiting in the Brokr inbox.
    pub fn retain_listed(&self, listed: &[&str]) -> Result<(), PlacedError> {
        let mut ids = self.read_ids()?;
        let initial_len = ids.len();
        ids.retain(|existing| listed.iter().any(|l| l == existing));
        if ids.len() == initial_len {
            return Ok(());
        }
        self.write_ids(&ids)
    }

    fn path(&self) -> PathBuf {
        self.dir.join(COLLECTED_FILE)
    }

    fn read_ids(&self) -> Result<Vec<String>, PlacedError> {
        let path = self.path();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let ids: Vec<String> = serde_json::from_slice(&bytes)
                    .map_err(|e| PlacedError::Malformed(e.to_string()))?;
                Ok(ids)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(PlacedError::Io(e)),
        }
    }

    fn write_ids(&self, ids: &[String]) -> Result<(), PlacedError> {
        let bytes = serde_json::to_vec(ids).map_err(|e| PlacedError::Malformed(e.to_string()))?;
        write_atomic(&self.path(), &bytes).map_err(PlacedError::Io)
    }
}

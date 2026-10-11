use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

/// Origin mechanism for a file arriving on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceivedHow {
    /// Delivered directly by a remote peer.
    Sent,
    /// Fetched explicitly from another device's folder.
    Downloaded,
}

/// A persisted entry recording an arrived file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedRow {
    /// Monotonically increasing identifier ordering the arrival.
    pub id: u64,
    /// Destination path relative to the receive folder.
    pub path: String,
    /// Identity of the device that provided the file.
    pub device_id: String,
    /// Human-readable name of the peer device at arrival time.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Arrival time as Unix epoch seconds.
    pub received_at: u64,
    /// How the file reached this device.
    pub how: ReceivedHow,
}

/// Uncommitted arrival details waiting to be assigned an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReceived {
    /// Destination path relative to the receive folder.
    pub path: String,
    /// Identity of the device that provided the file.
    pub device_id: String,
    /// Human-readable name of the peer device at arrival time.
    pub device_name: Option<String>,
    /// Arrival time as Unix epoch seconds.
    pub received_at: u64,
    /// How the file reached this device.
    pub how: ReceivedHow,
}

/// Why reading or writing the received history journal failed.
#[derive(Debug)]
pub enum ReceivedHistoryError {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// Stored JSON did not match a valid received rows record.
    Malformed(String),
}

impl fmt::Display for ReceivedHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "received history storage error: {e}"),
            Self::Malformed(m) => write!(f, "received history record is unreadable: {m}"),
        }
    }
}

impl std::error::Error for ReceivedHistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Malformed(_) => None,
        }
    }
}

/// Thread-safe persistent journal of arrived files.
pub struct ReceivedHistory {
    file_path: PathBuf,
    lock: Mutex<()>,
}

impl ReceivedHistory {
    /// Builds a received history tracker rooted at the application data directory.
    pub fn new(app_data_dir: impl Into<PathBuf>) -> Self {
        Self {
            file_path: app_data_dir.into().join("received.json"),
            lock: Mutex::new(()),
        }
    }

    /// Persists new arrivals in order, assigning strictly ascending identifiers.
    pub fn record(&self, rows: Vec<NewReceived>) -> Result<(), ReceivedHistoryError> {
        let _guard = self.lock();
        if rows.is_empty() {
            return Ok(());
        }
        let mut existing = self.read_raw_rows()?;
        let start_id = existing.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        for (id, new_row) in (start_id..).zip(rows) {
            existing.push(ReceivedRow {
                id,
                path: new_row.path,
                device_id: new_row.device_id,
                device_name: new_row.device_name,
                received_at: new_row.received_at,
                how: new_row.how,
            });
        }
        let bytes = serde_json::to_vec(&existing)
            .map_err(|e| ReceivedHistoryError::Malformed(e.to_string()))?;
        crate::atomic::write_atomic(&self.file_path, &bytes).map_err(ReceivedHistoryError::Io)
    }

    /// Returns all recorded arrivals ordered newest first by descending identifier.
    pub fn rows(&self) -> Result<Vec<ReceivedRow>, ReceivedHistoryError> {
        let _guard = self.lock();
        let mut rows = self.read_raw_rows()?;
        rows.sort_by_key(|r| std::cmp::Reverse(r.id));
        Ok(rows)
    }

    /// Clears all recorded arrivals by overwriting the store with an empty record.
    pub fn clear(&self) -> Result<(), ReceivedHistoryError> {
        let _guard = self.lock();
        crate::atomic::write_atomic(&self.file_path, b"[]").map_err(ReceivedHistoryError::Io)
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        match self.lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn read_raw_rows(&self) -> Result<Vec<ReceivedRow>, ReceivedHistoryError> {
        match std::fs::read(&self.file_path) {
            Ok(bytes) => {
                let rows: Vec<ReceivedRow> = serde_json::from_slice(&bytes)
                    .map_err(|e| ReceivedHistoryError::Malformed(e.to_string()))?;
                Ok(rows)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(ReceivedHistoryError::Io(e)),
        }
    }
}

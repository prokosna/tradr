use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tradr_core::{Clock, DeviceId, UnixTime};
use tradr_identity::SystemClock;

use super::api::{OutboxEntry, OutboxState};
use super::send::SentDelivery;

const DELIVERIES_FILE: &str = "deliveries.json";
const MAX_TEMP_ATTEMPTS: u32 = 100;
const THIRTY_DAYS_SECS: i64 = 30 * 24 * 3600;
const SIXTY_DAYS_SECS: i64 = 60 * 24 * 3600;

/// Why reading, writing, or parsing the sent deliveries journal failed.
#[derive(Debug)]
pub enum OutboxError {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// Stored JSON did not match the expected schema or contained invalid fields.
    Malformed(String),
}

impl fmt::Display for OutboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "outbox storage error: {e}"),
            Self::Malformed(m) => write!(f, "outbox records are unreadable: {m}"),
        }
    }
}

impl std::error::Error for OutboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Malformed(_) => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SentRecordWire {
    id: String,
    recipient_device_id: String,
    names: Vec<String>,
    sent_at: i64,
    #[serde(default)]
    state: Option<OutboxState>,
    #[serde(default)]
    collected_at: Option<i64>,
}

/// A record of a sent delivery persisted in the local journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentRecord {
    /// The delivery identifier assigned by the Brokr.
    pub id: String,
    /// The recipient device identifier.
    pub recipient_device_id: DeviceId,
    /// The file names carried in the delivery.
    pub names: Vec<String>,
    /// When the delivery was handed to the Brokr.
    pub sent_at: UnixTime,
    /// The last observed state from the Brokr, if recorded.
    pub state: Option<OutboxState>,
    /// Millisecond collection timestamp from the Brokr, if recorded.
    pub collected_at: Option<i64>,
}

impl SentRecord {
    /// The delivery identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The recipient device identifier.
    pub fn recipient(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// The recipient device identifier.
    pub fn recipient_device_id(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// The file names carried in the delivery.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// When the delivery was handed to the Brokr.
    pub fn sent_at(&self) -> UnixTime {
        self.sent_at
    }
}

/// The status of a locally recorded delivery evaluated against current Brokr state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryStatus {
    /// The delivery identifier.
    pub id: String,
    /// The recipient device identifier.
    pub recipient_device_id: DeviceId,
    /// The file names carried in the delivery.
    pub names: Vec<String>,
    /// When the delivery was sent locally.
    pub sent_at: UnixTime,
    /// The delivery state: waiting, delivered, or expired.
    pub state: OutboxState,
    /// Millisecond collection timestamp from the Brokr, if delivered.
    pub collected_at: Option<i64>,
}

impl DeliveryStatus {
    /// The delivery identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The recipient device identifier.
    pub fn recipient(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// The recipient device identifier.
    pub fn recipient_device_id(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// The file names carried in the delivery.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// When the delivery was sent locally.
    pub fn sent_at(&self) -> UnixTime {
        self.sent_at
    }

    /// The delivery state.
    pub fn state(&self) -> OutboxState {
        self.state
    }

    /// Millisecond collection timestamp if delivered.
    pub fn collected_at(&self) -> Option<i64> {
        self.collected_at
    }
}

fn create_temp_sibling(path: &Path) -> Result<(std::fs::File, PathBuf), OutboxError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".tmp-{}-{count}", std::process::id()));
        let temp = path.with_file_name(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => return Ok((file, temp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(OutboxError::Io(e)),
        }
    }
    Err(OutboxError::Io(std::io::Error::other(
        "no fresh temporary file name was free",
    )))
}

/// A local record of sent deferred deliveries persisted to `deliveries.json`.
pub struct SentDeliveries {
    dir: PathBuf,
    entries: Vec<SentRecord>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl fmt::Debug for SentDeliveries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentDeliveries")
            .field("dir", &self.dir)
            .field("entries", &self.entries)
            .finish()
    }
}

impl SentDeliveries {
    /// Loads the sent deliveries journal from `dir`.
    pub fn load(dir: &Path) -> Result<Self, OutboxError> {
        Self::load_with_clock(dir, Arc::new(SystemClock))
    }

    /// Loads the sent deliveries journal from `dir` using the given clock.
    pub fn load_with_clock(
        dir: &Path,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, OutboxError> {
        let path = dir.join(DELIVERIES_FILE);
        let entries = match std::fs::read(&path) {
            Ok(bytes) => {
                let wires: Vec<SentRecordWire> = serde_json::from_slice(&bytes)
                    .map_err(|e| OutboxError::Malformed(e.to_string()))?;
                let mut records = Vec::with_capacity(wires.len());
                for w in wires {
                    let recipient_device_id = w
                        .recipient_device_id
                        .parse::<DeviceId>()
                        .map_err(|e| OutboxError::Malformed(e.to_string()))?;
                    records.push(SentRecord {
                        id: w.id,
                        recipient_device_id,
                        names: w.names,
                        sent_at: UnixTime::from_secs(w.sent_at),
                        state: w.state,
                        collected_at: w.collected_at,
                    });
                }
                records
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(OutboxError::Io(e)),
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            entries,
            clock,
        })
    }

    /// Constructs a journal manager for `dir`, loading any existing file.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, OutboxError> {
        Self::load(dir.as_ref())
    }

    /// Replaces the clock used for expiry checks.
    pub fn with_clock(mut self, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// All sent delivery records in the journal.
    pub fn all(&self) -> &[SentRecord] {
        &self.entries
    }

    /// Records a new delivery and atomically persists the journal, pruning old records.
    pub fn record(
        &mut self,
        id: impl Into<String>,
        recipient_device_id: DeviceId,
        names: Vec<String>,
        sent_at: UnixTime,
    ) -> Result<(), OutboxError> {
        let now_secs = sent_at.as_secs().max(self.clock.now().as_secs());
        self.entries.retain(|r| {
            if let Some(collected_at_ms) = r.collected_at {
                let collected_at_secs = collected_at_ms / 1000;
                if now_secs.saturating_sub(collected_at_secs) > THIRTY_DAYS_SECS {
                    return false;
                }
            }
            if r.state == Some(OutboxState::Delivered)
                && now_secs.saturating_sub(r.sent_at.as_secs()) > THIRTY_DAYS_SECS
            {
                return false;
            }
            if now_secs.saturating_sub(r.sent_at.as_secs()) > SIXTY_DAYS_SECS {
                return false;
            }
            true
        });

        self.entries.push(SentRecord {
            id: id.into(),
            recipient_device_id,
            names,
            sent_at,
            state: Some(OutboxState::Waiting),
            collected_at: None,
        });

        self.save()
    }

    /// Records a completed `SentDelivery` at the given timestamp.
    pub fn record_delivery(
        &mut self,
        delivery: &SentDelivery,
        sent_at: UnixTime,
    ) -> Result<(), OutboxError> {
        self.record(
            delivery.id.clone(),
            delivery.recipient,
            delivery.names.clone(),
            sent_at,
        )
    }

    /// Merges local records with Brokr outbox responses using the ambient clock.
    pub fn merge_with(&self, outbox: &[OutboxEntry]) -> Vec<DeliveryStatus> {
        self.merge_with_at(outbox, self.clock.now())
    }

    /// Merges local records with Brokr outbox responses evaluated at `now`.
    pub fn merge_with_at(&self, outbox: &[OutboxEntry], now: UnixTime) -> Vec<DeliveryStatus> {
        self.entries
            .iter()
            .map(|record| {
                if let Some(entry) = outbox.iter().find(|e| e.id == record.id) {
                    DeliveryStatus {
                        id: record.id.clone(),
                        recipient_device_id: record.recipient_device_id,
                        names: record.names.clone(),
                        sent_at: record.sent_at,
                        state: entry.state,
                        collected_at: entry.collected_at,
                    }
                } else {
                    let elapsed = now.as_secs().saturating_sub(record.sent_at.as_secs());
                    let state = if elapsed > THIRTY_DAYS_SECS {
                        OutboxState::Expired
                    } else {
                        OutboxState::Waiting
                    };
                    DeliveryStatus {
                        id: record.id.clone(),
                        recipient_device_id: record.recipient_device_id,
                        names: record.names.clone(),
                        sent_at: record.sent_at,
                        state,
                        collected_at: None,
                    }
                }
            })
            .collect()
    }

    /// Updates internal cached delivery states according to the current Brokr outbox.
    pub fn update_states(&mut self, outbox: &[OutboxEntry]) {
        let statuses = self.merge_with(outbox);
        for status in statuses {
            if let Some(record) = self.entries.iter_mut().find(|r| r.id == status.id) {
                record.state = Some(status.state);
                record.collected_at = status.collected_at;
            }
        }
    }

    fn save(&self) -> Result<(), OutboxError> {
        std::fs::create_dir_all(&self.dir).map_err(OutboxError::Io)?;
        let path = self.dir.join(DELIVERIES_FILE);
        let wires: Vec<SentRecordWire> = self
            .entries
            .iter()
            .map(|r| SentRecordWire {
                id: r.id.clone(),
                recipient_device_id: r.recipient_device_id.to_string(),
                names: r.names.clone(),
                sent_at: r.sent_at.as_secs(),
                state: r.state,
                collected_at: r.collected_at,
            })
            .collect();
        let bytes =
            serde_json::to_vec_pretty(&wires).map_err(|e| OutboxError::Malformed(e.to_string()))?;
        let (mut file, temp) = create_temp_sibling(&path)?;
        let written = file.write_all(&bytes).and_then(|()| file.sync_all());
        drop(file);
        let result = written
            .and_then(|()| std::fs::rename(&temp, &path))
            .map_err(OutboxError::Io);
        if result.is_err() {
            let remove_result = std::fs::remove_file(&temp);
            if let Err(cleanup_err) = remove_result {
                eprintln!("outbox: failed to clean up temp file: {cleanup_err}");
            }
        }
        result
    }
}

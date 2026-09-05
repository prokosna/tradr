//! BLE proximity discovery source and advertising traits (docs/03, ADR-0019).
//! ScanReport uses ScanReportError rather than BleError so BleError retains only radio failure variants.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use tradr_core::{
    BoxFuture, Candidate, Clock, DiscoveryError, DiscoveryEvent, DiscoverySource, Monotonic,
    ObservationId, ObservationKey, ObservationKeyError, PeerObservation, SourceId, TransportId,
};

use crate::advertisement::{Advertisement, SERVICE_DATA_LEN};
use crate::eid::BroadcastSecret;

/// The discovery source identifier for BLE proximity discovery.
pub const BLE_SOURCE_ID: SourceId = SourceId::new("ble");

// Declared locally rather than imported from tradr-transport, which this
// crate may not depend on (rule B2).
const BLE_GATT: TransportId = TransportId::new("ble-gatt");

/// The time after which an unrefreshed BLE observation is considered lost.
pub const BLE_OBSERVATION_TTL_SECS: u64 = 30;

/// An error from a BLE adapter, scanner, or advertiser.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleError {
    /// The platform or radio does not support the requested operation.
    Unsupported,
    /// Permission to use the Bluetooth adapter was denied.
    PermissionDenied,
    /// The Bluetooth adapter is turned off or unavailable.
    AdapterUnavailable,
    /// An underlying I/O error occurred.
    Io(std::io::ErrorKind),
    /// The source or scanner is closed and will produce no further reports.
    Closed,
}

impl fmt::Display for BleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "BLE operation is unsupported"),
            Self::PermissionDenied => write!(f, "BLE permission denied"),
            Self::AdapterUnavailable => write!(f, "BLE adapter unavailable"),
            Self::Io(kind) => write!(f, "BLE I/O error: {kind}"),
            Self::Closed => write!(f, "BLE source is closed"),
        }
    }
}

impl std::error::Error for BleError {}

/// An error constructing a `ScanReport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanReportError {
    /// The handle was invalid according to observation key rules.
    InvalidHandle(ObservationKeyError),
    /// The service data payload was not `SERVICE_DATA_LEN` bytes.
    WrongLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
}

impl fmt::Display for ScanReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle(e) => write!(f, "invalid scan report handle: {e}"),
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} service data bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for ScanReportError {}

/// A report from a BLE scanner carrying a peripheral handle and service data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    handle: String,
    service_data: [u8; SERVICE_DATA_LEN],
}

impl ScanReport {
    /// Validates the handle against `ObservationKey` rules and checks service data length.
    pub fn new(handle: &str, service_data: &[u8]) -> Result<Self, ScanReportError> {
        let key = ObservationKey::new(handle).map_err(ScanReportError::InvalidHandle)?;
        if service_data.len() != SERVICE_DATA_LEN {
            return Err(ScanReportError::WrongLength {
                expected: SERVICE_DATA_LEN,
                actual: service_data.len(),
            });
        }
        let mut data = [0u8; SERVICE_DATA_LEN];
        data.copy_from_slice(service_data);
        Ok(Self {
            handle: key.as_str().to_string(),
            service_data: data,
        })
    }

    /// The peripheral handle reported by the radio.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The 10-byte service data payload.
    pub fn service_data(&self) -> &[u8] {
        &self.service_data
    }
}

/// Advertises the Tradr BLE proximity payload (docs/03, ADR-0019).
pub trait BleAdvertiser: Send {
    /// Starts advertising the 10-byte service data payload.
    fn start(
        &mut self,
        service_data: [u8; SERVICE_DATA_LEN],
    ) -> BoxFuture<'_, Result<(), BleError>>;

    /// Stops advertising.
    fn stop(&mut self) -> BoxFuture<'_, Result<(), BleError>>;
}

/// Scans for Tradr BLE advertisements (docs/03, ADR-0019).
pub trait BleScanner: Send {
    /// Yields the next scan report observed by the radio.
    fn next_report(&mut self) -> BoxFuture<'_, Result<ScanReport, BleError>>;
}

/// Supplies broadcast secrets currently held by the device (docs/03).
pub trait BroadcastSecrets: Send {
    /// Returns the broadcast secrets currently held.
    fn secrets(&self) -> Vec<BroadcastSecret>;
}

// Tracks observation state and emission time for a peripheral handle.
struct TrackedHandle {
    last_seen: Monotonic,
    last_observation: PeerObservation,
}

/// A `DiscoverySource` driving a `BleScanner` and matching against `BroadcastSecrets`.
pub struct BleSource {
    scanner: Box<dyn BleScanner>,
    secrets: Box<dyn BroadcastSecrets>,
    clock: Box<dyn Clock + Send + Sync>,
    tracked: BTreeMap<ObservationKey, TrackedHandle>,
    pending_events: VecDeque<DiscoveryEvent>,
}

impl BleSource {
    /// Creates a new `BleSource` wrapping the scanner, secrets provider, and clock.
    pub fn new(
        scanner: Box<dyn BleScanner>,
        secrets: Box<dyn BroadcastSecrets>,
        clock: Box<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            scanner,
            secrets,
            clock,
            tracked: BTreeMap::new(),
            pending_events: VecDeque::new(),
        }
    }
}

// Narrows a BleError to DiscoveryError at the source boundary (docs/03).
fn narrow_ble_error(err: BleError) -> DiscoveryError {
    match err {
        BleError::Closed => DiscoveryError::Closed,
        BleError::Unsupported => DiscoveryError::Io(std::io::ErrorKind::Unsupported),
        BleError::PermissionDenied => DiscoveryError::Io(std::io::ErrorKind::PermissionDenied),
        BleError::AdapterUnavailable => DiscoveryError::Io(std::io::ErrorKind::NotConnected),
        BleError::Io(kind) => DiscoveryError::Io(kind),
    }
}

impl DiscoverySource for BleSource {
    fn id(&self) -> SourceId {
        BLE_SOURCE_ID
    }

    fn next_event(&mut self) -> BoxFuture<'_, Result<DiscoveryEvent, DiscoveryError>> {
        Box::pin(async move {
            loop {
                if let Some(event) = self.pending_events.pop_front() {
                    return Ok(event);
                }

                let report = self.scanner.next_report().await.map_err(narrow_ble_error)?;

                let now_mono = self.clock.monotonic_now();

                let expired: Vec<ObservationKey> = self
                    .tracked
                    .iter()
                    .filter(|(_, tracked)| {
                        now_mono.duration_since(tracked.last_seen).as_secs()
                            >= BLE_OBSERVATION_TTL_SECS
                    })
                    .map(|(key, _)| key.clone())
                    .collect();

                for key in expired {
                    self.tracked.remove(&key);
                    let id = ObservationId::new(BLE_SOURCE_ID, key);
                    self.pending_events.push_back(DiscoveryEvent::Lost(id));
                }

                let Ok(ad) = Advertisement::from_service_data(report.service_data()) else {
                    if let Some(event) = self.pending_events.pop_front() {
                        return Ok(event);
                    }
                    continue;
                };

                let secrets = self.secrets.secrets();
                let now_wall = self.clock.now();
                let eid = ad.eid();
                let matched = secrets.iter().any(|s| s.matches(&eid, now_wall).is_some());
                if !matched {
                    if let Some(event) = self.pending_events.pop_front() {
                        return Ok(event);
                    }
                    continue;
                }

                let key = ObservationKey::new(report.handle())
                    .expect("handle validated on ScanReport construction");
                let candidate = Candidate::new(BLE_GATT, report.handle())
                    .expect("handle validated on ScanReport construction");
                let id = ObservationId::new(BLE_SOURCE_ID, key.clone());
                let observation =
                    PeerObservation::new(id, vec![candidate]).with_capabilities(ad.capabilities());

                if let Some(tracked) = self.tracked.get_mut(&key) {
                    if tracked.last_observation == observation {
                        tracked.last_seen = now_mono;
                        if let Some(event) = self.pending_events.pop_front() {
                            return Ok(event);
                        }
                        continue;
                    }
                    tracked.last_seen = now_mono;
                    tracked.last_observation = observation.clone();
                } else {
                    self.tracked.insert(
                        key,
                        TrackedHandle {
                            last_seen: now_mono,
                            last_observation: observation.clone(),
                        },
                    );
                }

                self.pending_events
                    .push_back(DiscoveryEvent::Observed(observation));

                if let Some(event) = self.pending_events.pop_front() {
                    return Ok(event);
                }
            }
        })
    }
}

//! The Known Devices registry (docs/13-deferred-delivery.md, "Where the
//! trust lives" and "The device side"). Stores devices this installation has
//! met through a direct, verified handshake, used to address Deferred
//! Deliveries when peers are offline.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tradr_core::{
    DeviceId, DisplayName, PUBLIC_KEY_POINT_LEN, PublicIdentity, PublicKeyPoint, TrustTier,
    UnixTime,
};

/// The format version written to disk.
const KNOWN_DEVICES_VERSION: u32 = 1;

/// The maximum number of attempts to find an unused temporary file name.
const MAX_TEMP_ATTEMPTS: usize = 10_000;

/// A device previously encountered through a direct, verified handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDevice {
    device_id: DeviceId,
    identity: PublicIdentity,
    display_name: Option<DisplayName>,
    tier: TrustTier,
    last_seen: UnixTime,
}

impl KnownDevice {
    /// Builds a `KnownDevice` with the specified device ID, public identity,
    /// optional display name, trust tier, and last-seen timestamp.
    pub fn new(
        device_id: DeviceId,
        identity: PublicIdentity,
        display_name: Option<DisplayName>,
        tier: TrustTier,
        last_seen: UnixTime,
    ) -> Self {
        Self {
            device_id,
            identity,
            display_name,
            tier,
            last_seen,
        }
    }

    /// The permanent identifier of this device.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The public identity (signing and agreement public keys) of this device.
    pub fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// The display name published by this device, if known.
    pub fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    /// The trust tier assigned to this device.
    pub fn tier(&self) -> TrustTier {
        self.tier
    }

    /// When this device was last seen directly.
    pub fn last_seen(&self) -> UnixTime {
        self.last_seen
    }

    // Builds the on-disk record representation of this device.
    fn to_record(&self) -> KnownDeviceRecord {
        KnownDeviceRecord {
            device_id: self.device_id.to_string(),
            identity_pub: encode_hex(self.identity.identity_pub().as_bytes()),
            agreement_pub: encode_hex(self.identity.agreement_pub().as_bytes()),
            display_name: self.display_name.as_ref().map(|n| n.as_str().to_string()),
            tier: match self.tier {
                TrustTier::SameAccount => "same-account".to_string(),
                TrustTier::Linked => "linked".to_string(),
                TrustTier::NearbyEphemeral => "nearby-ephemeral".to_string(),
                TrustTier::Rejected => "rejected".to_string(),
            },
            last_seen: self.last_seen.as_secs(),
        }
    }
}

/// The result of recording a device in `KnownDevices`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The device was not previously in the registry.
    New,
    /// The device was already present and its public keys match what was stored.
    Refreshed,
    /// The device was already present but its identity or agreement key differed.
    KeysChanged,
}

/// An error from the Known Devices registry.
#[non_exhaustive]
#[derive(Debug)]
pub enum KnownDevicesError {
    /// The registry file was not valid JSON, a field was missing or
    /// malformed, or a key was not a valid SEC-1 public key point.
    Malformed(String),
    /// The file declared a format version this build does not understand.
    UnknownVersion(u32),
    /// A record's stored `DeviceId` does not equal the ID derived from
    /// its identity key.
    MismatchedDeviceId {
        /// The Device ID derived from the identity key.
        expected: DeviceId,
        /// The Device ID found in the record.
        found: DeviceId,
    },
    /// The record's trust tier is not allowed in this registry. Only
    /// `SameAccount` and `Linked` devices are ever stored.
    InvalidTier(TrustTier),
    /// Persisting failed, and removing the temporary file left behind
    /// also failed.
    CleanupFailed {
        /// The original error from the write or rename.
        original: std::io::Error,
        /// The error from attempting to remove the temporary file.
        cleanup: std::io::Error,
    },
    /// An I/O error reading or writing the registry file.
    Io(std::io::Error),
}

impl fmt::Display for KnownDevicesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "known devices registry is malformed: {reason}"),
            Self::UnknownVersion(v) => write!(f, "unknown known devices registry version: {v}"),
            Self::MismatchedDeviceId { expected, found } => write!(
                f,
                "record device id {found} does not match derived device id {expected}"
            ),
            Self::InvalidTier(tier) => write!(
                f,
                "trust tier {tier:?} cannot be stored in known devices registry"
            ),
            Self::CleanupFailed { original, cleanup } => write!(
                f,
                "{original}, and removing the temporary file left behind also failed: {cleanup}"
            ),
            Self::Io(source) => write!(f, "known devices registry i/o error: {source}"),
        }
    }
}

impl std::error::Error for KnownDevicesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::CleanupFailed { original, .. } => Some(original),
            Self::Malformed(_)
            | Self::UnknownVersion(_)
            | Self::MismatchedDeviceId { .. }
            | Self::InvalidTier(_) => None,
        }
    }
}

/// The on-disk serialization of one device.
#[derive(Debug, Serialize, Deserialize)]
struct KnownDeviceRecord {
    device_id: String,
    identity_pub: String,
    agreement_pub: String,
    #[serde(default)]
    display_name: Option<String>,
    tier: String,
    last_seen: i64,
}

/// The entire file `known-devices.json` holds.
#[derive(Debug, Serialize, Deserialize)]
struct KnownDevicesFile {
    version: u32,
    devices: Vec<KnownDeviceRecord>,
}

/// A persisted registry of devices met directly and verified.
#[derive(Debug)]
pub struct KnownDevices {
    path: PathBuf,
    devices: Vec<KnownDevice>,
}

impl KnownDevices {
    /// Loads the registry at `path`. A missing file produces an empty registry;
    /// malformed records, unknown versions, or mismatched device IDs are
    /// returned as errors.
    pub fn load(path: &Path) -> Result<Self, KnownDevicesError> {
        let raw = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(KnownDevicesError::Io(source)),
        };

        let Some(bytes) = raw else {
            return Ok(Self {
                path: path.to_path_buf(),
                devices: Vec::new(),
            });
        };

        let file: KnownDevicesFile = serde_json::from_slice(&bytes)
            .map_err(|source| KnownDevicesError::Malformed(source.to_string()))?;

        if file.version != KNOWN_DEVICES_VERSION {
            return Err(KnownDevicesError::UnknownVersion(file.version));
        }

        let mut devices = Vec::with_capacity(file.devices.len());
        for record in file.devices {
            let record_device_id = record
                .device_id
                .parse::<DeviceId>()
                .map_err(|source| KnownDevicesError::Malformed(source.to_string()))?;

            let identity_bytes = decode_hex_exact::<PUBLIC_KEY_POINT_LEN>(&record.identity_pub)
                .map_err(KnownDevicesError::Malformed)?;
            let identity_pub = PublicKeyPoint::from_bytes(&identity_bytes)
                .map_err(|source| KnownDevicesError::Malformed(source.to_string()))?;

            let derived_id =
                DeviceId::from_identity_digest(blake3::hash(identity_pub.as_bytes()).as_bytes());
            if record_device_id != derived_id {
                return Err(KnownDevicesError::MismatchedDeviceId {
                    expected: derived_id,
                    found: record_device_id,
                });
            }

            let agreement_bytes = decode_hex_exact::<PUBLIC_KEY_POINT_LEN>(&record.agreement_pub)
                .map_err(KnownDevicesError::Malformed)?;
            let agreement_pub = PublicKeyPoint::from_bytes(&agreement_bytes)
                .map_err(|source| KnownDevicesError::Malformed(source.to_string()))?;

            let identity = PublicIdentity::new(identity_pub, agreement_pub, derived_id);

            let display_name = match record.display_name {
                Some(name) => Some(
                    DisplayName::new(&name)
                        .map_err(|source| KnownDevicesError::Malformed(source.to_string()))?,
                ),
                None => None,
            };

            let tier = match record.tier.as_str() {
                "same-account" | "SameAccount" => TrustTier::SameAccount,
                "linked" | "Linked" => TrustTier::Linked,
                "nearby-ephemeral" | "NearbyEphemeral" => {
                    return Err(KnownDevicesError::InvalidTier(TrustTier::NearbyEphemeral));
                }
                "rejected" | "Rejected" => {
                    return Err(KnownDevicesError::InvalidTier(TrustTier::Rejected));
                }
                other => {
                    return Err(KnownDevicesError::Malformed(format!(
                        "invalid or unrecognized trust tier: {other}"
                    )));
                }
            };

            let last_seen = UnixTime::from_secs(record.last_seen);

            if devices
                .iter()
                .any(|d: &KnownDevice| d.device_id == record_device_id)
            {
                return Err(KnownDevicesError::Malformed(format!(
                    "device id {record_device_id} appears more than once"
                )));
            }

            devices.push(KnownDevice {
                device_id: record_device_id,
                identity,
                display_name,
                tier,
                last_seen,
            });
        }

        devices.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.device_id.cmp(&b.device_id))
        });

        Ok(Self {
            path: path.to_path_buf(),
            devices,
        })
    }

    /// Looks up a known device by its `DeviceId`.
    pub fn get(&self, device_id: &DeviceId) -> Option<&KnownDevice> {
        self.devices.iter().find(|d| &d.device_id == device_id)
    }

    /// Every known device, sorted by `last_seen` newest first.
    pub fn all(&self) -> &[KnownDevice] {
        &self.devices
    }

    /// Inserts or replaces a device entry and persists the updated registry.
    ///
    /// Refuses a `tier` of `NearbyEphemeral` or `Rejected` without modifying
    /// in-memory state or the on-disk file.
    pub fn record(&mut self, device: KnownDevice) -> Result<RecordOutcome, KnownDevicesError> {
        if device.tier != TrustTier::SameAccount && device.tier != TrustTier::Linked {
            return Err(KnownDevicesError::InvalidTier(device.tier));
        }

        let existing_index = self
            .devices
            .iter()
            .position(|d| d.device_id == device.device_id);

        let outcome = match existing_index {
            None => RecordOutcome::New,
            Some(idx) => {
                let existing = &self.devices[idx];
                let same_keys = existing.identity.identity_pub() == device.identity.identity_pub()
                    && existing.identity.agreement_pub() == device.identity.agreement_pub();
                if same_keys {
                    RecordOutcome::Refreshed
                } else {
                    RecordOutcome::KeysChanged
                }
            }
        };

        let mut prospective = self.devices.clone();
        if let Some(idx) = existing_index {
            prospective[idx] = device;
        } else {
            prospective.push(device);
        }

        prospective.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.device_id.cmp(&b.device_id))
        });

        self.persist(&prospective)?;
        self.devices = prospective;
        Ok(outcome)
    }

    /// Updates and persists the display name of an existing device entry.
    pub fn set_display_name(
        &mut self,
        device_id: &DeviceId,
        display_name: Option<DisplayName>,
    ) -> Result<bool, KnownDevicesError> {
        let Some(idx) = self.devices.iter().position(|d| &d.device_id == device_id) else {
            return Ok(false);
        };

        if self.devices[idx].display_name == display_name {
            return Ok(false);
        }

        let mut prospective = self.devices.clone();
        prospective[idx].display_name = display_name;

        self.persist(&prospective)?;
        self.devices = prospective;
        Ok(true)
    }

    // Writes `devices` to `self.path` via a temporary file renamed over the
    // destination, removing the temporary file if write or rename fails.
    fn persist(&self, devices: &[KnownDevice]) -> Result<(), KnownDevicesError> {
        let file = KnownDevicesFile {
            version: KNOWN_DEVICES_VERSION,
            devices: devices.iter().map(KnownDevice::to_record).collect(),
        };

        let json = serde_json::to_vec_pretty(&file)
            .map_err(|source| KnownDevicesError::Malformed(source.to_string()))?;

        let dir = match self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(d) => d,
            None => Path::new("."),
        };
        fs::create_dir_all(dir).map_err(KnownDevicesError::Io)?;

        let (mut temp_file, temp_path) =
            create_fresh_temp_file(dir).map_err(KnownDevicesError::Io)?;

        use std::io::Write;
        let written = temp_file
            .write_all(&json)
            .and_then(|()| temp_file.sync_all());
        drop(temp_file);
        if let Err(source) = written {
            return Err(fail_and_cleanup(&temp_path, source));
        }

        fs::rename(&temp_path, &self.path).map_err(|source| fail_and_cleanup(&temp_path, source))
    }
}

// Encodes a byte slice as lowercase hexadecimal characters.
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Decodes a hexadecimal string into an exact array of `N` bytes.
fn decode_hex_exact<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!(
            "expected {} hex characters for key, got {}",
            N * 2,
            s.len()
        ));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &s[i * 2..i * 2 + 2];
        let b0 = pair.as_bytes()[0];
        let b1 = pair.as_bytes()[1];
        if !b0.is_ascii_hexdigit() || !b1.is_ascii_hexdigit() {
            return Err(format!("invalid hex character in '{pair}'"));
        }
        *byte = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

// Creates a fresh temporary file using `create_new` to avoid collisions.
fn create_fresh_temp_file(dir: &Path) -> Result<(fs::File, PathBuf), std::io::Error> {
    static NEXT: AtomicU64 = AtomicU64::new(0);

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let candidate = dir.join(format!(
            ".tmp-known-devices-{}-{unique}",
            std::process::id()
        ));

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);

        match opts.open(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        }
    }
    Err(std::io::Error::other(
        "could not find a fresh temporary file name",
    ))
}

// Removes a temporary file after a failed write or rename, preserving both errors.
fn fail_and_cleanup(temp_path: &Path, original: std::io::Error) -> KnownDevicesError {
    match fs::remove_file(temp_path) {
        Ok(()) => KnownDevicesError::Io(original),
        Err(cleanup) => KnownDevicesError::CleanupFailed { original, cleanup },
    }
}

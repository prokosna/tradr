//! Thread-safe Known Devices registry and recorder for handshake completion (docs/13, "Where the trust lives").

use std::path::Path;
use std::sync::Mutex;

use tradr_core::{DeviceId, DisplayName, PublicIdentity, TrustTier, UnixTime};
use tradr_identity::{KnownDevice, KnownDevices, KnownDevicesError, RecordOutcome};

/// Records devices met through a verified direct handshake.
pub trait KnownDeviceRecorder: Send + Sync {
    /// Records a verified direct peer encounter.
    fn record(&self, identity: &PublicIdentity, tier: TrustTier, seen_at: UnixTime);
}

/// Thread-safe wrapper around the persistent Known Devices registry.
#[derive(Debug)]
pub struct KnownDevicesStore {
    inner: Mutex<KnownDevices>,
}

impl KnownDevicesStore {
    /// Opens or creates the Known Devices registry at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KnownDevicesError> {
        let registry = KnownDevices::load(path.as_ref())?;
        Ok(Self {
            inner: Mutex::new(registry),
        })
    }

    /// Takes a snapshot of all known devices, ordered by last seen newest first.
    pub fn snapshot(&self) -> Vec<KnownDevice> {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.all().to_vec()
    }

    /// Updates and persists the display name of an existing device entry.
    pub fn set_display_name(
        &self,
        device_id: &DeviceId,
        display_name: Option<DisplayName>,
    ) -> Result<bool, KnownDevicesError> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.set_display_name(device_id, display_name)
    }
}

impl KnownDeviceRecorder for KnownDevicesStore {
    fn record(&self, identity: &PublicIdentity, tier: TrustTier, seen_at: UnixTime) {
        if tier != TrustTier::SameAccount && tier != TrustTier::Linked {
            return;
        }

        let device_id = identity.device_id();
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let display_name = guard
            .get(&device_id)
            .and_then(|d| d.display_name().cloned());
        let device = KnownDevice::new(device_id, identity.clone(), display_name, tier, seen_at);

        match guard.record(device) {
            Ok(RecordOutcome::KeysChanged) => {
                eprintln!("known devices: public keys changed for device {device_id}");
            }
            Err(e) => {
                eprintln!("known devices: failed to persist device {device_id}: {e}");
            }
            Ok(RecordOutcome::New) | Ok(RecordOutcome::Refreshed) => {}
        }
    }
}

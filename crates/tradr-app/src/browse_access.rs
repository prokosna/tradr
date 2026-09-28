use std::collections::HashMap;
use std::sync::Mutex;

use tradr_core::DeviceId;

/// Remembers per authenticated device whether it is permitted to browse and modify this device's folder.
#[derive(Debug, Default)]
pub struct BrowseAccess {
    allowed: Mutex<HashMap<DeviceId, bool>>,
}

impl BrowseAccess {
    /// Starts with no recorded devices.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records access permission for a device, replacing any earlier grant.
    pub fn record(&self, device: DeviceId, allowed: bool) {
        self.allowed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(device, allowed);
    }

    /// Whether the device has been recorded as allowed, returning false if unknown.
    pub fn allowed(&self, device: DeviceId) -> bool {
        self.allowed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&device)
            .copied()
            .unwrap_or(false)
    }
}

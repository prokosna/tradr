//! Device Key custody and storage ladder traversal.

use std::path::PathBuf;
use std::sync::Arc;

use tradr_core::{
    Backing, KeyStore, PublicIdentity, Rng, SecretStore, SoftwareReason, StorageLevel,
};
use tradr_identity::{SoftwareKeyStore, select_rung_index};
use tradr_secrets::FileStore;
#[cfg(target_os = "linux")]
use tradr_secrets::SecretServiceStore;

/// The slot every rung of the storage ladder uses for the Device Key.
pub const DEVICE_KEY_SLOT: &str = "device-key";

/// An opened Device Key and the storage rung it was selected on.
pub struct DeviceIdentity {
    public_identity: PublicIdentity,
    key_store: Arc<dyn KeyStore>,
    secret_store: Arc<dyn SecretStore + Send + Sync>,
}

impl DeviceIdentity {
    /// The device's public identity.
    pub fn public_identity(&self) -> PublicIdentity {
        self.public_identity.clone()
    }

    /// The opened key store, for TLS and cryptographic handshakes.
    pub fn key_store(&self) -> Arc<dyn KeyStore> {
        Arc::clone(&self.key_store)
    }

    /// The storage rung holding this device's key and secrets.
    pub fn secret_store(&self) -> Arc<dyn SecretStore + Send + Sync> {
        Arc::clone(&self.secret_store)
    }

    /// Where the key is held, for displaying whether hardware backing was achieved.
    pub fn backing(&self) -> Backing {
        self.key_store.backing()
    }

    /// The storage level of the rung holding the key.
    pub fn storage_level(&self) -> StorageLevel {
        self.secret_store.level()
    }
}

/// Builds the storage ladder over `keys_dir`, highest rung first.
pub fn platform_ladder(keys_dir: PathBuf) -> Vec<Arc<dyn SecretStore + Send + Sync>> {
    let file_rung: Arc<dyn SecretStore + Send + Sync> = Arc::new(FileStore::new(keys_dir));

    // Secret Service is a Linux D-Bus interface; there is nothing on the
    // other end of it on any other platform, so the rung exists only there
    // (docs/05-security.md, "Key storage").
    #[cfg(target_os = "linux")]
    let secret_service_rung = SecretServiceStore::open();

    // A rung that is absent is skipped by never joining the ladder at all
    // (docs/05-security.md, "Descending the Linux ladder"), which is why this
    // pushes conditionally rather than filling a fixed-size array. Rungs are owned
    // rather than borrowed so the selected one can be kept beside the KeyStore it opened.
    let mut ladder: Vec<Arc<dyn SecretStore + Send + Sync>> = Vec::with_capacity(2);
    #[cfg(target_os = "linux")]
    match secret_service_rung {
        Ok(rung) => ladder.push(Arc::new(rung)),
        // One line so that a headless machine with no Secret Service does
        // not get a paragraph on every start.
        Err(e) => eprintln!("device-identity: secret service unavailable, using file: {e}"),
    }
    ladder.push(file_rung);
    ladder
}

/// Searches `ladder` for the Device Key and opens it on the rung that answers.
pub fn open_device_identity(
    ladder: &[Arc<dyn SecretStore + Send + Sync>],
    rng: &dyn Rng,
) -> Result<DeviceIdentity, String> {
    let borrowed: Vec<&dyn SecretStore> = ladder
        .iter()
        .map(|rung| rung.as_ref() as &dyn SecretStore)
        .collect();
    let index = select_rung_index(&borrowed, DEVICE_KEY_SLOT).map_err(|e| e.to_string())?;
    let secret_store = ladder
        .get(index)
        .cloned()
        .ok_or_else(|| "selected rung index out of range".to_string())?;

    let key_store = SoftwareKeyStore::open(secret_store.as_ref(), DEVICE_KEY_SLOT, rng)
        .map_err(|e| e.to_string())?;
    let public_identity = key_store.public_identity().map_err(|e| e.to_string())?;

    Ok(DeviceIdentity {
        public_identity,
        key_store: Arc::new(key_store),
        secret_store,
    })
}

/// Splits a `Backing` into what is rendered and why, for a caller that shows it.
pub fn describe_backing(backing: Backing) -> (&'static str, Option<String>) {
    match backing {
        Backing::Hardware => ("hardware", None),
        Backing::Software(reason) => ("software", Some(software_reason_name(reason).to_string())),
    }
}

/// The name a person reads for one rung of the ladder.
pub fn storage_level_name(level: StorageLevel) -> &'static str {
    match level {
        StorageLevel::SecretService => "secret service",
        StorageLevel::File => "file",
    }
}

fn software_reason_name(reason: SoftwareReason) -> &'static str {
    match reason {
        SoftwareReason::PlatformHasNoSecureElement => "platform has no secure element",
        SoftwareReason::NoTpmPresent => "no TPM present",
        SoftwareReason::KeymintTooOld => "secure element predates this operation",
        SoftwareReason::NoSecretService => "no Secret Service session available",
    }
}

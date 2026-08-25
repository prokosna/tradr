//! Opens the Device Key store once, at startup, and exposes what it holds
//! to the frontend (WI-M0-014a). The first thing the product actually
//! does: every piece of key custody existed already, but nothing had
//! ever called any of it.

use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime, State};

use tradr_core::{Backing, KeyStore, SecretStore, SoftwareReason, StorageLevel};
use tradr_identity::{OsRng, SoftwareKeyStore, select_rung};
use tradr_secrets::FileStore;

/// The slot every rung of the storage ladder uses for the Device Key.
const DEVICE_KEY_SLOT: &str = "device-key";

/// What the frontend needs to render the device's identity: the public
/// `DeviceId`, where the key is held, and why when it is not hardware.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceIdentitySnapshot {
    device_id: String,
    backing: String,
    reason: Option<String>,
    storage: String,
}

/// The outcome of opening the key store at startup, kept as managed state
/// so a failure here can be shown in a window instead of aborting `setup`
/// and leaving no window at all.
pub struct IdentityState(pub Result<DeviceIdentitySnapshot, String>);

/// Builds the storage ladder, opens the Device Key through it, and turns
/// the result into a snapshot the frontend can render. Runs once, from
/// the plugin's `setup` hook. Never panics: every failure becomes the
/// `Err` side of the returned `Result`.
pub fn open_identity<R: Runtime>(app: &AppHandle<R>) -> Result<DeviceIdentitySnapshot, String> {
    let keys_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the app data directory: {e}"))?
        .join("keys");

    let file_rung = FileStore::new(keys_dir);
    // The two rungs above the file are WI-M0-007e; today's ladder holds
    // only this one, but it is walked through select_rung rather than
    // used directly, so those rungs are a one-line addition later.
    let ladder: [&dyn SecretStore; 1] = [&file_rung];
    let rung = select_rung(&ladder, DEVICE_KEY_SLOT).map_err(|e| e.to_string())?;

    let key_store =
        SoftwareKeyStore::open(rung, DEVICE_KEY_SLOT, &OsRng).map_err(|e| e.to_string())?;
    let identity = key_store.public_identity().map_err(|e| e.to_string())?;

    let (backing, reason) = describe_backing(key_store.backing());

    Ok(DeviceIdentitySnapshot {
        device_id: identity.device_id().to_string(),
        backing: backing.to_string(),
        reason,
        storage: storage_level_name(rung.level()).to_string(),
    })
}

// Splits a Backing into the two fields the frontend renders separately:
// "hardware" or "software" needs no argument, while a software fallback
// carries a reason a plain string cannot lose to translation drift.
fn describe_backing(backing: Backing) -> (&'static str, Option<String>) {
    match backing {
        Backing::Hardware => ("hardware", None),
        Backing::Software(reason) => ("software", Some(software_reason_name(reason).to_string())),
    }
}

// StorageLevel and SoftwareReason carry no Display of their own; these
// two are only for the strings this module hands to the frontend.
fn software_reason_name(reason: SoftwareReason) -> &'static str {
    match reason {
        SoftwareReason::PlatformHasNoSecureElement => "platform has no secure element",
        SoftwareReason::NoTpmPresent => "no TPM present",
        SoftwareReason::KeymintTooOld => "secure element predates this operation",
        SoftwareReason::NoSecretService => "no Secret Service session available",
    }
}

fn storage_level_name(level: StorageLevel) -> &'static str {
    match level {
        StorageLevel::SecretService => "secret service",
        StorageLevel::KernelKeyring => "kernel keyring",
        StorageLevel::File => "file",
    }
}

/// Called once from `setup`: opens the key store, logs its `DeviceId` and
/// backing (both public values; nothing else about a `KeyStore` is ever
/// logged), and returns the state to be managed by the app.
pub fn init_identity_state<R: Runtime>(app: &AppHandle<R>) -> IdentityState {
    let outcome = open_identity(app);
    match &outcome {
        Ok(snapshot) => println!(
            "WI-M0-014a device-identity: device_id={} backing={}",
            snapshot.device_id, snapshot.backing
        ),
        Err(e) => println!("WI-M0-014a device-identity: failed to open key store: {e}"),
    }
    IdentityState(outcome)
}

/// Returns the device's identity, as opened once at startup. The `Err`
/// side is the failure's `Display`, so the frontend has something true to
/// show even when the key store could not be opened.
#[tauri::command]
pub fn device_identity(state: State<'_, IdentityState>) -> Result<DeviceIdentitySnapshot, String> {
    state.0.clone()
}

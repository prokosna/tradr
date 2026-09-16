//! Opens the Device Key store once, at startup, and exposes what it holds
//! to the frontend (WI-M0-014a). Delegates key storage ladder assembly and
//! Device Key opening to tradr-app (WI-M8-011).

use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Runtime, State};

use tradr_app::identity::{
    DeviceIdentity, describe_backing, open_device_identity, platform_ladder, storage_level_name,
};
use tradr_core::{KeyStore, PublicIdentity, SecretStore};
use tradr_identity::OsRng;

/// What the frontend needs to render the device's identity: the public
/// `DeviceId`, where the key is held, and why when it is not hardware.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceIdentitySnapshot {
    device_id: String,
    backing: String,
    reason: Option<String>,
    storage: String,
}

// What a successful open of the key store yields: the snapshot for the
// frontend and the opened DeviceIdentity.
type OpenedIdentity = (DeviceIdentitySnapshot, DeviceIdentity);

/// The outcome of opening the key store at startup, kept as managed state
/// so a failure here can be shown in a window instead of aborting `setup`.
/// Carries the `DeviceIdentity` the Device Key was selected on, so a Link
/// Secret can go on the same rung with no second selection made anywhere.
pub struct IdentityState(Result<OpenedIdentity, String>);

impl IdentityState {
    /// The device's own `PublicIdentity`, as opened once at startup. Used
    /// by `sign_in` to compute the Attestation nonce.
    pub fn public_identity(&self) -> Result<PublicIdentity, String> {
        self.0
            .as_ref()
            .map(|(_, identity)| identity.public_identity())
            .map_err(|e| e.clone())
    }

    /// The device's opened key store, passed to transports for TLS and handshakes.
    pub fn key_store(&self) -> Result<Arc<dyn KeyStore>, String> {
        self.0
            .as_ref()
            .map(|(_, identity)| identity.key_store())
            .map_err(|e| e.clone())
    }

    /// The rung of the storage ladder the Device Key was found on, for a
    /// Link Secret to be stored on the same rung.
    pub fn secret_store(&self) -> Result<Arc<dyn SecretStore + Send + Sync>, String> {
        self.0
            .as_ref()
            .map(|(_, identity)| identity.secret_store())
            .map_err(|e| e.clone())
    }
}

// Builds the storage ladder, opens the Device Key through it, and turns
// the result into a snapshot plus the opened DeviceIdentity.
fn open_identity<R: Runtime>(app: &AppHandle<R>) -> Result<OpenedIdentity, String> {
    let dir = crate::paths::app_data_dir(app)?;
    let keys_dir = tradr_app::paths::device_keys_dir(&dir);

    let ladder = platform_ladder(keys_dir);
    let identity = open_device_identity(&ladder, &OsRng)?;

    let (backing, reason) = describe_backing(identity.backing());
    let snapshot = DeviceIdentitySnapshot {
        device_id: identity.public_identity().device_id().to_string(),
        backing: backing.to_string(),
        reason,
        storage: storage_level_name(identity.storage_level()).to_string(),
    };

    Ok((snapshot, identity))
}

/// Called once from `setup`: opens the key store, logs its `DeviceId` and
/// backing (both public values; nothing else about a `KeyStore` is ever
/// logged), and returns the state to be managed by the app.
pub fn init_identity_state<R: Runtime>(app: &AppHandle<R>) -> IdentityState {
    let outcome = open_identity(app);
    match &outcome {
        Ok((snapshot, _)) => println!(
            "device-identity: device_id={} backing={}",
            snapshot.device_id, snapshot.backing
        ),
        Err(e) => println!("device-identity: failed to open key store: {e}"),
    }
    IdentityState(outcome)
}

/// Returns the device's identity, as opened once at startup. The `Err`
/// side is the failure's `Display`, so the frontend has something true to
/// show even when the key store could not be opened.
#[tauri::command]
pub fn device_identity(state: State<'_, IdentityState>) -> Result<DeviceIdentitySnapshot, String> {
    state
        .0
        .as_ref()
        .map(|(snapshot, _)| snapshot.clone())
        .map_err(|e| e.clone())
}

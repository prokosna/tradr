//! Opens the Device Key store once, at startup, and exposes what it holds
//! to the frontend (WI-M0-014a). The first thing the product actually
//! does: every piece of key custody existed already, but nothing had
//! ever called any of it.

use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime, State};

use tradr_core::{Backing, KeyStore, PublicIdentity, SecretStore, SoftwareReason, StorageLevel};
use tradr_identity::{OsRng, SoftwareKeyStore, select_rung_index};
use tradr_secrets::FileStore;
#[cfg(target_os = "linux")]
use tradr_secrets::SecretServiceStore;

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

// What a successful open of the key store yields: the snapshot for the
// frontend, the PublicIdentity, the KeyStore, and the SecretStore the
// Device Key was selected on (docs/05, "One rung per device").
type OpenedIdentity = (
    DeviceIdentitySnapshot,
    PublicIdentity,
    Arc<dyn KeyStore>,
    Arc<dyn SecretStore + Send + Sync>,
);

/// The outcome of opening the key store at startup, kept as managed state
/// so a failure here can be shown in a window instead of aborting `setup`.
/// Carries the `PublicIdentity`, `KeyStore`, and the `SecretStore` the
/// Device Key was selected on, so a Link Secret can go on the same rung
/// with no second selection made anywhere (docs/05, "One rung per device").
pub struct IdentityState(Result<OpenedIdentity, String>);

impl IdentityState {
    /// The device's own `PublicIdentity`, as opened once at startup. Used
    /// by `sign_in` to compute the Attestation nonce.
    pub fn public_identity(&self) -> Result<PublicIdentity, String> {
        self.0
            .as_ref()
            .map(|(_, identity, _, _)| identity.clone())
            .map_err(|e| e.clone())
    }

    /// The device's opened key store, passed to transports for TLS and handshakes.
    pub fn key_store(&self) -> Result<Arc<dyn KeyStore>, String> {
        self.0
            .as_ref()
            .map(|(_, _, store, _)| store.clone())
            .map_err(|e| e.clone())
    }

    /// The rung of the storage ladder the Device Key was found on, for a
    /// Link Secret to be stored on the same rung.
    pub fn secret_store(&self) -> Result<Arc<dyn SecretStore + Send + Sync>, String> {
        self.0
            .as_ref()
            .map(|(_, _, _, secrets)| secrets.clone())
            .map_err(|e| e.clone())
    }
}

// Builds the storage ladder, opens the Device Key through it, and turns
// the result into a snapshot plus the PublicIdentity it was built from.
// Runs once, from the plugin's setup hook. Never panics: every failure
// becomes the Err side of the returned Result.
fn open_identity<R: Runtime>(app: &AppHandle<R>) -> Result<OpenedIdentity, String> {
    let keys_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the app data directory: {e}"))?
        .join("keys");

    let file_rung: Arc<dyn SecretStore + Send + Sync> = Arc::new(FileStore::new(keys_dir));

    // Secret Service is a Linux D-Bus interface; there is nothing on the
    // other end of it anywhere else, so the rung exists only there
    // (docs/05-security.md, "Key storage"). macOS gets the file rung
    // today; a Keychain rung is M4.
    #[cfg(target_os = "linux")]
    let secret_service_rung = SecretServiceStore::open();

    // A rung that is absent is skipped by never joining the ladder at all
    // (docs/05-security.md, "Descending the Linux ladder"), which is why
    // this pushes conditionally rather than passing a fixed-size array.
    // Owned, not borrowed, so the selected rung can be kept beside the
    // KeyStore it opened rather than dropped with the ladder (docs/05).
    let mut ladder: Vec<Arc<dyn SecretStore + Send + Sync>> = Vec::with_capacity(2);
    #[cfg(target_os = "linux")]
    match secret_service_rung {
        Ok(rung) => ladder.push(Arc::new(rung)),
        // One line, so a headless machine without a Secret Service does
        // not get this on every start.
        Err(e) => eprintln!("device-identity: secret service unavailable, using file: {e}"),
    }
    ladder.push(file_rung);

    let borrowed: Vec<&dyn SecretStore> = ladder
        .iter()
        .map(|rung| rung.as_ref() as &dyn SecretStore)
        .collect();
    let index = select_rung_index(&borrowed, DEVICE_KEY_SLOT).map_err(|e| e.to_string())?;
    // The index came from searching `borrowed`, which was built from
    // `ladder` one-to-one, so it names a rung `ladder` holds.
    let secrets = Arc::clone(&ladder[index]);

    let key_store = SoftwareKeyStore::open(secrets.as_ref(), DEVICE_KEY_SLOT, &OsRng)
        .map_err(|e| e.to_string())?;
    let identity = key_store.public_identity().map_err(|e| e.to_string())?;

    let (backing, reason) = describe_backing(key_store.backing());

    let snapshot = DeviceIdentitySnapshot {
        device_id: identity.device_id().to_string(),
        backing: backing.to_string(),
        reason,
        storage: storage_level_name(secrets.level()).to_string(),
    };

    let key_store: Arc<dyn KeyStore> = Arc::new(key_store);
    Ok((snapshot, identity, key_store, secrets))
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
        StorageLevel::File => "file",
    }
}

/// Called once from `setup`: opens the key store, logs its `DeviceId` and
/// backing (both public values; nothing else about a `KeyStore` is ever
/// logged), and returns the state to be managed by the app.
pub fn init_identity_state<R: Runtime>(app: &AppHandle<R>) -> IdentityState {
    let outcome = open_identity(app);
    match &outcome {
        Ok((snapshot, _, _, _)) => println!(
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
        .map(|(snapshot, _, _, _)| snapshot.clone())
        .map_err(|e| e.clone())
}

//! Hands docs/05 step 6 the account list `AttestationPolicy::linked_accounts`
//! needs (DCR-074). Read off `tradr_identity::LinkRegistry` at each
//! classification and never captured once, so removing a Link takes
//! effect from the very next call. `PeerTrustState` is the precedent: a
//! `Result` built once at startup, reported through every later use.

use std::path::Path;
use std::sync::{Arc, Mutex};

use tauri::{AppHandle, Manager, Runtime};
use tradr_identity::{AccountId, LinkRegistry};

/// The outcome of loading this device's Link registry, kept as managed
/// state so a failed load reports the error on every use rather than
/// being silently read as empty, which would withdraw `TrustTier::Linked`
/// from every peer. A plain `std::sync::Mutex`, not `tokio::sync::Mutex`:
/// the link exchange's `record` closure is synchronous (DCR-076).
pub struct LinkRegistryState(Result<Arc<Mutex<LinkRegistry>>, String>);

impl LinkRegistryState {
    /// Loads the registry at `path`. A missing file is an empty registry
    /// (`LinkRegistry::load`'s own rule); a malformed one becomes this
    /// state's `Err`, named after `path` so the message says which file
    /// needs fixing.
    pub fn load(path: &Path) -> Self {
        let outcome = LinkRegistry::load(path)
            .map(|registry| Arc::new(Mutex::new(registry)))
            .map_err(|e| format!("link registry at {}: {e}", path.display()));
        Self(outcome)
    }

    /// The registry handle, cloned for a caller to lock and read.
    pub fn registry(&self) -> Result<Arc<Mutex<LinkRegistry>>, String> {
        self.0.clone()
    }

    /// Every account currently linked, read fresh from the registry on
    /// this call. Holds no copy of its own, so a Link removed between two
    /// calls is gone from the very next one.
    pub fn linked_accounts(&self) -> Result<Vec<AccountId>, String> {
        let registry = self.registry()?;
        let accounts = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .linked_accounts();
        Ok(accounts)
    }
}

/// Builds the `LinkRegistryState` to be managed by the app: `links.json`
/// beside `static-peers.json` in the app data directory. A path that
/// cannot be resolved becomes this state's `Err`, never a panic.
pub(crate) fn init_link_registry_state<R: Runtime>(app: &AppHandle<R>) -> LinkRegistryState {
    match app.path().app_data_dir() {
        Ok(dir) => LinkRegistryState::load(&dir.join("links.json")),
        Err(e) => LinkRegistryState(Err(format!(
            "could not resolve the app data directory: {e}"
        ))),
    }
}

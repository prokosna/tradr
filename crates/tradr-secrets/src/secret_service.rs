//! The Secret Service rung of the Linux storage ladder
//! (docs/05-security.md, "Key storage"): a D-Bus session-scoped
//! collection, looked up by attribute rather than by label. Never
//! unlocks anything -- a locked collection is read as a failed
//! operation (DCR-034, "A locked Secret Service is a rung that fails").

use std::collections::HashMap;

use secret_service::EncryptionType;
use secret_service::blocking::{Collection, SecretService};

use tradr_core::{SecretStore, SecretStoreError, StorageLevel};

/// Marks every item this store creates as Tradr's own, so a lookup by
/// attributes cannot be answered by an unrelated application's item that
/// happens to share a collection.
const APPLICATION_ATTRIBUTE: (&str, &str) = ("application", "com.tradr.app");

/// The attribute key a slot name is stored under.
const SLOT_ATTRIBUTE: &str = "slot";

fn backend_err(source: secret_service::Error) -> SecretStoreError {
    SecretStoreError::Backend(Box::new(source))
}

// The exact attribute set an item for `slot` carries: both the constant
// application tag and the slot itself, so a `replace` create only ever
// matches Tradr's own prior item for that slot, never a bystander's.
fn attributes_for(slot: &str) -> HashMap<&str, &str> {
    HashMap::from([
        (APPLICATION_ATTRIBUTE.0, APPLICATION_ATTRIBUTE.1),
        (SLOT_ATTRIBUTE, slot),
    ])
}

/// The Secret Service rung, reached over D-Bus (docs/05-security.md,
/// "Key storage"). Holds no `Collection`: one borrows the `Session`
/// inside `SecretService` by reference, so it cannot be stored alongside
/// it and is instead looked up fresh for each operation.
pub struct SecretServiceStore {
    service: SecretService<'static>,
}

impl SecretServiceStore {
    /// Connects to the session bus and confirms a Secret Service answers
    /// on it by reaching a collection, without unlocking it (DCR-034).
    /// Fails only when nothing answers at all: no session bus, or no
    /// Secret Service on it. A locked collection is still reached, so a
    /// lock never fails `open` -- only `store` and `load` see it.
    pub fn open() -> Result<Self, SecretStoreError> {
        let service = SecretService::connect(EncryptionType::Dh).map_err(backend_err)?;
        let store = Self { service };
        store.collection()?;
        Ok(store)
    }

    // Reaches the collection this store uses. Fetched fresh on every
    // call: see the struct's doc comment for why one is never kept in
    // `self`.
    fn collection(&self) -> Result<Collection<'_>, SecretStoreError> {
        self.service.get_any_collection().map_err(backend_err)
    }

    // A locked collection has not said whether it holds this device's
    // key (DCR-034), so this reports the lock as a failed read rather
    // than unlocking it or treating it as an empty one.
    fn ensure_unlocked(collection: &Collection<'_>) -> Result<(), SecretStoreError> {
        if collection.is_locked().map_err(backend_err)? {
            return Err(backend_err(secret_service::Error::Locked));
        }
        Ok(())
    }
}

impl SecretStore for SecretServiceStore {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let collection = self.collection()?;
        Self::ensure_unlocked(&collection)?;
        // `replace: true` matched against the same attribute set below is
        // what turns a second `store` into an update of the one item
        // rather than a second item competing for the same lookup.
        collection
            .create_item(
                &format!("Tradr {slot}"),
                attributes_for(slot),
                secret,
                true,
                "application/octet-stream",
            )
            .map_err(backend_err)?;
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        let collection = self.collection()?;
        Self::ensure_unlocked(&collection)?;
        let items = collection
            .search_items(attributes_for(slot))
            .map_err(backend_err)?;
        let Some(item) = items.into_iter().next() else {
            return Ok(None);
        };
        let secret = item.get_secret().map_err(backend_err)?;
        Ok(Some(secret))
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        let collection = self.collection()?;
        Self::ensure_unlocked(&collection)?;
        let items = collection
            .search_items(attributes_for(slot))
            .map_err(backend_err)?;
        for item in items {
            item.delete().map_err(backend_err)?;
        }
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::SecretService
    }
}

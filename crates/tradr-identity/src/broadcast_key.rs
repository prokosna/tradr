//! The persisted Account Broadcast Key registry (docs/11-account-linking.md,
//! "Distributing the Account Broadcast Key"). A Critical Module (CLAUDE.md
//! section 6): a rotation whose bytes do not change leaves a revoked device
//! matching every EID, and a key read back for another account leaks identity
//! across account boundaries.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tradr_core::{
    ACCOUNT_BROADCAST_KEY_LEN, AccountBroadcastKey, BroadcastKeyOffer, BroadcastKeyOfferError, Rng,
    RngError, SecretStore, SecretStoreError, UnixTime, next_generation,
};

use crate::attestation::AccountId;

/// The SecretStore slot holding the Account Broadcast Key.
pub const ACCOUNT_BROADCAST_KEY_SLOT: &str = "account-broadcast-key";

#[derive(Debug, Serialize, Deserialize)]
struct AccountBroadcastKeyRecord {
    account_iss: String,
    account_sub: String,
    generation: u32,
    created_at: i64,
}

/// An error from the Account Broadcast Key registry.
#[non_exhaustive]
#[derive(Debug)]
pub enum BroadcastKeyRegistryError {
    /// The record file was not valid JSON in the expected shape, or a stored key
    /// had an invalid length.
    Malformed(String),
    /// The record belongs to a different account than requested.
    WrongAccount,
    /// The record exists on disk but the secret store slot is empty.
    SecretMissing,
    /// The entropy source failed while drawing random bytes.
    Rng(RngError),
    /// The secret store failed during an operation.
    Secret(SecretStoreError),
    /// An offer was constructed with an invalid generation or creation time.
    Offer(BroadcastKeyOfferError),
    /// The record write failed and restoring the previous secret also failed.
    SecretRollbackFailed {
        /// Why the record write failed.
        persist: Box<BroadcastKeyRegistryError>,
        /// Why restoring the secret store failed.
        restore: SecretStoreError,
    },
    /// The registry file could not be read or written.
    Io(std::io::Error),
}

impl fmt::Display for BroadcastKeyRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => {
                write!(f, "account broadcast key registry is malformed: {reason}")
            }
            Self::WrongAccount => write!(f, "record belongs to a different account"),
            Self::SecretMissing => write!(f, "account broadcast key slot is empty"),
            Self::Rng(source) => write!(f, "entropy source error: {source}"),
            Self::Secret(source) => write!(f, "secret store error: {source}"),
            Self::Offer(source) => write!(f, "broadcast key offer error: {source}"),
            Self::SecretRollbackFailed { persist, restore } => write!(
                f,
                "{persist}, and rolling back the secret store also failed: {restore}"
            ),
            Self::Io(source) => write!(f, "account broadcast key registry i/o error: {source}"),
        }
    }
}

impl std::error::Error for BroadcastKeyRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Secret(source) => Some(source),
            Self::Rng(source) => Some(source),
            Self::Offer(source) => Some(source),
            Self::SecretRollbackFailed { persist, .. } => Some(persist.as_ref()),
            Self::Malformed(_) | Self::WrongAccount | Self::SecretMissing => None,
        }
    }
}

/// The Account Broadcast Key registry: manages the persisted key and metadata
/// for one account.
#[derive(Debug)]
pub struct BroadcastKeyRegistry {
    path: PathBuf,
    account: AccountId,
    generation: Option<u32>,
    created_at: Option<UnixTime>,
}

impl BroadcastKeyRegistry {
    /// Loads the registry at `path` for `account`.
    pub fn load(path: &Path, account: &AccountId) -> Result<Self, BroadcastKeyRegistryError> {
        let raw = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(BroadcastKeyRegistryError::Io(source)),
        };

        let Some(bytes) = raw else {
            return Ok(Self {
                path: path.to_path_buf(),
                account: account.clone(),
                generation: None,
                created_at: None,
            });
        };

        let record: AccountBroadcastKeyRecord = serde_json::from_slice(&bytes)
            .map_err(|source| BroadcastKeyRegistryError::Malformed(source.to_string()))?;

        if record.account_iss != account.iss() || record.account_sub != account.sub() {
            return Err(BroadcastKeyRegistryError::WrongAccount);
        }

        if record.generation == 0 {
            return Err(BroadcastKeyRegistryError::Malformed(
                "generation must be non-zero".to_string(),
            ));
        }

        if record.created_at <= 0 {
            return Err(BroadcastKeyRegistryError::Malformed(
                "created_at must be after the Unix epoch".to_string(),
            ));
        }

        Ok(Self {
            path: path.to_path_buf(),
            account: account.clone(),
            generation: Some(record.generation),
            created_at: Some(UnixTime::from_secs(record.created_at)),
        })
    }

    /// The account this registry was opened for.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The generation of the current key, if a record exists.
    pub fn generation(&self) -> Option<u32> {
        self.generation
    }

    /// When the current key was created, if a record exists.
    pub fn created_at(&self) -> Option<UnixTime> {
        self.created_at
    }

    /// Loads the current Account Broadcast Key offer from the secret store.
    pub fn offer(
        &self,
        secrets: &dyn SecretStore,
    ) -> Result<Option<BroadcastKeyOffer>, BroadcastKeyRegistryError> {
        let (Some(generation), Some(created_at)) = (self.generation, self.created_at) else {
            return Ok(None);
        };

        let stored = secrets
            .load(ACCOUNT_BROADCAST_KEY_SLOT)
            .map_err(BroadcastKeyRegistryError::Secret)?;

        let Some(bytes) = stored else {
            return Err(BroadcastKeyRegistryError::SecretMissing);
        };

        let key = AccountBroadcastKey::from_bytes(&bytes)
            .map_err(|source| BroadcastKeyRegistryError::Malformed(source.to_string()))?;

        // load refused generation == 0 and created_at <= 0, so offer construction cannot fail.
        let offer = BroadcastKeyOffer::new(key, generation, created_at)
            .expect("offer inputs were validated when the record was loaded");

        Ok(Some(offer))
    }

    /// Generates a fresh 32-byte key from `rng` and persists both halves.
    pub fn generate(
        &mut self,
        rng: &dyn Rng,
        now: UnixTime,
        secrets: &dyn SecretStore,
    ) -> Result<BroadcastKeyOffer, BroadcastKeyRegistryError> {
        let mut bytes = [0u8; ACCOUNT_BROADCAST_KEY_LEN];
        rng.fill_bytes(&mut bytes)
            .map_err(BroadcastKeyRegistryError::Rng)?;
        let key = AccountBroadcastKey::from_bytes(&bytes)
            .expect("ACCOUNT_BROADCAST_KEY_LEN bytes is an account broadcast key");
        let generation = next_generation(self.generation);
        let offer = BroadcastKeyOffer::new(key, generation, now)
            .map_err(BroadcastKeyRegistryError::Offer)?;
        self.adopt(&offer, secrets)?;
        Ok(offer)
    }

    /// Adopts a key offer supplied by a caller, persisting both halves.
    pub fn adopt(
        &mut self,
        offer: &BroadcastKeyOffer,
        secrets: &dyn SecretStore,
    ) -> Result<(), BroadcastKeyRegistryError> {
        let previous = secrets
            .load(ACCOUNT_BROADCAST_KEY_SLOT)
            .map_err(BroadcastKeyRegistryError::Secret)?;

        secrets
            .store(ACCOUNT_BROADCAST_KEY_SLOT, offer.key().as_bytes())
            .map_err(BroadcastKeyRegistryError::Secret)?;

        let record = AccountBroadcastKeyRecord {
            account_iss: self.account.iss().to_string(),
            account_sub: self.account.sub().to_string(),
            generation: offer.generation(),
            created_at: offer.created_at().as_secs(),
        };

        if let Err(persist_err) = persist(&self.path, &record) {
            let rollback_result = match previous {
                Some(prev_bytes) => secrets.store(ACCOUNT_BROADCAST_KEY_SLOT, &prev_bytes),
                None => secrets.remove(ACCOUNT_BROADCAST_KEY_SLOT),
            };
            return Err(match rollback_result {
                Ok(()) => persist_err,
                Err(restore_err) => BroadcastKeyRegistryError::SecretRollbackFailed {
                    persist: Box::new(persist_err),
                    restore: restore_err,
                },
            });
        }

        self.generation = Some(offer.generation());
        self.created_at = Some(offer.created_at());
        Ok(())
    }

    /// Discards both the secret and the record on disk.
    pub fn clear(path: &Path, secrets: &dyn SecretStore) -> Result<(), BroadcastKeyRegistryError> {
        secrets
            .remove(ACCOUNT_BROADCAST_KEY_SLOT)
            .map_err(BroadcastKeyRegistryError::Secret)?;

        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(BroadcastKeyRegistryError::Io(source)),
        }
    }
}

// Replacing the file by rename prevents readers from observing a partial write,
// leaving the record either fully committed to disk or completely absent.
fn persist(
    path: &Path,
    record: &AccountBroadcastKeyRecord,
) -> Result<(), BroadcastKeyRegistryError> {
    let json = serde_json::to_vec_pretty(record)
        .expect("an AccountBroadcastKeyRecord serializes to json without error");

    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir).map_err(BroadcastKeyRegistryError::Io)?;
    }

    let temp_path = temp_path_for(path);
    fs::write(&temp_path, &json).map_err(BroadcastKeyRegistryError::Io)?;
    if let Err(err) = fs::rename(&temp_path, path) {
        let _discard = fs::remove_file(&temp_path);
        return Err(BroadcastKeyRegistryError::Io(err));
    }
    Ok(())
}

// Staging in the target directory ensures the rename is same-filesystem and atomic.
fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

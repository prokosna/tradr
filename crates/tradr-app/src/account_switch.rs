//! Signing in as a different account: what counts as the previous account,
//! when the switch needs the user's word, and the record that outlives a
//! sign-out.

use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tradr_identity::AccountId;

use crate::atomic::{Access, write_atomic_with};
use crate::sign_in::{SignInState, VerifiedSignIn};

// Never holds an email: the issuer and subject are all that identify an account.
#[derive(Serialize, Deserialize)]
struct AccountRecord {
    iss: String,
    sub: String,
}

/// The account this device belonged to before this sign-in: the live
/// sign-in first, else the record a past run left.
pub fn previous_account(state: &SignInState, recorded: Option<AccountId>) -> Option<AccountId> {
    state.own_account().or(recorded)
}

/// Whether signing in as `new` must be confirmed first.
pub fn needs_confirmation(previous: Option<&AccountId>, new: &AccountId) -> bool {
    previous.is_some_and(|previous| previous != new)
}

/// Loads the account of record. A missing file is `None`; an unreadable or
/// malformed one is an error, never read as "no account".
pub fn load_account_of_record(path: &Path) -> Result<Option<AccountId>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "failed to read the account record at {}: {e}",
                path.display()
            ));
        }
    };
    let record: AccountRecord = serde_json::from_slice(&bytes)
        .map_err(|e| format!("the account record at {} is malformed: {e}", path.display()))?;
    Ok(Some(AccountId::new(&record.iss, &record.sub)))
}

/// Records `account` as the one this device belongs to, readable only by the owner.
pub fn keep_account_of_record(path: &Path, account: &AccountId) -> Result<(), String> {
    let record = AccountRecord {
        iss: account.iss().to_string(),
        sub: account.sub().to_string(),
    };
    let json = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    write_atomic_with(path, &json, Access::OwnerOnly).map_err(|e| {
        format!(
            "could not keep the account record at {}: {e}",
            path.display()
        )
    })
}

/// A verified sign-in waiting for the user to confirm or refuse the switch.
#[derive(Default)]
pub struct PendingSwitch {
    held: Mutex<Option<VerifiedSignIn>>,
}

impl PendingSwitch {
    // A poisoned mutex still holds a usable value; recovering it keeps one
    // panic from failing every later call.
    fn recover(&self) -> std::sync::MutexGuard<'_, Option<VerifiedSignIn>> {
        self.held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Holds `verified`, replacing any switch already waiting.
    pub fn hold(&self, verified: VerifiedSignIn) {
        *self.recover() = Some(verified);
    }

    /// Hands out the waiting switch, once.
    pub fn take(&self) -> Option<VerifiedSignIn> {
        self.recover().take()
    }

    /// Drops the waiting switch.
    pub fn discard(&self) {
        *self.recover() = None;
    }
}

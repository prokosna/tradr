//! The decision of which storage ladder rung holds a device's key
//! (docs/05-security.md, "Descending the Linux ladder"). A failed rung refuses
//! only when no lower rung holds a key, preventing minting over a hidden key
//! without blocking adoption of an existing one.

use std::fmt;

use tradr_core::{SecretStore, SecretStoreError, StorageLevel};

/// `select_rung` could not settle on a rung to use.
#[derive(Debug)]
pub enum LadderError {
    /// The ladder passed in had no rungs at all.
    NoRungs,
    /// A rung's `load` failed and no lower rung held a key to adopt.
    /// `level` names the highest rung that failed.
    RungFailed {
        level: StorageLevel,
        source: SecretStoreError,
    },
}

impl fmt::Display for LadderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRungs => write!(f, "storage ladder has no rungs"),
            Self::RungFailed { level, source } => {
                write!(
                    f,
                    "storage ladder rung {} failed: {source}",
                    level_name(*level)
                )
            }
        }
    }
}

impl std::error::Error for LadderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoRungs => None,
            Self::RungFailed { source, .. } => Some(source),
        }
    }
}

// StorageLevel carries no Display of its own; this is only for the message above.
fn level_name(level: StorageLevel) -> &'static str {
    match level {
        StorageLevel::SecretService => "Secret Service",
        StorageLevel::File => "file",
    }
}

/// Finds which rung of `ladder` holds a device's key, walking highest first
/// without calling `store`. A failed rung refuses only when no lower rung holds
/// a key, preventing minting over a hidden key while adopting an existing
/// one (docs/05-security.md, "Descending the Linux ladder"). If empty, returns `0`.
pub fn select_rung_index(ladder: &[&dyn SecretStore], slot: &str) -> Result<usize, LadderError> {
    if ladder.is_empty() {
        return Err(LadderError::NoRungs);
    }

    let mut first_failure = None;

    for (index, &rung) in ladder.iter().enumerate() {
        match rung.load(slot) {
            Ok(Some(_)) => return Ok(index),
            Ok(None) => {}
            Err(source) => {
                if first_failure.is_none() {
                    first_failure = Some(LadderError::RungFailed {
                        level: rung.level(),
                        source,
                    });
                }
            }
        }
    }

    match first_failure {
        Some(err) => Err(err),
        None => Ok(0),
    }
}

/// Finds which rung of `ladder` holds a device's key (docs/05-security.md,
/// "Descending the Linux ladder"). A thin wrapper over `select_rung_index`
/// so the two answers cannot drift apart; reading `ladder` back at the
/// index that index came from cannot be out of range.
pub fn select_rung<'a>(
    ladder: &[&'a dyn SecretStore],
    slot: &str,
) -> Result<&'a dyn SecretStore, LadderError> {
    let index = select_rung_index(ladder, slot)?;
    Ok(ladder[index])
}

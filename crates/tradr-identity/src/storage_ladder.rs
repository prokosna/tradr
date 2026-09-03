//! The pure decision of which rung of the Linux storage ladder holds a
//! device's key (docs/05-security.md, "Descending the Linux ladder"). The
//! two real backends, Secret Service and a `0600` file, are WI-M0-007d/e;
//! this module only walks whatever `SecretStore`s it is given.

use std::fmt;

use tradr_core::{SecretStore, SecretStoreError, StorageLevel};

/// `select_rung` could not settle on a rung to use.
#[derive(Debug)]
pub enum LadderError {
    /// The ladder passed in had no rungs at all.
    NoRungs,
    /// A rung's `load` returned `Err`, so the search stopped there rather
    /// than treating it as empty and reading past it. `level` names the
    /// rung that failed, not any rung below it.
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
/// and returning the position of the first whose `load(slot)` holds a
/// value, without calling `store`. A rung whose `load` errors stops the
/// search rather than being read as empty (docs/05-security.md,
/// "Descending the Linux ladder"). If every rung is empty, `0` is returned.
pub fn select_rung_index(ladder: &[&dyn SecretStore], slot: &str) -> Result<usize, LadderError> {
    if ladder.is_empty() {
        return Err(LadderError::NoRungs);
    }

    for (index, &rung) in ladder.iter().enumerate() {
        match rung.load(slot) {
            Ok(Some(_)) => return Ok(index),
            Ok(None) => continue,
            Err(source) => {
                return Err(LadderError::RungFailed {
                    level: rung.level(),
                    source,
                });
            }
        }
    }

    Ok(0)
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

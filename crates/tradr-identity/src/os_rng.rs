//! The real entropy source behind `SoftwareKeyStore` (WI-M0-014a). Lives
//! beside its only caller rather than in the composition root, so a
//! future move off Tauri (Change Drill D9) never puts an entropy source
//! in the set of files being rewritten.

use tradr_core::{Rng, RngError};

/// Draws randomness from the operating system via `getrandom`.
pub struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(buf).map_err(|e| RngError::Source(Box::new(e)))
    }
}

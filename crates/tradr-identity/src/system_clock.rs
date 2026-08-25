//! The real wall-clock and monotonic source behind staleness checks
//! (WI-M0-014b). Lives beside `verify_attestation`, its caller, for the
//! same reason `OsRng` lives beside `SoftwareKeyStore`: a future move off
//! Tauri (Change Drill D9) must never put a clock read in the set of
//! files being rewritten.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tradr_core::{Clock, Monotonic, UnixTime};

/// Reads the operating system's wall clock and monotonic clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTime {
        let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        UnixTime::from_secs(secs)
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(Instant::now())
    }
}

//! Layer 1's time abstraction (rule B6). No implementation lives here:
//! `SystemTime::now()` and any OS monotonic call belong to a Layer 3
//! `Clock` implementation, never to this crate, so tests can pin time
//! instead of racing the wall clock.

use std::fmt;
use std::time::{Duration, Instant};

/// Seconds since the Unix epoch, 1970-01-01T00:00:00Z UTC.
///
/// Kept distinct from `Monotonic` so wall-clock time (an Attestation's
/// `iat`, the 15-minute EID windows) and duration measurement can never
/// be mixed up at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(i64);

/// An error computing the time between two `UnixTime` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixTimeError {
    /// The argument passed as the earlier time is actually later than the
    /// receiver, so the elapsed duration would be negative.
    ArgumentIsLater,
}

impl fmt::Display for UnixTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArgumentIsLater => {
                write!(f, "the argument UnixTime is later than the receiver")
            }
        }
    }
}

impl std::error::Error for UnixTimeError {}

impl UnixTime {
    /// Builds a `UnixTime` from raw seconds since the Unix epoch.
    pub fn from_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Returns the raw seconds since the Unix epoch.
    pub fn as_secs(self) -> i64 {
        self.0
    }

    /// Returns the seconds elapsed from `earlier` to `self`. Errors rather
    /// than returning a negative or wrapped value when `earlier` is in
    /// fact later than `self`.
    pub fn elapsed_since(self, earlier: UnixTime) -> Result<u64, UnixTimeError> {
        if earlier.0 > self.0 {
            return Err(UnixTimeError::ArgumentIsLater);
        }
        // The check above guarantees self.0 >= earlier.0, so the
        // difference is non-negative and fits in a u64.
        Ok((self.0 - earlier.0) as u64)
    }
}

/// A monotonic time reading, distinct from `UnixTime` so the two kinds of
/// time cannot be confused. Never runs backwards, even across a wall-clock
/// step or adjustment. Carries a `std::time::Instant`, whose only
/// constructor reads the OS monotonic clock, a read that belongs to a
/// Layer 3 `Clock` implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Monotonic(Instant);

impl Monotonic {
    /// Wraps an `Instant` a `Clock` implementation already obtained.
    pub fn from_instant(instant: Instant) -> Self {
        Self(instant)
    }

    /// Returns the duration elapsed from `earlier` to `self`. Saturates to
    /// zero rather than panicking if `earlier` is later than `self`,
    /// matching `Instant::duration_since`.
    pub fn duration_since(self, earlier: Monotonic) -> Duration {
        self.0.duration_since(earlier.0)
    }
}

/// Wall-clock and monotonic time, kept as two methods because the design
/// needs both kinds and they must never be confused (rule B6).
pub trait Clock {
    /// The current wall-clock time, used for an Attestation's `iat` and
    /// the 15-minute EID windows.
    fn now(&self) -> UnixTime;

    /// The current monotonic reading, non-decreasing across calls on the
    /// same `Clock` even when the wall clock steps backwards.
    fn monotonic_now(&self) -> Monotonic;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_since_computes_the_gap_when_the_receiver_is_later() {
        let earlier = UnixTime::from_secs(100);
        let later = UnixTime::from_secs(142);

        assert_eq!(later.elapsed_since(earlier), Ok(42));
    }

    #[test]
    fn elapsed_since_is_zero_for_equal_times() {
        let t = UnixTime::from_secs(100);

        assert_eq!(t.elapsed_since(t), Ok(0));
    }

    #[test]
    fn elapsed_since_errors_when_the_argument_is_later_than_the_receiver() {
        let earlier = UnixTime::from_secs(100);
        let later = UnixTime::from_secs(142);

        assert_eq!(
            earlier.elapsed_since(later),
            Err(UnixTimeError::ArgumentIsLater)
        );
    }

    #[test]
    fn monotonic_duration_since_is_zero_for_equal_readings() {
        let reading = Monotonic::from_instant(Instant::now());

        assert_eq!(reading.duration_since(reading), Duration::ZERO);
    }

    #[test]
    fn monotonic_duration_since_reports_an_increasing_reading() {
        let earlier = Monotonic::from_instant(Instant::now());
        let later = Monotonic::from_instant(earlier.0 + Duration::from_millis(50));

        assert_eq!(later.duration_since(earlier), Duration::from_millis(50));
    }

    // A fake proves the trait is usable behind a reference, the shape a
    // composition root actually holds it in.
    struct FixedClock {
        wall: UnixTime,
        mono: Monotonic,
    }

    impl Clock for FixedClock {
        fn now(&self) -> UnixTime {
            self.wall
        }

        fn monotonic_now(&self) -> Monotonic {
            self.mono
        }
    }

    #[test]
    fn a_clock_implementation_can_be_called_through_the_trait() {
        let clock = FixedClock {
            wall: UnixTime::from_secs(1_000),
            mono: Monotonic::from_instant(Instant::now()),
        };
        let dyn_clock: &dyn Clock = &clock;

        assert_eq!(dyn_clock.now(), UnixTime::from_secs(1_000));
    }
}

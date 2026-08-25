//! Layer 1's randomness abstraction (rule B7). No implementation lives
//! here: an OS CSPRNG call belongs to a Layer 3 `Rng` implementation, never
//! to this crate, so tests can pin the bytes a caller receives.

use std::fmt;

/// A source of randomness, exposing one fallible method that fills a
/// caller-supplied buffer. Takes `&self` rather than `&mut self` so a
/// single instance can be shared. Deliberately has no method returning a
/// number in a range: the design does not use one.
pub trait Rng {
    /// Fills `buf` with random bytes, or reports why the source could not.
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError>;
}

/// An error obtaining randomness from an `Rng`.
#[derive(Debug)]
pub enum RngError {
    /// The underlying source failed; its own error is preserved.
    Source(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(e) => write!(f, "rng source failed: {e}"),
        }
    }
}

impl std::error::Error for RngError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(e) => Some(e.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake that writes a fixed byte, proving the trait is callable
    // through a shared reference and through a trait object.
    struct FixedRng {
        byte: u8,
    }

    impl Rng for FixedRng {
        fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
            buf.fill(self.byte);
            Ok(())
        }
    }

    #[test]
    fn an_rng_implementation_can_be_called_through_a_shared_reference() {
        let rng = FixedRng { byte: 0x42 };
        let dyn_rng: &dyn Rng = &rng;
        let mut buf = [0u8; 4];

        dyn_rng.fill_bytes(&mut buf).expect("fake never fails");

        assert_eq!(buf, [0x42, 0x42, 0x42, 0x42]);
    }

    #[test]
    fn rng_error_reports_its_source() {
        let err = RngError::Source("underlying failure".into());

        assert_eq!(err.to_string(), "rng source failed: underlying failure");
    }
}

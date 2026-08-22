//! How much a peer is trusted, settled during Attestation verification. See
//! `docs/05-security.md` and `proto/tradr/v1/control.proto`'s `TrustTier`.

/// The four real trust tiers a peer can hold once verified.
///
/// Ordered from least to most trusted, so `a >= b` reads "at least as
/// trusted as `b`". The wire's `TRUST_TIER_UNSPECIFIED` has no variant here:
/// an unspecified tier must never be treated as a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustTier {
    /// Failed authentication; every later request from this peer is denied.
    Rejected,
    /// An unknown peer, granted only while ephemeral receive mode is on.
    NearbyEphemeral,
    /// A device of a linked account.
    Linked,
    /// A device of the same account.
    SameAccount,
}

/// An error converting a wire `i32` to a `TrustTier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTierError {
    /// The wire value was `TRUST_TIER_UNSPECIFIED` (0), which grants nothing.
    Unspecified,
    /// The wire value matches no tier `control.proto` defines.
    Unknown(i32),
}

impl std::fmt::Display for TrustTierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "trust tier is unspecified"),
            Self::Unknown(value) => write!(f, "trust tier wire value {value} matches no tier"),
        }
    }
}

impl std::error::Error for TrustTierError {}

impl TryFrom<i32> for TrustTier {
    type Error = TrustTierError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Err(TrustTierError::Unspecified),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::NearbyEphemeral),
            3 => Ok(Self::Linked),
            4 => Ok(Self::SameAccount),
            other => Err(TrustTierError::Unknown(other)),
        }
    }
}

impl From<TrustTier> for i32 {
    fn from(tier: TrustTier) -> Self {
        match tier {
            TrustTier::Rejected => 1,
            TrustTier::NearbyEphemeral => 2,
            TrustTier::Linked => 3,
            TrustTier::SameAccount => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins the wire values against proto/tradr/v1/control.proto's TrustTier
    // enum, since this crate cannot depend on tradr-proto to check them.
    #[test]
    fn wire_values_match_control_proto() {
        assert_eq!(i32::from(TrustTier::Rejected), 1);
        assert_eq!(i32::from(TrustTier::NearbyEphemeral), 2);
        assert_eq!(i32::from(TrustTier::Linked), 3);
        assert_eq!(i32::from(TrustTier::SameAccount), 4);
    }

    #[test]
    fn try_from_round_trips_every_real_tier() {
        for tier in [
            TrustTier::Rejected,
            TrustTier::NearbyEphemeral,
            TrustTier::Linked,
            TrustTier::SameAccount,
        ] {
            let wire: i32 = tier.into();
            assert_eq!(TrustTier::try_from(wire), Ok(tier));
        }
    }

    #[test]
    fn ordering_expresses_at_least_this_much_trust() {
        assert!(TrustTier::SameAccount > TrustTier::Linked);
        assert!(TrustTier::Linked > TrustTier::NearbyEphemeral);
        assert!(TrustTier::NearbyEphemeral > TrustTier::Rejected);
    }

    #[test]
    fn try_from_rejects_the_unspecified_wire_value() {
        let result = TrustTier::try_from(0);

        assert_eq!(result, Err(TrustTierError::Unspecified));
    }

    #[test]
    fn try_from_rejects_a_value_no_tier_uses() {
        let result = TrustTier::try_from(99);

        assert_eq!(result, Err(TrustTierError::Unknown(99)));
    }
}

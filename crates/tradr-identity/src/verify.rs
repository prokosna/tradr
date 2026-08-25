//! The join: docs/05 "Who runs the seven steps" (DCR-025). Selects a
//! Provider Profile once and runs every step that depends on one -- the
//! `id_token` signature check and the classification that follows --
//! against that same value, rather than letting each pick its own. No
//! I/O: a cache miss is reported back rather than fetched, per DCR-022.

use std::fmt;

use tradr_core::{Clock, PublicKeyPoint, TrustTier};

use crate::attestation::{AttestationError, AttestationPolicy, classify_with_profile};
use crate::id_token::{TokenError, peek_issuer, verify_id_token};
use crate::jwks_cache::JwksCache;

/// The outcome of `verify_attestation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The Attestation checked out; the token's account earns this tier.
    Verified(TrustTier),
    /// The token names a `kid` the cache does not hold, and the refetch
    /// budget allows one fetch of this uri. Fetch it, `JwksCache::install`
    /// it, and call `verify_attestation` again.
    JwksNeeded {
        /// The `jwks_uri` of the profile the token's `iss` selected.
        jwks_uri: String,
    },
}

/// Why `verify_attestation` could not produce a `Verification`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The token itself was rejected: malformed, a disallowed algorithm, a
    /// bad signature, or an unknown `kid` with no refetch budget left.
    Token(TokenError),
    /// The token verified but failed classification: an unrecognised
    /// issuer, audience, nonce, staleness, or account check.
    Attestation(AttestationError),
    /// The cache passed in was built for a different `jwks_uri` than the
    /// one the token's issuer selects. Verifying against it would let one
    /// provider's keys vouch for another provider's token.
    CacheIsForAnotherProvider {
        /// The `jwks_uri` of the profile the token's `iss` selected.
        expected: String,
        /// The `jwks_uri` the cache passed in was actually built with.
        held: String,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(e) => write!(f, "{e}"),
            Self::Attestation(e) => write!(f, "{e}"),
            Self::CacheIsForAnotherProvider { expected, held } => write!(
                f,
                "cache is bound to {held}, but the token's issuer selects {expected}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Runs docs/05's seven steps against `token`, using `cache` for step 2's
/// keys and `identity_pub`/`agreement_pub` for step 4's nonce check. Does
/// no I/O: a `JwksNeeded` result names the uri to fetch and install via
/// `JwksCache::install` before calling this function again.
pub fn verify_attestation(
    policy: &AttestationPolicy,
    cache: &mut JwksCache,
    token: &str,
    identity_pub: &PublicKeyPoint,
    agreement_pub: &PublicKeyPoint,
    clock: &dyn Clock,
) -> Result<Verification, VerifyError> {
    // Step 1: read iss from an as-yet-unverified token. A malformed token
    // dies here, before a profile is selected and before the cache's
    // refetch budget is touched at all.
    let iss = peek_issuer(token).map_err(VerifyError::Token)?;

    // Step 1 continued: select the profile by an exact issuer match. An
    // unknown issuer must not be a way to make a device fetch anything, so
    // this runs before the cache is consulted.
    let profile = policy
        .profiles
        .iter()
        .find(|p| p.issuer == iss)
        .ok_or(VerifyError::Attestation(AttestationError::UnknownIssuer))?;

    // A cache built for one provider must never be trusted for another,
    // even when it happens to hold a key under the kid the token names.
    if cache.jwks_uri() != profile.jwks_uri {
        return Err(VerifyError::CacheIsForAnotherProvider {
            expected: profile.jwks_uri.clone(),
            held: cache.jwks_uri().to_string(),
        });
    }

    // Step 2: verify the signature under the same profile step 1 selected,
    // never a second selection.
    let claims = match verify_id_token(profile, cache.keys(), token) {
        Ok(claims) => claims,
        Err(TokenError::UnknownKeyId(kid)) => {
            return if cache.claim_refetch_for(&kid, clock.monotonic_now()) {
                Ok(Verification::JwksNeeded {
                    jwks_uri: profile.jwks_uri.clone(),
                })
            } else {
                Err(VerifyError::Token(TokenError::UnknownKeyId(kid)))
            };
        }
        Err(e) => return Err(VerifyError::Token(e)),
    };

    // Steps 3 through 6, against the same profile again.
    classify_with_profile(
        profile,
        policy,
        &claims,
        identity_pub,
        agreement_pub,
        clock.now(),
    )
    .map(Verification::Verified)
    .map_err(VerifyError::Attestation)
}

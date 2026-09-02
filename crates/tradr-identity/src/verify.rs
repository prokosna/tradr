//! The join: docs/05 "Who runs the seven steps" (DCR-025). Selects a
//! Provider Profile once and runs every step that depends on one -- the
//! `id_token` signature check and the classification that follows --
//! against that same value, rather than letting each pick its own. No
//! I/O: a cache miss is reported back rather than fetched, per DCR-022.

use std::fmt;

use tradr_core::{Clock, DeviceId, PublicKeyPoint, TrustTier};

use crate::attestation::{
    AccountId, AttestationError, AttestationPolicy, LinkPolicy, ProviderProfile, VerifiedClaims,
    check_claims, classify_with_profile,
};
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
    match verify_steps_one_and_two(policy.profiles, cache, token, clock)? {
        EarlyOutcome::JwksNeeded { jwks_uri } => Ok(Verification::JwksNeeded { jwks_uri }),
        EarlyOutcome::Claims { profile, claims } => {
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
    }
}

/// What steps 1 and 2 produced: either the profile they selected together
/// with the token's verified claims, or the `JwksNeeded` signal step 2's
/// refetch budget allowed. Shared between `verify_attestation` and
/// `verify_link_attestation` so profile selection and signature
/// verification stay one implementation rather than two (DCR-025).
enum EarlyOutcome<'a> {
    Claims {
        profile: &'a ProviderProfile,
        claims: VerifiedClaims,
    },
    JwksNeeded {
        jwks_uri: String,
    },
}

// Steps 1 and 2 of docs/05's seven: select the profile by an exact issuer
// match, confirm the cache is bound to that profile's jwks_uri, then verify
// the token's signature against the cache's keys. An unknown kid spends the
// cache's refetch budget rather than failing outright, per docs/05 "The
// token never chooses how it is verified".
fn verify_steps_one_and_two<'a>(
    profiles: &'a [ProviderProfile],
    cache: &mut JwksCache,
    token: &str,
    clock: &dyn Clock,
) -> Result<EarlyOutcome<'a>, VerifyError> {
    // Step 1: read iss from an as-yet-unverified token. A malformed token
    // dies here, before a profile is selected and before the cache's
    // refetch budget is touched at all.
    let iss = peek_issuer(token).map_err(VerifyError::Token)?;

    // Step 1 continued: select the profile by an exact issuer match. An
    // unknown issuer must not be a way to make a device fetch anything, so
    // this runs before the cache is consulted.
    let profile = profiles
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
    match verify_id_token(profile, cache.keys(), token) {
        Ok(claims) => Ok(EarlyOutcome::Claims { profile, claims }),
        Err(TokenError::UnknownKeyId(kid)) => {
            if cache.claim_refetch_for(&kid, clock.monotonic_now()) {
                Ok(EarlyOutcome::JwksNeeded {
                    jwks_uri: profile.jwks_uri.clone(),
                })
            } else {
                Err(VerifyError::Token(TokenError::UnknownKeyId(kid)))
            }
        }
        Err(e) => Err(VerifyError::Token(e)),
    }
}

/// The outcome of `verify_link_attestation`: docs/05's steps 1 to 5 answer
/// "which account", not "which tier", since the account is what a Link
/// record stores (docs/05, "What runs on a stream that has no session").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkVerification {
    /// The Attestation checked out through step 5; the token names this
    /// account. Step 6 has not run.
    Verified(AccountId),
    /// The token names a `kid` the cache does not hold, and the refetch
    /// budget allows one fetch of this uri. Fetch it, `JwksCache::install`
    /// it, and call `verify_link_attestation` again.
    JwksNeeded {
        /// The `jwks_uri` of the profile the token's `iss` selected.
        jwks_uri: String,
    },
}

/// Why `verify_link_attestation` could not produce a `LinkVerification`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkVerifyError {
    /// Steps 1 to 5 refused the token itself.
    Attestation(VerifyError),
    /// The key join: the peer's claimed identity key does not hash to the
    /// `DeviceId` the channel authenticated.
    KeyDoesNotMatchChannel {
        /// The `DeviceId` the channel actually authenticated.
        authenticated: DeviceId,
        /// The `DeviceId` the peer's identity key claims.
        claimed: DeviceId,
    },
}

impl fmt::Display for LinkVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attestation(e) => write!(f, "{e}"),
            Self::KeyDoesNotMatchChannel {
                authenticated,
                claimed,
            } => write!(
                f,
                "attestation claims device {claimed}, but the channel authenticated {authenticated}"
            ),
        }
    }
}

impl std::error::Error for LinkVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Attestation(e) => Some(e),
            Self::KeyDoesNotMatchChannel { .. } => None,
        }
    }
}

/// Runs docs/05's steps 1 to 5 plus the key join against `token`, and never
/// step 6 (docs/05, "What runs on a stream that has no session"; DCR-072).
/// `policy` carries no account field, so step 6 is inexpressible here. The
/// key join runs first, against `authenticated`, mirroring
/// `hello::AwaitingPeerHello::on_peer_hello`'s check 2. No I/O (DCR-022).
pub fn verify_link_attestation(
    policy: &LinkPolicy,
    cache: &mut JwksCache,
    token: &str,
    identity_pub: &PublicKeyPoint,
    agreement_pub: &PublicKeyPoint,
    authenticated: DeviceId,
    clock: &dyn Clock,
) -> Result<LinkVerification, LinkVerifyError> {
    // The key join. One hash, before any signature work, and before a
    // profile is selected at all.
    let digest: [u8; 32] = blake3::hash(identity_pub.as_bytes()).into();
    let claimed = DeviceId::from_identity_digest(&digest);
    if claimed != authenticated {
        return Err(LinkVerifyError::KeyDoesNotMatchChannel {
            authenticated,
            claimed,
        });
    }

    match verify_steps_one_and_two(policy.profiles, cache, token, clock)
        .map_err(LinkVerifyError::Attestation)?
    {
        EarlyOutcome::JwksNeeded { jwks_uri } => Ok(LinkVerification::JwksNeeded { jwks_uri }),
        EarlyOutcome::Claims { profile, claims } => {
            check_claims(
                profile,
                &claims,
                identity_pub,
                agreement_pub,
                policy.staleness_limit_secs,
                policy.future_skew_limit_secs,
                clock.now(),
            )
            .map_err(|e| LinkVerifyError::Attestation(VerifyError::Attestation(e)))?;
            Ok(LinkVerification::Verified(AccountId::new(
                &claims.iss,
                &claims.sub,
            )))
        }
    }
}

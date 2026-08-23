//! Attestation policy: docs/05-security.md "What a verifier does", steps 1
//! and 3 through 6. Step 2, verifying the `id_token` signature against the
//! provider's JWKS, is WI-M0-011b; `VerifiedClaims` can only be built after
//! that step, so a caller cannot reach `classify` without it.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tradr_core::{PublicIdentity, PublicKeyPoint, TrustTier, UnixTime};

use crate::id_token::SignatureAlgorithm;

/// How a provider stores the Attestation nonce (docs/05, "Provider
/// profiles"). A provider that stores a digest of the nonce fails step 4
/// outright under the wrong assumption, which is why this is a profile
/// field rather than something inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceBinding {
    /// `nonce == base64url(BLAKE3(identity_pub || agreement_pub))`.
    Verbatim,
    /// `nonce == base64url(SHA-256(the verbatim form))`.
    Hashed,
}

/// Everything a provider brings to verification. Nothing else in this
/// crate names a provider (docs/05, "Provider profiles").
pub struct ProviderProfile {
    /// Compared byte-for-byte against `iss`. Selecting the profile is step 1.
    pub issuer: String,
    /// One client id per platform. `aud` is checked against the whole set
    /// (docs/05, "Why step 3 compares against a set").
    pub client_ids: Vec<String>,
    /// How this provider encodes the Attestation nonce.
    pub nonce_binding: NonceBinding,
    /// The signature algorithms this provider's tokens may use (DCR-020,
    /// DCR-021). The token's `alg` header is compared against this set and
    /// never used to select a verification method.
    pub algorithms: Vec<SignatureAlgorithm>,
}

/// An account's identity, the `(iss, sub)` pair (ADR-0010). `sub` is unique
/// only within an issuer, so the pair is what identity means, never `sub`
/// alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountId {
    iss: String,
    sub: String,
}

impl AccountId {
    /// Builds an `AccountId` from an issuer and a subject.
    pub fn new(iss: &str, sub: &str) -> Self {
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
        }
    }
}

/// Claims read from an `id_token` whose signature has already been checked
/// against the provider's JWKS (docs/05 step 2). The type carries that
/// guarantee in its name: nothing in this crate can build one without
/// having gone through step 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    /// The token's issuer.
    pub iss: String,
    /// The token's subject.
    pub sub: String,
    /// The token's audience: the client id of whichever platform ran the
    /// OAuth flow.
    pub aud: String,
    /// When the token was issued.
    pub iat: UnixTime,
    /// The Attestation nonce, encoded per the selected profile's
    /// `nonce_binding`.
    pub nonce: String,
}

/// The policy a device applies to a peer's Attestation.
pub struct AttestationPolicy<'a> {
    /// Every provider profile this device trusts. Compiled in, per
    /// docs/05: "Profiles are compiled in and are not user-configurable."
    pub profiles: &'a [ProviderProfile],
    /// This device's own account.
    pub own_account: &'a AccountId,
    /// Accounts linked to this device's own account.
    pub linked_accounts: &'a [AccountId],
    /// How old an `iat` may be before it is rejected, in seconds. 30 days
    /// by default (docs/05, "Handling expiry").
    pub staleness_limit_secs: u64,
    /// Widens step 6 alone: an unrecognised account is accepted at
    /// `TrustTier::NearbyEphemeral` instead of rejected. Every earlier step
    /// still applies in full.
    pub ephemeral_receive: bool,
}

/// Why an Attestation was rejected. Rejection is always an `Err`: the wire
/// tier `TrustTier::Rejected` exists for encoding a decision already made
/// elsewhere, not for a caller to receive here and forget to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    /// No provider profile's `issuer` matches the token's `iss` exactly.
    UnknownIssuer,
    /// `aud` is not one of the selected profile's client ids.
    AudienceNotRecognised,
    /// The nonce does not bind the peer's identity and agreement keys.
    NonceMismatch,
    /// `iat` falls outside the staleness limit, in either direction.
    Stale,
    /// The `(iss, sub)` pair is neither the device's own account nor a
    /// linked one, and ephemeral-receive mode is off.
    UntrustedAccount,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIssuer => write!(f, "no provider profile matches the token's issuer"),
            Self::AudienceNotRecognised => {
                write!(f, "aud is not one of the profile's client ids")
            }
            Self::NonceMismatch => write!(f, "nonce does not bind the peer's public keys"),
            Self::Stale => write!(f, "iat is outside the staleness limit"),
            Self::UntrustedAccount => write!(f, "account is neither own nor linked"),
        }
    }
}

impl std::error::Error for AttestationError {}

/// The nonce a conforming peer must present, per the profile's
/// `nonce_binding`. Concatenation order is part of the binding: swapping
/// the two keys must not produce the same nonce.
fn expected_nonce(
    binding: NonceBinding,
    identity_pub: &PublicKeyPoint,
    agreement_pub: &PublicKeyPoint,
) -> String {
    let mut input = identity_pub.as_bytes().to_vec();
    input.extend_from_slice(agreement_pub.as_bytes());
    let verbatim = URL_SAFE_NO_PAD.encode(blake3::hash(&input).as_bytes());
    match binding {
        NonceBinding::Verbatim => verbatim,
        NonceBinding::Hashed => URL_SAFE_NO_PAD.encode(Sha256::digest(verbatim.as_bytes())),
    }
}

/// The nonce a device computes before starting the OAuth flow, so the
/// `id_token` it gets back binds its own identity and agreement keys
/// (docs/05 step 4). Hand the result to the provider as the OAuth `nonce`
/// parameter: the returned `id_token` then carries it back for `classify`
/// to check.
pub fn attestation_nonce(binding: NonceBinding, identity: &PublicIdentity) -> String {
    expected_nonce(binding, identity.identity_pub(), identity.agreement_pub())
}

/// Applies `policy` to `claims`, already-verified per docs/05 step 2, and
/// returns the trust tier a conforming Attestation earns. Steps run in
/// order and stop at the first failure: step 1 selects the profile before
/// anything else is read, since every later step depends on which profile
/// is in force.
pub fn classify(
    policy: &AttestationPolicy,
    claims: &VerifiedClaims,
    identity_pub: &PublicKeyPoint,
    agreement_pub: &PublicKeyPoint,
    now: UnixTime,
) -> Result<TrustTier, AttestationError> {
    // Step 1: select the profile by an exact issuer match. Nothing else is
    // read first, so a token cannot nominate its own verification rules.
    let profile = policy
        .profiles
        .iter()
        .find(|p| p.issuer == claims.iss)
        .ok_or(AttestationError::UnknownIssuer)?;

    // Step 3: aud is checked against the profile's whole client id set, not
    // one value, since aud is whichever platform ran the flow.
    if !profile.client_ids.iter().any(|id| id == &claims.aud) {
        return Err(AttestationError::AudienceNotRecognised);
    }

    // Step 4: the nonce must bind this peer's keys, per the profile's
    // encoding. This is the trust root: without it a stolen id_token is
    // replayable with the attacker's own keys.
    let expected = expected_nonce(profile.nonce_binding, identity_pub, agreement_pub);
    if claims.nonce != expected {
        return Err(AttestationError::NonceMismatch);
    }

    // Step 5: iat must be neither stale nor in the future. elapsed_since
    // errors when iat is later than now, which rejects a future iat instead
    // of letting a subtraction produce unbounded life via a negative age.
    let age = now
        .elapsed_since(claims.iat)
        .map_err(|_| AttestationError::Stale)?;
    if age > policy.staleness_limit_secs {
        return Err(AttestationError::Stale);
    }

    // Step 6: identity is the (iss, sub) pair, never sub alone.
    let account = AccountId::new(&claims.iss, &claims.sub);
    if account == *policy.own_account {
        return Ok(TrustTier::SameAccount);
    }
    if policy.linked_accounts.contains(&account) {
        return Ok(TrustTier::Linked);
    }
    if policy.ephemeral_receive {
        return Ok(TrustTier::NearbyEphemeral);
    }
    Err(AttestationError::UntrustedAccount)
}

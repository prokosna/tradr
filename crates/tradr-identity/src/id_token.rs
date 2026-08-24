//! `id_token` signature verification: docs/05 "The token never chooses how
//! it is verified" (DCR-020, DCR-021), step 2 of docs/05's seven steps.
//! The accepted algorithm comes from the caller's `ProviderProfile`, never
//! from the token's own `alg` header, compared before the signature is
//! read at all. No I/O: fetching or caching a JWKS is the caller's job.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde_json::Value;
use sha2::Sha256;
use tradr_core::UnixTime;

use crate::attestation::{ProviderProfile, VerifiedClaims};

/// A signature algorithm an `id_token` may be verified with. Closed, and
/// carries no `none` variant: DCR-020 makes accepting an unsigned token
/// unrepresentable rather than merely forbidden by a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256, the only algorithm Google's profile
    /// lists.
    Rs256,
}

/// One entry of a provider's published JWKS, already parsed. Fetching and
/// caching the set this comes from is WI-M0-011d.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    /// The key id an `id_token` header names to select this key.
    pub kid: String,
    /// The algorithm this key is published for.
    pub algorithm: SignatureAlgorithm,
    /// The RSA modulus `n`, big-endian.
    pub modulus: Vec<u8>,
    /// The RSA public exponent `e`, big-endian.
    pub exponent: Vec<u8>,
}

/// Why an `id_token` failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The token is not a well-formed JWT: not three base64url segments, a
    /// segment that fails to decode, a header or payload that is not valid
    /// JSON, or a claim that is missing or the wrong JSON type.
    Malformed(String),
    /// The token's `alg` header names something outside the profile's
    /// accepted set. Carries what the token claimed, never used to select a
    /// verification method.
    AlgorithmNotPermitted(String),
    /// The token's `kid` names no key the caller supplied.
    UnknownKeyId(String),
    /// A key with this `kid` was supplied, but not for the algorithm the
    /// token's header claims. Distinct from `UnknownKeyId`: the kid is
    /// known, and from `SignatureInvalid`: no signature was checked.
    KeyAlgorithmMismatch(String),
    /// The signature does not verify against the selected key.
    SignatureInvalid,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed id_token: {reason}"),
            Self::AlgorithmNotPermitted(alg) => {
                write!(
                    f,
                    "algorithm {alg} is not permitted by the provider profile"
                )
            }
            Self::UnknownKeyId(kid) => write!(f, "no key with id {kid} was supplied"),
            Self::KeyAlgorithmMismatch(kid) => {
                write!(f, "key {kid} is not published for the claimed algorithm")
            }
            Self::SignatureInvalid => write!(f, "signature does not verify"),
        }
    }
}

impl std::error::Error for TokenError {}

/// Verifies `token` against `profile` and `keys`, and returns its claims.
/// The header's `alg` is compared against `profile.algorithms` before the
/// signature is read: `alg: none` and algorithm confusion both depend on
/// the header being trusted before, or instead of, that comparison.
pub fn verify_id_token(
    profile: &ProviderProfile,
    keys: &[Jwk],
    token: &str,
) -> Result<VerifiedClaims, TokenError> {
    let (header_b64, payload_b64, signature_b64) = split_segments(token)?;
    // Every segment's base64 shape is checked before any of its content is
    // read, so an undecodable segment is always Malformed regardless of
    // which of the other two segments would otherwise fail first.
    let header_bytes = decode_segment(header_b64)?;
    let payload_bytes = decode_segment(payload_b64)?;
    let signature = decode_segment(signature_b64)?;

    let header = parse_json(header_bytes, "header")?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| TokenError::Malformed("header has no alg".to_string()))?;
    let algorithm = permitted_algorithm(profile, alg)?;

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| TokenError::Malformed("header has no kid".to_string()))?;
    let key = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| TokenError::UnknownKeyId(kid.to_string()))?;
    // A key published for one algorithm must not verify a token claiming
    // another, even when the key material would technically accept it (an
    // RS256 and a PS256 key can share the same RSA modulus and exponent).
    if key.algorithm != algorithm {
        return Err(TokenError::KeyAlgorithmMismatch(kid.to_string()));
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_signature(algorithm, key, signing_input.as_bytes(), &signature)?;

    let payload = parse_json(payload_bytes, "payload")?;
    parse_claims(&payload)
}

/// Reads `iss` from `token`'s payload without checking its signature.
/// Verification does not alter the payload, so the `iss` read here is the
/// `iss` the signature covers: a forged one selects a profile whose keys
/// will not verify the token, and step 2 rejects it. Nothing but `iss` may
/// be read this way, not a JWKS host, a `kid`, or an `alg`.
pub fn peek_issuer(token: &str) -> Result<String, TokenError> {
    let (_, payload_b64, _) = split_segments(token)?;
    let payload_bytes = decode_segment(payload_b64)?;
    let payload = parse_json(payload_bytes, "payload")?;
    require_str(&payload, "iss")
}

// Splits a token into its three raw (still base64url-encoded) segments.
// Rejects anything that is not exactly three dot-separated segments.
fn split_segments(token: &str) -> Result<(&str, &str, &str), TokenError> {
    let parts: Vec<&str> = token.split('.').collect();
    match parts[..] {
        [header, payload, signature] => Ok((header, payload, signature)),
        _ => Err(TokenError::Malformed(
            "a token must have exactly three segments".to_string(),
        )),
    }
}

// Decodes one JWT segment. Strict base64url without padding: JWT defines
// one spelling, and accepting the padded form would give a token two
// encodings.
fn decode_segment(segment: &str) -> Result<Vec<u8>, TokenError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| TokenError::Malformed(format!("segment is not base64url: {e}")))
}

fn parse_json(bytes: Vec<u8>, which: &str) -> Result<Value, TokenError> {
    serde_json::from_slice(&bytes)
        .map_err(|e| TokenError::Malformed(format!("{which} is not valid JSON: {e}")))
}

// Compares `alg` against the profile's accepted set. The set is the only
// source of truth; `alg` is never used to choose how verification proceeds.
fn permitted_algorithm(
    profile: &ProviderProfile,
    alg: &str,
) -> Result<SignatureAlgorithm, TokenError> {
    let claimed = match alg {
        "RS256" => Some(SignatureAlgorithm::Rs256),
        _ => None,
    };
    match claimed {
        Some(algorithm) if profile.algorithms.contains(&algorithm) => Ok(algorithm),
        _ => Err(TokenError::AlgorithmNotPermitted(alg.to_string())),
    }
}

fn verify_signature(
    algorithm: SignatureAlgorithm,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), TokenError> {
    match algorithm {
        SignatureAlgorithm::Rs256 => verify_rs256(key, signing_input, signature),
    }
}

fn verify_rs256(key: &Jwk, signing_input: &[u8], signature: &[u8]) -> Result<(), TokenError> {
    let public_key = RsaPublicKey::new(
        BigUint::from_bytes_be(&key.modulus),
        BigUint::from_bytes_be(&key.exponent),
    )
    .map_err(|_| TokenError::SignatureInvalid)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature = RsaSignature::try_from(signature).map_err(|_| TokenError::SignatureInvalid)?;
    verifying_key
        .verify(signing_input, &signature)
        .map_err(|_| TokenError::SignatureInvalid)
}

// Reads the five claims docs/05 requires, rejecting a missing or
// wrong-shaped one rather than defaulting it: a defaulted claim is a claim
// an attacker did not have to supply.
fn parse_claims(payload: &Value) -> Result<VerifiedClaims, TokenError> {
    Ok(VerifiedClaims {
        iss: require_str(payload, "iss")?,
        sub: require_str(payload, "sub")?,
        aud: require_str(payload, "aud")?,
        iat: UnixTime::from_secs(require_i64(payload, "iat")?),
        nonce: require_str(payload, "nonce")?,
    })
}

// Reads a string claim. `aud` given as a JSON array also fails here, since
// `as_str` returns `None` for any non-string value (DCR-021).
fn require_str(payload: &Value, name: &str) -> Result<String, TokenError> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| TokenError::Malformed(format!("missing or non-string claim: {name}")))
}

fn require_i64(payload: &Value, name: &str) -> Result<i64, TokenError> {
    payload
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| TokenError::Malformed(format!("missing or non-integer claim: {name}")))
}

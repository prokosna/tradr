#![forbid(unsafe_code)]
//! Attestation issue and verify, Noise, key storage.

mod attestation;
mod id_token;
mod jwks;
mod software_key_store;

pub use attestation::{
    AccountId, AttestationError, AttestationPolicy, NonceBinding, ProviderProfile, VerifiedClaims,
    classify,
};
pub use id_token::{Jwk, SignatureAlgorithm, TokenError, verify_id_token};
pub use jwks::{JwksError, parse_jwks};
pub use software_key_store::SoftwareKeyStore;

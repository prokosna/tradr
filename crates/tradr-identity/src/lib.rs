#![forbid(unsafe_code)]
//! Attestation issue and verify, Noise, key storage.

mod attestation;
mod google;
mod id_token;
mod jwks;
mod jwks_cache;
mod software_key_store;
mod storage_ladder;
mod verify;

pub use attestation::{
    AccountId, AttestationError, AttestationPolicy, NonceBinding, ProviderProfile, VerifiedClaims,
    attestation_nonce, classify, classify_with_profile,
};
pub use google::{OAuthClient, Platform, ProviderError, google, oauth_client};
pub use id_token::{Jwk, SignatureAlgorithm, TokenError, peek_issuer, verify_id_token};
pub use jwks::{JwksError, parse_jwks};
pub use jwks_cache::JwksCache;
pub use software_key_store::SoftwareKeyStore;
pub use storage_ladder::{LadderError, select_rung};
pub use verify::{Verification, VerifyError, verify_attestation};

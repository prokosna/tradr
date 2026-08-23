#![forbid(unsafe_code)]
//! Attestation issue and verify, Noise, key storage.

mod attestation;
mod software_key_store;

pub use attestation::{
    AccountId, AttestationError, AttestationPolicy, NonceBinding, ProviderProfile, VerifiedClaims,
    classify,
};
pub use software_key_store::SoftwareKeyStore;

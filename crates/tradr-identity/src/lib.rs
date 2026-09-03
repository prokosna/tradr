#![forbid(unsafe_code)]
//! Attestation issue and verify, Noise, key storage.

mod attestation;
mod google;
pub mod hello;
mod id_token;
mod invite;
mod jwks;
mod jwks_cache;
mod link;
mod os_rng;
mod software_key_store;
mod storage_ladder;
mod system_clock;
mod verify;

pub use attestation::{
    AccountId, AttestationError, AttestationPolicy, LinkPolicy, NonceBinding, ProviderProfile,
    VerifiedClaims, attestation_nonce, classify, classify_with_profile,
};
pub use google::{OAuthClient, Platform, ProviderError, google, oauth_client};
pub use id_token::{Jwk, SignatureAlgorithm, TokenError, peek_issuer, verify_id_token};
pub use invite::{INVITE_TTL_SECS, create_invite};
pub use jwks::{JwksError, parse_jwks};
pub use jwks_cache::JwksCache;
pub use link::{
    Link, LinkRegistry, LinkRegistryError, derive_link_id, derive_link_secret, device_fingerprint,
    link_secret_slot,
};
pub use os_rng::OsRng;
pub use software_key_store::SoftwareKeyStore;
pub use storage_ladder::{LadderError, select_rung, select_rung_index};
pub use system_clock::SystemClock;
pub use verify::{
    LinkVerification, LinkVerifyError, Verification, VerifyError, verify_attestation,
    verify_link_attestation,
};

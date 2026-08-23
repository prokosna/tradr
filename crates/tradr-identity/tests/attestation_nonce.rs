//! Supervisor-authored tests for WI-M0-011c, written before the
//! implementation. docs/05 step 4: the nonce is what binds an id_token to
//! one device's keys, so a stolen token cannot be replayed with an
//! attacker's own. Critical Module, and the failure it guards is that the
//! issuing side and the verifying side stop computing the same thing.

use std::cell::Cell;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};
use tradr_core::{KeyStore, PublicIdentity, Rng, RngError, TrustTier, UnixTime};
use tradr_identity::{
    AccountId, AttestationError, AttestationPolicy, NonceBinding, ProviderProfile,
    SignatureAlgorithm, SoftwareKeyStore, VerifiedClaims, attestation_nonce, classify,
};

const ISS: &str = "https://accounts.google.com";
const AUD: &str = "desktop.apps.googleusercontent.com";
const SUB: &str = "108133742015511111111";
const NOW: i64 = 1_800_000_000;

/// Fills each buffer with one repeated byte and moves on, so a store's two
/// keys differ and two stores seeded differently share nothing. Every byte
/// is a valid P-256 scalar at these values.
struct CountingRng {
    next: Cell<u8>,
}

impl CountingRng {
    fn starting_at(seed: u8) -> Self {
        Self {
            next: Cell::new(seed),
        }
    }
}

impl Rng for CountingRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(self.next.get());
        self.next.set(self.next.get().wrapping_add(1));
        Ok(())
    }
}

fn identity(seed: u8) -> PublicIdentity {
    let store = SoftwareKeyStore::generate(&CountingRng::starting_at(seed))
        .expect("these seeds are valid P-256 scalars");
    store
        .public_identity()
        .expect("a generated store must expose its public identity")
}

/// The verbatim nonce, computed here from BLAKE3 rather than taken from
/// the crate, so both encoding tests stand on something independent.
fn verbatim(identity: &PublicIdentity) -> String {
    let mut input = identity.identity_pub().as_bytes().to_vec();
    input.extend_from_slice(identity.agreement_pub().as_bytes());
    B64.encode(blake3::hash(&input).as_bytes())
}

fn profile(binding: NonceBinding) -> ProviderProfile {
    ProviderProfile {
        issuer: ISS.to_string(),
        client_ids: vec![AUD.to_string()],
        nonce_binding: binding,
        algorithms: vec![SignatureAlgorithm::Rs256],
    }
}

fn claims(nonce: &str) -> VerifiedClaims {
    VerifiedClaims {
        iss: ISS.to_string(),
        sub: SUB.to_string(),
        aud: AUD.to_string(),
        iat: UnixTime::from_secs(NOW),
        nonce: nonce.to_string(),
    }
}

/// A policy whose own account is the one every `claims` above names, so a
/// conforming Attestation lands at `SameAccount` and any rejection in
/// these tests came from step 4 rather than from step 6.
fn policy<'a>(profiles: &'a [ProviderProfile], own: &'a AccountId) -> AttestationPolicy<'a> {
    AttestationPolicy {
        profiles,
        own_account: own,
        linked_accounts: &[],
        staleness_limit_secs: 30 * 24 * 60 * 60,
        ephemeral_receive: false,
    }
}

// --- The two encodings ---

#[test]
fn the_verbatim_nonce_is_base64url_of_blake3_over_the_two_keys() {
    let id = identity(1);

    assert_eq!(
        attestation_nonce(NonceBinding::Verbatim, &id),
        verbatim(&id)
    );
}

#[test]
fn the_hashed_nonce_is_base64url_of_sha256_over_the_verbatim_form() {
    let id = identity(1);
    let expected = B64.encode(Sha256::digest(verbatim(&id).as_bytes()));

    assert_eq!(attestation_nonce(NonceBinding::Hashed, &id), expected);
}

#[test]
fn the_two_bindings_do_not_agree() {
    let id = identity(1);

    assert_ne!(
        attestation_nonce(NonceBinding::Verbatim, &id),
        attestation_nonce(NonceBinding::Hashed, &id)
    );
}

#[test]
fn a_nonce_carries_no_padding_and_nothing_outside_the_url_alphabet() {
    let id = identity(1);

    for binding in [NonceBinding::Verbatim, NonceBinding::Hashed] {
        let nonce = attestation_nonce(binding, &id);
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{binding:?} produced {nonce}"
        );
    }
}

// --- What the nonce binds ---

#[test]
fn two_devices_do_not_share_a_nonce() {
    assert_ne!(
        attestation_nonce(NonceBinding::Verbatim, &identity(1)),
        attestation_nonce(NonceBinding::Verbatim, &identity(64))
    );
}

#[test]
fn swapping_the_two_keys_changes_the_nonce() {
    let id = identity(1);
    let swapped = PublicIdentity::new(
        id.agreement_pub().clone(),
        id.identity_pub().clone(),
        id.device_id(),
    );

    assert_ne!(
        attestation_nonce(NonceBinding::Verbatim, &id),
        attestation_nonce(NonceBinding::Verbatim, &swapped)
    );
}

#[test]
fn the_same_identity_mints_the_same_nonce_twice() {
    let id = identity(1);

    assert_eq!(
        attestation_nonce(NonceBinding::Verbatim, &id),
        attestation_nonce(NonceBinding::Verbatim, &id)
    );
}

// --- Issue and verify are one computation, not two ---

#[test]
fn a_nonce_this_device_minted_is_the_one_classify_expects() {
    let id = identity(1);
    let profiles = [profile(NonceBinding::Verbatim)];
    let own = AccountId::new(ISS, SUB);
    let minted = attestation_nonce(NonceBinding::Verbatim, &id);

    assert_eq!(
        classify(
            &policy(&profiles, &own),
            &claims(&minted),
            id.identity_pub(),
            id.agreement_pub(),
            UnixTime::from_secs(NOW),
        ),
        Ok(TrustTier::SameAccount)
    );
}

#[test]
fn a_hashed_provider_accepts_only_the_hashed_form() {
    let id = identity(1);
    let profiles = [profile(NonceBinding::Hashed)];
    let own = AccountId::new(ISS, SUB);
    let minted = attestation_nonce(NonceBinding::Hashed, &id);

    assert_eq!(
        classify(
            &policy(&profiles, &own),
            &claims(&minted),
            id.identity_pub(),
            id.agreement_pub(),
            UnixTime::from_secs(NOW),
        ),
        Ok(TrustTier::SameAccount)
    );
}

#[test]
fn a_nonce_minted_under_the_other_binding_is_rejected() {
    let id = identity(1);
    let profiles = [profile(NonceBinding::Verbatim)];
    let own = AccountId::new(ISS, SUB);
    let wrong_form = attestation_nonce(NonceBinding::Hashed, &id);

    assert_eq!(
        classify(
            &policy(&profiles, &own),
            &claims(&wrong_form),
            id.identity_pub(),
            id.agreement_pub(),
            UnixTime::from_secs(NOW),
        ),
        Err(AttestationError::NonceMismatch)
    );
}

#[test]
fn one_devices_nonce_does_not_carry_over_to_another_devices_keys() {
    let mine = identity(1);
    let theirs = identity(64);
    let profiles = [profile(NonceBinding::Verbatim)];
    let own = AccountId::new(ISS, SUB);
    let minted = attestation_nonce(NonceBinding::Verbatim, &mine);

    assert_eq!(
        classify(
            &policy(&profiles, &own),
            &claims(&minted),
            theirs.identity_pub(),
            theirs.agreement_pub(),
            UnixTime::from_secs(NOW),
        ),
        Err(AttestationError::NonceMismatch)
    );
}

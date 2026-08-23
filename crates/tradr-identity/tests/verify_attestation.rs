//! Supervisor-authored tests for WI-M0-011g, written before the
//! implementation. DCR-025: the order of docs/05's seven steps is security
//! design, so it lives here rather than in the crate Change Drill D9
//! discards, and the profile is selected once. Critical Module -- each
//! piece below already passes its own tests, and the join is what is new.

use std::cell::Cell;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::time::{Duration, Instant};
use tradr_core::{Clock, KeyStore, Monotonic, PublicIdentity, Rng, RngError, TrustTier, UnixTime};
use tradr_identity::{
    AccountId, AttestationError, AttestationPolicy, Jwk, JwksCache, NonceBinding, ProviderProfile,
    SignatureAlgorithm, SoftwareKeyStore, TokenError, Verification, VerifyError, attestation_nonce,
    verify_attestation,
};

const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDYQ+qgF0T16c2x
yXBPU0I36ACKWEjOYpixQ1gz7x4MPcpmod8Yrjl7neTIfUVsmKT5brnzJ64kcKT8
b4zmtJ090gHN3Fa7L/RIiIAw+7xm1s1hrStLMDT5GZcQJ7gmtciuM4a2BoxOi3Cp
vxtN2SSsu4AumW1qOE81KD0K9+yodMTiUXRQHdM8BcWqz7MwLdFSNzTp0gWch3HV
/ApthIScsNrFXt0tGxMUZ5PGxrOBl7ToRSZmerdEuWUibv62uxGD8uTmjADTwx0u
IVJoI6ky8SBsP4tswRFmVM3yR9HkygjqnCK2bkJrEIO+hvgh0taZshYCRg5BKJBp
I+UAvpqjAgMBAAECggEBANHTw3ckXJJEEIDoswEkBOF9Rdj0o18rJn8GmjN5UywJ
X7GIaI7nq3oWzf0AHjWpPJeOKPiUjU9pw4nxKUJGBzIN6hY0LCpd8qPVXJsqA7e7
vXWBsLm4wgzWGU1hXDiis1zhPViqrcMfY2Yut20mu4CkQ0/zKMegbqliqydTONiO
+hMaKig1naMoSUn5UO2GDtTHocqDSTWa6TOI7o0mEtBqKkKdXrsulnzptCWNYpc9
IzZVurQZ8QG2PCB0oTpze3r1/aUMAwqE4P3h8kHEhDaHNDaDEfIiJTsojDoChMEf
wOHcwRtF4oDFCp1aI2c3XKSCYLKDFvQ8AeyTs5VKgkECgYEA5EI+9iXKa2+MXQZ6
4VZ5ks31Pk/fHs7z53RY2D4cG6ehK8Fhnd8b3J9wmoMPQySE6DamfXGk7mwqdERb
jJ/kxowc4g2fVW9WY5kcTbtPp0qgx3xRoIEb7ErVY3zzf5KLwR47mCYn93aLWnRp
Q6ZHUXH1KAnvjIfoxBROJ0SFuhECgYEA8oyFU53ZmidDB/3eO6bFSf7bXH3sWSnJ
0QEkB3HDOLkqeGEIWH9XxVnqwSDcZ807Z4mfCtSHC/pCaA075o7sTKpSF2JRkeGS
EH5G1/BZjzenRlaKPTEePisWYwxTwT19stxF/ViQ9fBHTsEZQ+iyLcQ1yVqIspH/
3SyLNdw+tXMCgYBCM/SO7+cFwhSz5m09bhdUvOekawYLqXqUZupdzaXZX4Ufa7ck
UtGB67x9FAYZMz5ZG4CuYYe0nyqxDiJ/ZuCztW+rIMhVvzUPLhlHckxn+P0o3qXO
J6QxpIK/mD4HgjmGiX4/YtG0tG02jwz40gFdXe/87OTNnZ2lQT5ppTYkAQKBgQCF
iZw2JygQ2SDsm3bpPK5OSQSY7bNce8djTM97UcT7y+Z4FGQ15RZ7zz+SSPdQJwxX
ustXeR9JFuXMx8x86Z9rrjI4MadbO+fhMMTsSqXkVe3AqhC+E/bkn3BZ5AWQ1LwJ
54CZNVPKNBnuYB3653iB/g7m5vNv7TYDnWyfoLzdxQKBgQC6EYvHMd8ol9WgpRXk
/F7ZcA5/6eUGkI1Z4l8nfnlylCUGp49v5hGY+i2z64/c5/VNF/NM9x9s1eFU2wwt
7GmF4b+pYDjQYFAIyK82trfgO+w3w7Gicmxo4Qw3By0IPG/+LskehuEz7Bw7EVKL
MH1PaxeOz3eaTQVEUUg5TNv80g==
-----END PRIVATE KEY-----"#;

const KID: &str = "provider-a-key";
const ISS_A: &str = "https://accounts.google.com";
const AUD_A: &str = "desktop-a.apps.googleusercontent.com";
const JWKS_A: &str = "https://a.example/jwks";
const ISS_B: &str = "https://login.microsoftonline.com/common/v2.0";
const AUD_B: &str = "desktop-b.example";
const JWKS_B: &str = "https://b.example/jwks";
const SUB: &str = "peer-subject";
const NOW: i64 = 1_800_000_000;

struct Timeline {
    origin: Instant,
}

impl Timeline {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    fn at(&self, secs: u64) -> Monotonic {
        Monotonic::from_instant(self.origin + Duration::from_secs(secs))
    }
}

struct CountingRng {
    next: Cell<u8>,
}

impl Rng for CountingRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(self.next.get());
        self.next.set(self.next.get().wrapping_add(1));
        Ok(())
    }
}

fn identity(seed: u8) -> PublicIdentity {
    let store = SoftwareKeyStore::generate(&CountingRng {
        next: Cell::new(seed),
    })
    .expect("these seeds are valid P-256 scalars");
    store.public_identity().expect("a generated store")
}

fn private_key() -> RsaPrivateKey {
    match RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM) {
        Ok(k) => k,
        Err(e) => panic!("the embedded test key must parse, got {e}"),
    }
}

fn published_key(kid: &str) -> Jwk {
    let public = RsaPublicKey::from(&private_key());
    Jwk {
        kid: kid.to_string(),
        algorithm: SignatureAlgorithm::Rs256,
        modulus: public.n().to_bytes_be(),
        exponent: public.e().to_bytes_be(),
    }
}

/// A key published under a real `kid` whose modulus is not the signing
/// key's, so a token selecting it fails on the signature rather than on
/// an unknown id.
fn impostor_key(kid: &str) -> Jwk {
    let mut key = published_key(kid);
    key.modulus[8] ^= 0xFF;
    key
}

fn document(keys: &[Jwk]) -> Vec<u8> {
    let entries: Vec<String> = keys
        .iter()
        .map(|k| {
            format!(
                r#"{{"kty":"RSA","alg":"RS256","use":"sig","kid":"{}","n":"{}","e":"{}"}}"#,
                k.kid,
                B64.encode(&k.modulus),
                B64.encode(&k.exponent)
            )
        })
        .collect();
    format!(r#"{{"keys":[{}]}}"#, entries.join(",")).into_bytes()
}

fn profile(issuer: &str, aud: &str, jwks_uri: &str) -> ProviderProfile {
    ProviderProfile {
        issuer: issuer.to_string(),
        client_ids: vec![aud.to_string()],
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
        jwks_uri: jwks_uri.to_string(),
    }
}

fn both_profiles() -> Vec<ProviderProfile> {
    vec![profile(ISS_A, AUD_A, JWKS_A), profile(ISS_B, AUD_B, JWKS_B)]
}

fn signed_token(header_json: &str, payload_json: &str) -> String {
    let input = format!("{}.{}", B64.encode(header_json), B64.encode(payload_json));
    let signing_key = SigningKey::<Sha256>::new(private_key());
    let signature = signing_key.sign(input.as_bytes());
    format!("{}.{}", input, B64.encode(signature.to_bytes()))
}

fn token_for(kid: &str, iss: &str, aud: &str, nonce: &str, iat: i64) -> String {
    signed_token(
        &format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{kid}"}}"#),
        &format!(r#"{{"iss":"{iss}","sub":"{SUB}","aud":"{aud}","iat":{iat},"nonce":"{nonce}"}}"#),
    )
}

fn conforming_token(id: &PublicIdentity) -> String {
    let nonce = attestation_nonce(NonceBinding::Verbatim, id);
    token_for(KID, ISS_A, AUD_A, &nonce, NOW)
}

fn own_account() -> AccountId {
    AccountId::new(ISS_A, SUB)
}

fn policy<'a>(profiles: &'a [ProviderProfile], own: &'a AccountId) -> AttestationPolicy<'a> {
    AttestationPolicy {
        profiles,
        own_account: own,
        linked_accounts: &[],
        staleness_limit_secs: 30 * 24 * 60 * 60,
        ephemeral_receive: false,
    }
}

fn warm_cache(uri: &str, keys: &[Jwk]) -> JwksCache {
    let mut cache = JwksCache::new(uri);
    cache
        .install(&document(keys))
        .expect("a well-formed document");
    cache
}

/// Both kinds of time arrive through one `Clock` rather than as two
/// arguments, so a caller cannot hand the staleness check and the refetch
/// budget readings that disagree with each other.
struct FixedClock {
    wall: UnixTime,
    mono: Monotonic,
}

impl Clock for FixedClock {
    fn now(&self) -> UnixTime {
        self.wall
    }

    fn monotonic_now(&self) -> Monotonic {
        self.mono
    }
}

fn run(
    policy: &AttestationPolicy,
    cache: &mut JwksCache,
    token: &str,
    id: &PublicIdentity,
    mono: Monotonic,
) -> Result<Verification, VerifyError> {
    let clock = FixedClock {
        wall: UnixTime::from_secs(NOW),
        mono,
    };
    verify_attestation(
        policy,
        cache,
        token,
        id.identity_pub(),
        id.agreement_pub(),
        &clock,
    )
}

// --- The whole sequence, end to end ---

#[test]
fn a_conforming_attestation_verifies() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let mut cache = warm_cache(JWKS_A, &[published_key(KID)]);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &conforming_token(&id),
            &id,
            time.at(0)
        ),
        Ok(Verification::Verified(TrustTier::SameAccount))
    );
}

// --- The fetch stays outside, and comes back to the same place ---

#[test]
fn an_unknown_kid_asks_for_the_jwks_rather_than_rejecting() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let mut cache = JwksCache::new(JWKS_A);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &conforming_token(&id),
            &id,
            time.at(0)
        ),
        Ok(Verification::JwksNeeded {
            jwks_uri: JWKS_A.to_string()
        })
    );
}

#[test]
fn installing_what_was_asked_for_and_calling_again_verifies() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let token = conforming_token(&id);
    let mut cache = JwksCache::new(JWKS_A);

    let first = run(
        &policy(&profiles, &own),
        &mut cache,
        &token,
        &id,
        time.at(0),
    );
    assert!(matches!(first, Ok(Verification::JwksNeeded { .. })));
    cache
        .install(&document(&[published_key(KID)]))
        .expect("install");

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &token,
            &id,
            time.at(1)
        ),
        Ok(Verification::Verified(TrustTier::SameAccount))
    );
}

#[test]
fn a_second_unknown_kid_inside_the_window_is_rejected_without_another_fetch() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let mut cache = JwksCache::new(JWKS_A);
    let first = run(
        &policy(&profiles, &own),
        &mut cache,
        &conforming_token(&id),
        &id,
        time.at(0),
    );
    assert!(matches!(first, Ok(Verification::JwksNeeded { .. })));

    let nonce = attestation_nonce(NonceBinding::Verbatim, &id);
    let other = token_for("a-second-unknown-kid", ISS_A, AUD_A, &nonce, NOW);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &other,
            &id,
            time.at(1)
        ),
        Err(VerifyError::Token(TokenError::UnknownKeyId(
            "a-second-unknown-kid".to_string()
        )))
    );
}

// --- One profile, selected once ---

#[test]
fn the_uri_asked_for_is_the_selected_profiles_and_not_the_first() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let nonce = attestation_nonce(NonceBinding::Verbatim, &id);
    let from_b = token_for(KID, ISS_B, AUD_B, &nonce, NOW);
    let mut cache = JwksCache::new(JWKS_B);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &from_b,
            &id,
            time.at(0)
        ),
        Ok(Verification::JwksNeeded {
            jwks_uri: JWKS_B.to_string()
        })
    );
}

#[test]
fn a_cache_holding_another_providers_keys_is_refused() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    // The token names provider A; the cache was built for provider B and
    // holds a key under the same id. Verifying against it would be
    // trusting B to vouch for A.
    let mut cache = warm_cache(JWKS_B, &[published_key(KID)]);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &conforming_token(&id),
            &id,
            time.at(0)
        ),
        Err(VerifyError::CacheIsForAnotherProvider {
            expected: JWKS_A.to_string(),
            held: JWKS_B.to_string(),
        })
    );
}

#[test]
fn an_issuer_no_profile_names_is_rejected_before_anything_is_fetched() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let nonce = attestation_nonce(NonceBinding::Verbatim, &id);
    let stranger = token_for(KID, "https://stranger.example", AUD_A, &nonce, NOW);
    let mut cache = JwksCache::new(JWKS_A);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &stranger,
            &id,
            time.at(0)
        ),
        Err(VerifyError::Attestation(AttestationError::UnknownIssuer))
    );

    // The budget is untouched: an unknown issuer must not be a way to make
    // a device fetch anything.
    assert!(cache.claim_refetch_for("any-kid", time.at(1)));
}

#[test]
fn claiming_another_providers_issuer_selects_keys_that_do_not_verify() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let nonce = attestation_nonce(NonceBinding::Verbatim, &id);
    // Signed by A's key, claiming B's issuer. Step 1 reads an unverified
    // `iss`, and this is why that is safe: the profile it selects carries
    // keys the signature cannot match.
    let forged = token_for(KID, ISS_B, AUD_B, &nonce, NOW);
    let mut cache = warm_cache(JWKS_B, &[impostor_key(KID)]);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &forged,
            &id,
            time.at(0)
        ),
        Err(VerifyError::Token(TokenError::SignatureInvalid))
    );
}

// --- Order within the sequence ---

#[test]
fn the_signature_is_checked_before_the_nonce() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    // Both wrong at once: the nonce binds nothing and the key does not
    // match. A sequence that checked claims first would say NonceMismatch.
    let token = token_for(KID, ISS_A, AUD_A, "not-a-binding-nonce", NOW);
    let mut cache = warm_cache(JWKS_A, &[impostor_key(KID)]);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &token,
            &id,
            time.at(0)
        ),
        Err(VerifyError::Token(TokenError::SignatureInvalid))
    );
}

#[test]
fn a_nonce_binding_another_devices_keys_is_rejected() {
    let time = Timeline::new();
    let mine = identity(1);
    let theirs = identity(64);
    let profiles = both_profiles();
    let own = own_account();
    let mut cache = warm_cache(JWKS_A, &[published_key(KID)]);

    assert_eq!(
        run(
            &policy(&profiles, &own),
            &mut cache,
            &conforming_token(&theirs),
            &mine,
            time.at(0)
        ),
        Err(VerifyError::Attestation(AttestationError::NonceMismatch))
    );
}

#[test]
fn a_stale_token_with_a_good_signature_reaches_the_staleness_check() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let nonce = attestation_nonce(NonceBinding::Verbatim, &id);
    let old = token_for(KID, ISS_A, AUD_A, &nonce, NOW - 40 * 24 * 60 * 60);
    let mut cache = warm_cache(JWKS_A, &[published_key(KID)]);

    assert_eq!(
        run(&policy(&profiles, &own), &mut cache, &old, &id, time.at(0)),
        Err(VerifyError::Attestation(AttestationError::Stale))
    );
}

#[test]
fn a_malformed_token_is_rejected_before_a_profile_is_selected() {
    let time = Timeline::new();
    let id = identity(1);
    let profiles = both_profiles();
    let own = own_account();
    let mut cache = JwksCache::new(JWKS_A);

    let outcome = run(
        &policy(&profiles, &own),
        &mut cache,
        "not.a.token",
        &id,
        time.at(0),
    );

    assert!(matches!(
        outcome,
        Err(VerifyError::Token(TokenError::Malformed(_)))
    ));
    assert!(cache.claim_refetch_for("any-kid", time.at(1)));
}

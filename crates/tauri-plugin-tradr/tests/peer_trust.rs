//! Supervisor-authored tests for WI-M6-001, written before the
//! implementation (CLAUDE.md section 6). Verification itself is already
//! tested in `tradr-identity`; what is new here is the join the live path
//! makes -- which policy it builds, what it does before a sign-in, and how
//! many outbound fetches a peer can drive.

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use tauri_plugin_tradr::peer_trust::{JwksFetch, PeerTrust};
use tradr_core::{
    BoxFuture, Clock, KeyStore, Monotonic, PublicIdentity, Rng, RngError, TrustTier, UnixTime,
};
use tradr_identity::{
    AccountId, Jwk, NonceBinding, ProviderProfile, SignatureAlgorithm, SoftwareKeyStore,
    attestation_nonce,
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

const KID: &str = "provider-key";
const ROTATED_KID: &str = "provider-key-2";
const ISS: &str = "https://accounts.google.com";
const AUD: &str = "desktop.apps.googleusercontent.com";
const OTHER_AUD: &str = "someone-elses-deployment.apps.googleusercontent.com";
const JWKS_URI: &str = "https://jwks.example/certs";
const OWN_SUB: &str = "own-subject";
const LINKED_SUB: &str = "linked-subject";
const STRANGER_SUB: &str = "stranger-subject";
const NOW: i64 = 1_800_000_000;
const STALENESS_LIMIT_SECS: u64 = 30 * 24 * 60 * 60;

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

// A key published under a real `kid` whose modulus is not the signing
// key's, so a token selecting it fails on the signature rather than on an
// unknown id.
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

fn profile() -> ProviderProfile {
    ProviderProfile {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        authorization_uri: "https://accounts.google.com/o/oauth2/auth".to_string(),
        token_uri: "https://oauth2.googleapis.com/token".to_string(),
        issuer: ISS.to_string(),
        client_ids: vec![AUD.to_string()],
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
        jwks_uri: JWKS_URI.to_string(),
    }
}

fn signed_token(header_json: &str, payload_json: &str) -> String {
    let input = format!("{}.{}", B64.encode(header_json), B64.encode(payload_json));
    let signing_key = SigningKey::<Sha256>::new(private_key());
    let signature = signing_key.sign(input.as_bytes());
    format!("{}.{}", input, B64.encode(signature.to_bytes()))
}

// A token binding `bound_to`'s keys in its nonce, whoever ends up
// presenting it. Separating the bound identity from the presented one is
// what makes the replay test possible at all.
fn token(kid: &str, sub: &str, aud: &str, bound_to: &PublicIdentity, iat: i64) -> String {
    let nonce = attestation_nonce(NonceBinding::Verbatim, bound_to);
    signed_token(
        &format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{kid}"}}"#),
        &format!(r#"{{"iss":"{ISS}","sub":"{sub}","aud":"{aud}","iat":{iat},"nonce":"{nonce}"}}"#),
    )
}

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

fn clock_at(wall_secs: i64) -> FixedClock {
    FixedClock {
        wall: UnixTime::from_secs(wall_secs),
        mono: Monotonic::from_instant(Instant::now()),
    }
}

/// A fetcher that answers with a fixed document and counts how often it
/// was asked. The count is the whole point: a peer naming an unknown
/// `kid` must not be able to turn one connection into repeated outbound
/// requests.
struct CountingFetch {
    document: Vec<u8>,
    calls: AtomicUsize,
    fails: bool,
}

impl CountingFetch {
    fn serving(keys: &[Jwk]) -> Arc<Self> {
        Arc::new(Self {
            document: document(keys),
            calls: AtomicUsize::new(0),
            fails: false,
        })
    }

    fn failing() -> Arc<Self> {
        Arc::new(Self {
            document: Vec::new(),
            calls: AtomicUsize::new(0),
            fails: true,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl JwksFetch for CountingFetch {
    fn fetch<'a>(&'a self, _jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fails {
                Err("the provider could not be reached".to_string())
            } else {
                Ok(self.document.clone())
            }
        })
    }
}

// A PeerTrust already holding `keys`, so a test that is not about
// fetching never reaches the network seam at all.
fn trust_holding(keys: &[Jwk], fetch: Arc<CountingFetch>) -> PeerTrust {
    let trust = PeerTrust::new(profile(), fetch);
    trust
        .install(&document(keys))
        .expect("a well-formed document");
    trust
}

fn own_account() -> AccountId {
    AccountId::new(ISS, OWN_SUB)
}

fn linked_account() -> AccountId {
    AccountId::new(ISS, LINKED_SUB)
}

async fn classify(
    trust: &PeerTrust,
    presented_by: &PublicIdentity,
    token: &str,
    own: Option<&AccountId>,
    linked: &[AccountId],
) -> Result<TrustTier, String> {
    trust
        .classify(
            token,
            presented_by.identity_pub(),
            presented_by.agreement_pub(),
            own,
            linked,
            &clock_at(NOW),
        )
        .await
}

#[tokio::test]
async fn a_device_that_has_not_signed_in_grants_no_tier_at_all() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, None, &[]).await;

    let message = outcome.expect_err("no sign-in means no account to classify against");
    assert!(
        message.contains("sign in"),
        "the refusal must name what is missing, got {message}"
    );
    assert_eq!(
        fetch.calls(),
        0,
        "a device with no account must not be made to fetch"
    );
}

#[tokio::test]
async fn a_peer_of_this_devices_own_account_is_same_account() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
}

#[tokio::test]
async fn a_peer_of_a_linked_account_is_linked() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, LINKED_SUB, AUD, &peer, NOW);

    let outcome = classify(
        &trust,
        &peer,
        &token,
        Some(&own_account()),
        &[linked_account()],
    )
    .await;

    assert_eq!(outcome, Ok(TrustTier::Linked));
}

#[tokio::test]
async fn a_peer_of_an_account_that_is_neither_is_refused_rather_than_downgraded() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, STRANGER_SUB, AUD, &peer, NOW);

    let outcome = classify(
        &trust,
        &peer,
        &token,
        Some(&own_account()),
        &[linked_account()],
    )
    .await;

    assert!(
        outcome.is_err(),
        "ephemeral receive is off, so an unknown account is a refusal and never a lower tier, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_bound_to_another_devices_keys_is_refused_when_replayed() {
    let victim = identity(1);
    let attacker = identity(9);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    // Google really signed this, for the victim's account and the
    // victim's keys. The attacker presents it unaltered over a channel
    // authenticated as their own device.
    let stolen = token(KID, OWN_SUB, AUD, &victim, NOW);

    let outcome = classify(&trust, &attacker, &stolen, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "the nonce binds the victim's keys, not the presenter's, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_signed_by_a_key_the_provider_never_published_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[impostor_key(KID)],
        CountingFetch::serving(&[impostor_key(KID)]),
    );
    let token = token(KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "the kid resolves and the signature does not verify under it, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_older_than_the_staleness_limit_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let issued = NOW - (STALENESS_LIMIT_SECS as i64) - 1;
    let token = token(KID, OWN_SUB, AUD, &peer, issued);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "an Attestation older than docs/05's limit is refused, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_token_for_another_deployments_audience_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );
    let token = token(KID, OWN_SUB, OTHER_AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "aud must be in this deployment's client set, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_rotated_key_is_fetched_once_and_then_verifies() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID), published_key(ROTATED_KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(ROTATED_KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert_eq!(outcome, Ok(TrustTier::SameAccount));
    assert_eq!(fetch.calls(), 1, "exactly one fetch, and no retry loop");
}

#[tokio::test]
async fn the_cache_stays_warm_across_connections() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID), published_key(ROTATED_KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(ROTATED_KID, OWN_SUB, AUD, &peer, NOW);

    for _ in 0..3 {
        let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;
        assert_eq!(outcome, Ok(TrustTier::SameAccount));
    }

    assert_eq!(
        fetch.calls(),
        1,
        "the document a connection fetched must serve the connections after it"
    );
}

#[tokio::test]
async fn a_peer_naming_an_unknown_key_cannot_drive_a_fetch_per_connection() {
    let peer = identity(1);
    // The document never carries the kid the peer names, so every
    // verification ends unresolved. Only the refetch budget stands
    // between that and one outbound request per connection.
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token("a-kid-nobody-published", OWN_SUB, AUD, &peer, NOW);

    for _ in 0..5 {
        let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;
        assert!(outcome.is_err(), "an unresolvable kid grants nothing");
    }

    assert_eq!(
        fetch.calls(),
        1,
        "docs/05's refetch floor bounds this at one, whatever the peer sends"
    );
}

#[tokio::test]
async fn a_fetch_that_fails_refuses_rather_than_granting_a_tier() {
    let peer = identity(1);
    let fetch = CountingFetch::failing();
    let trust = trust_holding(&[published_key(KID)], fetch.clone());
    let token = token(ROTATED_KID, OWN_SUB, AUD, &peer, NOW);

    let outcome = classify(&trust, &peer, &token, Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "an unreachable provider is a refusal, never a tier, got {outcome:?}"
    );
    assert_eq!(fetch.calls(), 1);
}

#[tokio::test]
async fn a_malformed_token_is_refused_without_reaching_the_provider() {
    let peer = identity(1);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = trust_holding(&[published_key(KID)], fetch.clone());

    let outcome = classify(&trust, &peer, "not-a-jwt", Some(&own_account()), &[]).await;

    assert!(outcome.is_err(), "a malformed token grants nothing");
    assert_eq!(
        fetch.calls(),
        0,
        "a token that does not parse must not cost an outbound request"
    );
}

#[tokio::test]
async fn an_empty_token_is_refused() {
    let peer = identity(1);
    let trust = trust_holding(
        &[published_key(KID)],
        CountingFetch::serving(&[published_key(KID)]),
    );

    let outcome = classify(&trust, &peer, "", Some(&own_account()), &[]).await;

    assert!(
        outcome.is_err(),
        "the empty token a device carries before it signs in grants nothing"
    );
}

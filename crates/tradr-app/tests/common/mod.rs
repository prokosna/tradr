//! The fake identity provider both Critical Module test files stand on:
//! one RSA key, the JWKS document publishing it, and tokens signed with
//! it. Shared rather than copied because there is one provider here, not
//! one per test binary -- a second copy of a signing key is a second
//! thing to keep in step (DF-29).

use std::cell::Cell;
use std::sync::Arc;
use std::sync::Mutex;
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

use tradr_app::peer_trust::JwksFetch;
use tradr_core::{BoxFuture, Clock, KeyStore, Monotonic, PublicIdentity, Rng, RngError, UnixTime};
use tradr_identity::{
    Jwk, NonceBinding, ProviderProfile, SignatureAlgorithm, SoftwareKeyStore, attestation_nonce,
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

pub const KID: &str = "provider-key";
pub const ISS: &str = "https://accounts.google.com";
pub const AUD: &str = "desktop.apps.googleusercontent.com";
pub const JWKS_URI: &str = "https://jwks.example/certs";
pub const OWN_SUB: &str = "own-subject";
pub const NOW: i64 = 1_800_000_000;
pub const STALENESS_LIMIT_SECS: u64 = 30 * 24 * 60 * 60;

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

/// A device identity derived from `seed`, so two calls with different
/// seeds are two devices and the same seed is the same device.
pub fn identity(seed: u8) -> PublicIdentity {
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

/// The provider's published key under `kid`, the one `signed_token` signs
/// with.
pub fn published_key(kid: &str) -> Jwk {
    let public = RsaPublicKey::from(&private_key());
    Jwk {
        kid: kid.to_string(),
        algorithm: SignatureAlgorithm::Rs256,
        modulus: public.n().to_bytes_be(),
        exponent: public.e().to_bytes_be(),
    }
}

/// A key published under a real `kid` whose modulus is not the signing
/// key's, so a token selecting it fails on the signature rather than on an
/// unknown id.
pub fn impostor_key(kid: &str) -> Jwk {
    let mut key = published_key(kid);
    key.modulus[8] ^= 0xFF;
    key
}

/// The JWKS document publishing `keys`, as the provider would serve it.
pub fn document(keys: &[Jwk]) -> Vec<u8> {
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

/// The provider profile every test classifies against. Its `token_uri`
/// and `jwks_uri` are deliberately different hosts, so a path that
/// confuses the two is visible.
pub fn profile() -> ProviderProfile {
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

/// A token binding `bound_to`'s keys in its nonce, whoever ends up
/// presenting it. Separating the bound identity from the presented one is
/// what makes the replay test possible at all.
pub fn token(kid: &str, sub: &str, aud: &str, bound_to: &PublicIdentity, iat: i64) -> String {
    let nonce = attestation_nonce(NonceBinding::Verbatim, bound_to);
    signed_token(
        &format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{kid}"}}"#),
        &format!(r#"{{"iss":"{ISS}","sub":"{sub}","aud":"{aud}","iat":{iat},"nonce":"{nonce}"}}"#),
    )
}

/// A clock pinned to one wall-clock second, so staleness is decided by
/// the token's `iat` and never by how long the test took.
pub struct FixedClock {
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

/// A `FixedClock` reading `wall_secs`.
pub fn clock_at(wall_secs: i64) -> FixedClock {
    FixedClock {
        wall: UnixTime::from_secs(wall_secs),
        mono: Monotonic::from_instant(Instant::now()),
    }
}

/// A fetcher that answers with a fixed document, counts how often it was
/// asked and records what it was asked for. The count is what bounds a
/// peer's ability to drive outbound requests; the uri is what says a
/// fetch went to the provider's JWKS and not to some other field of the
/// same profile.
pub struct CountingFetch {
    document: Vec<u8>,
    calls: AtomicUsize,
    uris: Mutex<Vec<String>>,
    fails: bool,
}

impl CountingFetch {
    /// A fetcher serving the document publishing `keys`.
    pub fn serving(keys: &[Jwk]) -> Arc<Self> {
        Arc::new(Self {
            document: document(keys),
            calls: AtomicUsize::new(0),
            uris: Mutex::new(Vec::new()),
            fails: false,
        })
    }

    /// A fetcher standing in for a provider that cannot be reached.
    pub fn failing() -> Arc<Self> {
        Arc::new(Self {
            document: Vec::new(),
            calls: AtomicUsize::new(0),
            uris: Mutex::new(Vec::new()),
            fails: true,
        })
    }

    /// How many times this fetcher was asked for a document.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Every uri this fetcher was asked for, in order.
    pub fn uris(&self) -> Vec<String> {
        self.uris
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl JwksFetch for CountingFetch {
    fn fetch<'a>(&'a self, jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.uris
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(jwks_uri.to_string());
            if self.fails {
                Err("the provider could not be reached".to_string())
            } else {
                Ok(self.document.clone())
            }
        })
    }
}

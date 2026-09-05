//! Tests for WI-M6-011: the inviter finishes and waits for replier close over QUIC.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use tauri_plugin_tradr::link_commands::{ReplierDeps, execute_send_link_reply};
use tauri_plugin_tradr::link_exchange::{LinkDecision, LinkOutcome};
use tauri_plugin_tradr::link_invite::{
    LinkInviteState, LinkProposalDto, LinkService, LinkServiceParts, ProposalSink,
};
use tauri_plugin_tradr::listener::{ListenerParams, handle_incoming_channel};
use tauri_plugin_tradr::peer_trust::{JwksFetch, OwnAttestation, PeerTrust};
use tradr_core::{
    BoxFuture, Candidate, Capabilities, Clock, DomainTag, HalfSecret, Invite, InviteId, KeyBinding,
    KeyStore, Monotonic, PeerExpectation, PublicIdentity, RootId, SecretStore, SecretStoreError,
    StorageLevel, Transport, TransportId, TrustTier, UnixTime, VersionRange,
};
use tradr_identity::{
    Jwk, LinkRegistry, NonceBinding, OsRng, ProviderProfile, SignatureAlgorithm, SoftwareKeyStore,
    attestation_nonce,
};
use tradr_integrity::BaoVerifier;
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

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
const ISS: &str = "https://accounts.google.com";
const AUD: &str = "desktop.apps.googleusercontent.com";
const JWKS_URI: &str = "https://jwks.example/certs";
const ALICE_SUB: &str = "alice-subject";
const BOB_SUB: &str = "bob-subject";
const NOW: i64 = 1_800_000_000;

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

fn token(sub: &str, bound_to: &PublicIdentity, iat: i64) -> String {
    let nonce = attestation_nonce(NonceBinding::Verbatim, bound_to);
    let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#);
    let payload =
        format!(r#"{{"iss":"{ISS}","sub":"{sub}","aud":"{AUD}","iat":{iat},"nonce":"{nonce}"}}"#);
    let input = format!("{}.{}", B64.encode(&header), B64.encode(&payload));
    let signing_key = SigningKey::<Sha256>::new(private_key());
    let signature = signing_key.sign(input.as_bytes());
    format!("{}.{}", input, B64.encode(signature.to_bytes()))
}

struct CountingFetch {
    document: Vec<u8>,
    calls: AtomicUsize,
}

impl CountingFetch {
    fn serving(keys: &[Jwk]) -> Arc<Self> {
        Arc::new(Self {
            document: document(keys),
            calls: AtomicUsize::new(0),
        })
    }
}

impl JwksFetch for CountingFetch {
    fn fetch<'a>(&'a self, _jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.document.clone())
        })
    }
}

fn test_trust() -> Arc<PeerTrust> {
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    trust
        .install(&document(&[published_key(KID)]))
        .expect("a well-formed document");
    Arc::new(trust)
}

struct FixedAttestation(String);

impl OwnAttestation for FixedAttestation {
    fn id_token(&self) -> Option<String> {
        Some(self.0.clone())
    }
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

fn clock_at(wall_secs: i64) -> Arc<FixedClock> {
    Arc::new(FixedClock {
        wall: UnixTime::from_secs(wall_secs),
        mono: Monotonic::from_instant(Instant::now()),
    })
}

#[derive(Default)]
struct MemoryStore {
    slots: Mutex<Vec<(String, Vec<u8>)>>,
}

impl SecretStore for MemoryStore {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let mut slots = self.slots.lock().expect("the slot map is never poisoned");
        slots.retain(|(name, _)| name != slot);
        slots.push((slot.to_string(), secret.to_vec()));
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self
            .slots
            .lock()
            .expect("the slot map is never poisoned")
            .iter()
            .find(|(name, _)| name == slot)
            .map(|(_, value)| value.clone()))
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .expect("the slot map is never poisoned")
            .retain(|(name, _)| name != slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

struct AnsweringSink {
    invites: Arc<LinkInviteState>,
    decision: Mutex<Option<LinkDecision>>,
}

impl AnsweringSink {
    fn new(invites: Arc<LinkInviteState>, decision: LinkDecision) -> Arc<Self> {
        Arc::new(Self {
            invites,
            decision: Mutex::new(Some(decision)),
        })
    }
}

impl ProposalSink for AnsweringSink {
    fn announce(&self, _proposal: &LinkProposalDto) -> Result<(), String> {
        if let Some(decision) = self.decision.lock().expect("not poisoned").take() {
            self.invites
                .answer(decision)
                .expect("the parked decision is answerable exactly once");
        }
        Ok(())
    }
}

#[tokio::test]
async fn link_exchange_over_quic_delivers_approval_and_persists_link() {
    tokio::time::timeout(Duration::from_secs(30), run_test())
        .await
        .expect("test did not hang");
}

async fn run_test() {
    let alice_dir = tempfile::tempdir().expect("alice tempdir");
    let bob_dir = tempfile::tempdir().expect("bob tempdir");

    let inviter_store = Arc::new(SoftwareKeyStore::generate(&OsRng).expect("inviter store"));
    let replier_store = Arc::new(SoftwareKeyStore::generate(&OsRng).expect("replier store"));

    let alice_id = inviter_store.public_identity().expect("alice identity");
    let bob_id = replier_store.public_identity().expect("bob identity");

    let clock = clock_at(NOW);

    let alice_token = token(ALICE_SUB, &alice_id, NOW);
    let bob_token = token(BOB_SUB, &bob_id, NOW);

    let half_a = HalfSecret::from_bytes(&[1u8; 16]).expect("16 bytes fit a HalfSecret");
    let invite_id = InviteId::from_bytes(&[2u8; 16]).expect("16 bytes fit an InviteId");
    let invite = Invite::new(
        invite_id,
        alice_id.identity_pub().clone(),
        alice_id.agreement_pub().clone(),
        alice_token.clone(),
        half_a,
        UnixTime::from_secs(NOW + 300),
    );

    let invites = Arc::new(LinkInviteState::new());
    invites.open(invite.clone()).expect("open invite");

    let alice_trust = test_trust();
    let bob_trust = test_trust();

    let inviter_registry = Arc::new(Mutex::new(
        LinkRegistry::load(&alice_dir.path().join("links.json")).expect("alice links"),
    ));
    let inviter_secrets = Arc::new(MemoryStore::default());

    let replier_registry = Arc::new(Mutex::new(
        LinkRegistry::load(&bob_dir.path().join("links.json")).expect("bob links"),
    ));
    let replier_secrets = Arc::new(MemoryStore::default());

    let service = LinkService::new(
        invites.clone(),
        LinkServiceParts {
            trust: Ok(alice_trust),
            registry: Ok(inviter_registry),
            secrets: Ok(inviter_secrets),
        },
        AnsweringSink::new(invites.clone(), LinkDecision::Approve),
        clock.clone(),
    );

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    let inviter_transport =
        QuicTransport::new(inviter_store.clone(), bind_addr).expect("inviter transport");
    let inviter_addr = inviter_transport.local_addr().expect("local addr");
    let replier_transport =
        QuicTransport::new(replier_store.clone(), bind_addr).expect("replier transport");

    let mut incoming = inviter_transport.listen().await.expect("listen");

    let inviter_id = alice_id.clone();
    let inviter_store_task = inviter_store.clone();
    let clock_task = clock.clone();
    let inviter_handle = tokio::spawn(async move {
        let channel = incoming.accept().await.expect("accept channel");
        let not_after = UnixTime::from_secs(clock_task.now().as_secs() + 30 * 24 * 3600);
        let keybind_sig = inviter_store_task
            .sign(DomainTag::KeyBind, inviter_id.agreement_pub().as_bytes())
            .expect("sign keybind");
        let our_key_binding =
            KeyBinding::new(inviter_id.agreement_pub().clone(), keybind_sig, not_after);

        let params = ListenerParams {
            root: RootId::new(1),
            our_identity: &inviter_id,
            our_attestation_token: Arc::new(FixedAttestation(alice_token)),
            our_key_binding,
            our_versions: VersionRange::new(1, 1).expect("version range"),
            our_capabilities: Capabilities::DIRECT_QUIC,
        };

        let inviter_vfs = NativeVfs::new();
        let res = handle_incoming_channel(
            channel.as_ref(),
            &inviter_vfs,
            params,
            inviter_store_task.as_ref(),
            &OsRng,
            clock_task.as_ref(),
            &BaoVerifier,
            |_| async { Ok(TrustTier::SameAccount) },
            None,
            Some(&service),
        )
        .await;
        drop(channel);
        res
    });

    let deps = ReplierDeps {
        invite: &invite,
        our_identity: &bob_id,
        our_attestation_token: bob_token,
        trust: bob_trust,
        registry: replier_registry.clone(),
        secrets: replier_secrets,
    };

    let candidate = Candidate::new(TransportId::new("direct-quic"), &inviter_addr.to_string())
        .expect("valid candidate");
    let channel = replier_transport
        .connect(&candidate, &PeerExpectation::Device(alice_id.device_id()))
        .await
        .expect("connect");

    let (replier_outcome, inviter_outcome) = tokio::join!(
        execute_send_link_reply(channel.as_ref(), deps, clock.as_ref(), &OsRng),
        inviter_handle,
    );

    let inviter_res = inviter_outcome.expect("inviter task completed");
    inviter_res.expect("inviter handled channel successfully");

    let replier_outcome = replier_outcome.expect("replier outcome succeeded");
    let link_id = match replier_outcome {
        LinkOutcome::Linked(id) => id,
        other => panic!("expected LinkOutcome::Linked, got {other:?}"),
    };

    assert!(
        replier_registry
            .lock()
            .expect("replier registry not poisoned")
            .link(&link_id)
            .is_some(),
        "replier registry must hold the link after approval"
    );
}

//! Supervisor-authored tests for WI-M6-006e, written before the
//! implementation (CLAUDE.md section 6). Verification itself is tested in
//! `tradr-identity` and the exchange in `tests/link_exchange.rs`; what is
//! new here is the join the composition root makes -- which `DeviceId`
//! reaches the verifier, and what the invite window survives (DCR-076).

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use tauri_plugin_tradr::link_exchange::LinkDecision;
use tauri_plugin_tradr::link_invite::{
    InviteWindowError, LinkInviteState, LinkProposalDto, LinkService, LinkServiceParts,
    ProposalSink,
};
use tauri_plugin_tradr::listener::LinkStreamService;
use tauri_plugin_tradr::peer_trust::{JwksFetch, PeerTrust};
use tradr_core::{
    BoxFuture, Clock, HalfSecret, Invite, InviteId, KeyStore, LinkDeclineReason, LinkReply,
    LinkSecret, Monotonic, PublicIdentity, Rng, RngError, SecretStore, SecretStoreError,
    SendStream, StorageLevel, TransportError, UnixTime,
};
use tradr_identity::{
    AccountId, Jwk, LinkRegistry, NonceBinding, ProviderProfile, SignatureAlgorithm,
    SoftwareKeyStore, attestation_nonce, derive_link_id, derive_link_secret, link_secret_slot,
};
use tradr_proto::framing::FrameDecoder;
use tradr_proto::link::decode_link_approve_frame;
use tradr_proto::message_type::{Classification, MessageType, Plane, classify};

// ---- Provider fixtures ---------------------------------------------------

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
const BOB_SUB: &str = "bob-subject";
const NOW: i64 = 1_800_000_000;
const MAX_FRAME: u32 = 65536;

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

// A token binding `bound_to`'s two keys in its nonce, whoever ends up
// presenting it. Separating the bound identity from the presented one is
// what lets a fixture keep the authenticated and the recomputed DeviceId
// apart.
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

// ---- Test doubles --------------------------------------------------------

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

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
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

#[derive(Default)]
struct MemoryStore {
    slots: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MemoryStore {
    fn get(&self, slot: &str) -> Option<Vec<u8>> {
        self.slots
            .lock()
            .expect("the slot map is never poisoned")
            .iter()
            .find(|(name, _)| name == slot)
            .map(|(_, value)| value.clone())
    }
}

impl SecretStore for MemoryStore {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let mut slots = self.slots.lock().expect("the slot map is never poisoned");
        slots.retain(|(name, _)| name != slot);
        slots.push((slot.to_string(), secret.to_vec()));
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self.get(slot))
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

struct RecordingSend {
    written: Arc<Mutex<Vec<u8>>>,
}

impl SendStream for RecordingSend {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.written
                .lock()
                .expect("the write log is never poisoned")
                .extend_from_slice(buf);
            Ok(())
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

// Answers the decision the service parks, from inside `announce` itself.
// The service parks before it announces and holds no lock while it does,
// so answering here is what a person pressing approve does one act later
// -- with no clock consulted and no task ordering to arrange (rule E3).
struct AnsweringSink {
    invites: Arc<LinkInviteState>,
    decision: Mutex<Option<LinkDecision>>,
    seen: Mutex<Vec<LinkProposalDto>>,
    // What `open` returned when called while this very decision was
    // pending, for the test that asks whether the window refuses then.
    reopen_while_pending: Mutex<Option<Result<(), InviteWindowError>>>,
    reopen_with: Mutex<Option<Invite>>,
}

impl AnsweringSink {
    fn new(invites: Arc<LinkInviteState>, decision: LinkDecision) -> Arc<Self> {
        Arc::new(Self {
            invites,
            decision: Mutex::new(Some(decision)),
            seen: Mutex::new(Vec::new()),
            reopen_while_pending: Mutex::new(None),
            reopen_with: Mutex::new(None),
        })
    }

    fn reopening(&self, invite: Invite) {
        *self.reopen_with.lock().expect("not poisoned") = Some(invite);
    }

    fn seen(&self) -> Vec<LinkProposalDto> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

impl ProposalSink for AnsweringSink {
    fn announce(&self, proposal: &LinkProposalDto) -> Result<(), String> {
        self.seen
            .lock()
            .expect("not poisoned")
            .push(proposal.clone());

        if let Some(invite) = self.reopen_with.lock().expect("not poisoned").take() {
            *self.reopen_while_pending.lock().expect("not poisoned") =
                Some(self.invites.open(invite));
        }

        if let Some(decision) = self.decision.lock().expect("not poisoned").take() {
            self.invites
                .answer(decision)
                .expect("the parked decision is answerable exactly once");
        }
        Ok(())
    }
}

// A sink that neither answers nor is expected to be reached.
struct SilentSink;

impl ProposalSink for SilentSink {
    fn announce(&self, _proposal: &LinkProposalDto) -> Result<(), String> {
        panic!("no proposal may be announced in this test")
    }
}

// Announces and then does nothing, which is a person putting the phone
// down mid-comparison. The only thing that ends the wait is the invite's
// own deadline (DCR-075).
struct UnansweringSink;

impl ProposalSink for UnansweringSink {
    fn announce(&self, _proposal: &LinkProposalDto) -> Result<(), String> {
        Ok(())
    }
}

// ---- Fixture assembly ----------------------------------------------------

fn half(byte: u8) -> HalfSecret {
    HalfSecret::from_bytes(&[byte; 16]).expect("16 bytes always fit a HalfSecret")
}

fn invite_id(byte: u8) -> InviteId {
    InviteId::from_bytes(&[byte; 16]).expect("16 bytes always fit an InviteId")
}

fn an_invite(alice: &PublicIdentity, id: InviteId, half_a: HalfSecret) -> Invite {
    Invite::new(
        id,
        alice.identity_pub().clone(),
        alice.agreement_pub().clone(),
        "alice-token-nothing-here-verifies".to_string(),
        half_a,
        UnixTime::from_secs(NOW + 300),
    )
}

fn a_reply(id: InviteId, bob: &PublicIdentity, half_b: HalfSecret) -> LinkReply {
    LinkReply::new(
        id,
        bob.identity_pub().clone(),
        bob.agreement_pub().clone(),
        token(BOB_SUB, bob, NOW),
        half_b,
    )
}

struct Fixture {
    service: LinkService,
    invites: Arc<LinkInviteState>,
    registry: Arc<Mutex<LinkRegistry>>,
    secrets: Arc<MemoryStore>,
    written: Arc<Mutex<Vec<u8>>>,
}

// The `TempDir` comes back beside the fixture rather than inside it: it is
// a guard nothing reads, and a field nothing reads is a dead-code warning
// under `-D warnings`.
fn fixture(
    invites: Arc<LinkInviteState>,
    sink: Arc<dyn ProposalSink>,
) -> (Fixture, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let registry = Arc::new(Mutex::new(
        LinkRegistry::load(&dir.path().join("links.json")).expect("a missing file is empty"),
    ));
    let secrets = Arc::new(MemoryStore::default());
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    trust
        .install(&document(&[published_key(KID)]))
        .expect("a well-formed document");

    let service = LinkService::new(
        invites.clone(),
        LinkServiceParts {
            trust: Ok(Arc::new(trust)),
            registry: Ok(registry.clone()),
            secrets: Ok(secrets.clone()),
        },
        sink,
        clock_at(NOW),
    );

    (
        Fixture {
            service,
            invites,
            registry,
            secrets,
            written: Arc::new(Mutex::new(Vec::new())),
        },
        dir,
    )
}

// `MessageType` carries no explicit discriminants, so the code is read
// through `classify` rather than cast -- the same route the exchange takes.
fn approve_frame_in(written: &[u8]) -> Option<tradr_core::LinkApprove> {
    let mut decoder = FrameDecoder::new(MAX_FRAME);
    decoder.feed(written);
    let frame = decoder.next_frame().ok()??;
    match classify(frame.type_code(), Plane::Control) {
        Classification::Known(MessageType::LinkApprove) => decode_link_approve_frame(&frame).ok(),
        _ => None,
    }
}

// ---- The key join: which DeviceId the verifier is handed -----------------

// The load-bearing test of this Work Item. A service that passed a
// `DeviceId` recomputed from the reply would compare a hash with itself,
// and every impostor would pass. The fixture keeps the two apart: the
// reply carries Bob's keys and the channel authenticated Carol, so a
// recomputed id would succeed here and the authenticated one must not.
#[tokio::test]
async fn the_channels_device_id_decides_and_never_one_recomputed_from_the_reply() {
    let alice = identity(1);
    let bob = identity(2);
    let carol = identity(3);
    assert_ne!(
        bob.device_id(),
        carol.device_id(),
        "the fixture must keep the authenticated and the recomputed ids apart"
    );

    let invites = Arc::new(LinkInviteState::new());
    let (f, _dir) = fixture(invites, Arc::new(SilentSink));
    f.invites
        .open(an_invite(&alice, invite_id(9), half(0xA1)))
        .expect("nothing is pending");

    let mut send = RecordingSend {
        written: f.written.clone(),
    };
    let outcome = f
        .service
        .serve(
            &mut send,
            a_reply(invite_id(9), &bob, half(0xB2)),
            carol.device_id(),
            MAX_FRAME,
        )
        .await
        .expect("a refused verification is a completed exchange, not an error");

    match outcome {
        tauri_plugin_tradr::link_exchange::LinkOutcome::Declined { reason, detail } => {
            assert_eq!(reason, Some(LinkDeclineReason::VerificationFailed));
            assert!(
                detail.is_some(),
                "the local reason is kept for a person even though the wire's is coarse"
            );
        }
        other => panic!("a reply the channel did not authenticate must decline, got {other:?}"),
    }
    assert!(
        f.registry.lock().expect("not poisoned").links().is_empty(),
        "nothing may be recorded for a reply that failed the key join"
    );
}

// The positive half of the pair above, and the fixture that makes the two
// distinguishable: the same reply, authenticated as Bob this time, links.
#[tokio::test]
async fn a_reply_the_channel_authenticated_links_and_records_the_secret_first() {
    let alice = identity(1);
    let bob = identity(2);

    let invites = Arc::new(LinkInviteState::new());
    let sink = AnsweringSink::new(invites.clone(), LinkDecision::Approve);
    let (f, _dir) = fixture(invites, sink.clone());
    let half_a = half(0xA1);
    let half_b = half(0xB2);
    f.invites
        .open(an_invite(&alice, invite_id(9), half_a))
        .expect("nothing is pending");

    let mut send = RecordingSend {
        written: f.written.clone(),
    };
    let outcome = f
        .service
        .serve(
            &mut send,
            a_reply(invite_id(9), &bob, half_b),
            bob.device_id(),
            MAX_FRAME,
        )
        .await
        .expect("an approved exchange completes");

    let expected_secret: LinkSecret = derive_link_secret(&half_a, &half_b);
    let expected_id = derive_link_id(&expected_secret);
    assert_eq!(
        outcome,
        tauri_plugin_tradr::link_exchange::LinkOutcome::Linked(expected_id)
    );

    let registry = f.registry.lock().expect("not poisoned");
    let link = registry
        .link(&expected_id)
        .expect("the approved link is in the registry");
    assert_eq!(link.peer_account(), &AccountId::new(ISS, BOB_SUB));
    assert_eq!(
        f.secrets.get(&link_secret_slot(&expected_id)).as_deref(),
        Some(expected_secret.as_bytes().as_slice()),
        "the secret goes to the rung the Device Key is on, under the slot the record names"
    );

    let written = f.written.lock().expect("not poisoned").clone();
    let approve = approve_frame_in(&written).expect("a LinkApprove is the last thing written");
    assert_eq!(approve.link_id(), expected_id);

    let seen = sink.seen();
    assert_eq!(seen.len(), 1, "one proposal reaches a person, exactly once");
    assert_eq!(seen[0].peer_sub, BOB_SUB);
    assert_eq!(seen[0].peer_fingerprint.len(), 12);
}

// ---- DCR-076: what the window survives -----------------------------------

// A `LinkReply` is the first frame on a stream carrying no session, so
// anything that can reach this device can send one. If a reply naming an
// unknown invite closed the window, closing someone else's would cost one
// connection and no credential at all.
#[tokio::test]
async fn a_reply_naming_another_invite_leaves_the_window_open() {
    let alice = identity(1);
    let bob = identity(2);

    let invites = Arc::new(LinkInviteState::new());
    let (f, _dir) = fixture(invites, Arc::new(SilentSink));
    f.invites
        .open(an_invite(&alice, invite_id(9), half(0xA1)))
        .expect("nothing is pending");

    let mut send = RecordingSend {
        written: f.written.clone(),
    };
    let refusal = f
        .service
        .serve(
            &mut send,
            a_reply(invite_id(7), &bob, half(0xB2)),
            bob.device_id(),
            MAX_FRAME,
        )
        .await
        .expect_err("a reply naming another invite is refused, never declined");
    assert!(matches!(
        refusal,
        tauri_plugin_tradr::link_exchange::LinkExchangeError::UnknownInvite
    ));

    assert!(
        f.written.lock().expect("not poisoned").is_empty(),
        "the stream closes with nothing written"
    );
    let still_open = f
        .invites
        .open_invite()
        .expect("the window survives a reply it is not answering");
    assert_eq!(still_open.invite_id(), &invite_id(9));
}

// The other half of "single-use": the exchange the window *is* holding
// closes it, and an approval and a decline close it alike.
#[tokio::test]
async fn the_exchange_the_window_is_holding_closes_it() {
    let alice = identity(1);
    let bob = identity(2);

    for decision in [LinkDecision::Approve, LinkDecision::Decline] {
        let invites = Arc::new(LinkInviteState::new());
        let sink = AnsweringSink::new(invites.clone(), decision);
        let (f, _dir) = fixture(invites, sink);
        f.invites
            .open(an_invite(&alice, invite_id(9), half(0xA1)))
            .expect("nothing is pending");

        let mut send = RecordingSend {
            written: f.written.clone(),
        };
        f.service
            .serve(
                &mut send,
                a_reply(invite_id(9), &bob, half(0xB2)),
                bob.device_id(),
                MAX_FRAME,
            )
            .await
            .expect("a completed exchange");

        assert!(
            f.invites.open_invite().is_none(),
            "a completed exchange closes the window, whichever way it went"
        );
    }
}

// The answer arrives on a later invocation than the exchange that waits
// for it, so the window is the single place it may be delivered -- and the
// first answer takes that place with it. A second must find nothing rather
// than be held for the next exchange, which would be a different peer
// approved by a press meant for this one.
#[tokio::test]
async fn the_first_answer_takes_the_pending_place_and_a_second_finds_nothing() {
    let alice = identity(1);
    let bob = identity(2);

    let invites = Arc::new(LinkInviteState::new());
    let sink = AnsweringSink::new(invites.clone(), LinkDecision::Approve);
    let (f, _dir) = fixture(invites, sink);
    f.invites
        .open(an_invite(&alice, invite_id(9), half(0xA1)))
        .expect("nothing is pending");

    assert!(
        f.invites.pending().is_none(),
        "nothing is waiting before an exchange runs"
    );

    let mut send = RecordingSend {
        written: f.written.clone(),
    };
    f.service
        .serve(
            &mut send,
            a_reply(invite_id(9), &bob, half(0xB2)),
            bob.device_id(),
            MAX_FRAME,
        )
        .await
        .expect("the sink answered it");

    assert!(
        f.invites.pending().is_none(),
        "the answer took the parked proposal with it"
    );
    assert!(matches!(
        f.invites.answer(LinkDecision::Approve),
        Err(InviteWindowError::NoPendingDecision)
    ));
}

// Showing a fresh QR is this design's own recovery from an expired
// invite, so a person will reach for it -- and it must never discard a
// proposal they are in the middle of reading. One sentence covers both
// halves: the QR on the screen is the invite this device will answer.
#[tokio::test]
async fn a_new_invite_is_refused_while_a_decision_waits_and_replaces_when_none_does() {
    let alice = identity(1);
    let bob = identity(2);

    let invites = Arc::new(LinkInviteState::new());
    let sink = AnsweringSink::new(invites.clone(), LinkDecision::Decline);
    sink.reopening(an_invite(&alice, invite_id(4), half(0xC3)));
    let (f, _dir) = fixture(invites, sink.clone());
    f.invites
        .open(an_invite(&alice, invite_id(9), half(0xA1)))
        .expect("nothing is pending");

    let mut send = RecordingSend {
        written: f.written.clone(),
    };
    f.service
        .serve(
            &mut send,
            a_reply(invite_id(9), &bob, half(0xB2)),
            bob.device_id(),
            MAX_FRAME,
        )
        .await
        .expect("the sink declined it");

    let refused = sink
        .reopen_while_pending
        .lock()
        .expect("not poisoned")
        .take()
        .expect("the sink attempted to open a second invite while its own decision waited");
    assert!(matches!(refused, Err(InviteWindowError::DecisionPending)));

    // Nothing is pending now, so the same call succeeds and the window
    // holds the invite the person is being shown.
    f.invites
        .open(an_invite(&alice, invite_id(4), half(0xC3)))
        .expect("no decision waits any more");
    assert_eq!(
        f.invites
            .open_invite()
            .expect("an invite is open")
            .invite_id(),
        &invite_id(4)
    );
}

// ---- One warm cache ------------------------------------------------------

// `verify_link` is a method on `PeerTrust` rather than a free function
// beside it for one reason: the cache an ordinary classification warms is
// the cache a link exchange reads. A second cache would spend a fetch on
// a provider whose keys this device already holds.
#[tokio::test]
async fn verify_link_reads_the_cache_an_ordinary_classification_already_warmed() {
    let bob = identity(2);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = PeerTrust::new(profile(), fetch.clone());
    trust
        .install(&document(&[published_key(KID)]))
        .expect("a well-formed document");

    let account = trust
        .verify_link(
            &token(BOB_SUB, &bob, NOW),
            bob.identity_pub(),
            bob.agreement_pub(),
            bob.device_id(),
            clock_at(NOW).as_ref(),
        )
        .await
        .expect("a token this cache can already check");

    assert_eq!(account, AccountId::new(ISS, BOB_SUB));
    assert_eq!(
        fetch.calls(),
        0,
        "a warm cache spends no fetch, and the link path shares the one PeerTrust holds"
    );
}

// Step 6 is inexpressible on the link path: the account is the answer,
// and a stranger's account is exactly what an invite exists to admit.
// A `verify_link` that reached `classify` instead would refuse here.
#[tokio::test]
async fn an_account_this_device_has_never_seen_verifies_on_the_link_path() {
    let stranger = identity(7);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = PeerTrust::new(profile(), fetch);
    trust
        .install(&document(&[published_key(KID)]))
        .expect("a well-formed document");

    let account = trust
        .verify_link(
            &token("a-subject-nothing-here-has-ever-linked", &stranger, NOW),
            stranger.identity_pub(),
            stranger.agreement_pub(),
            stranger.device_id(),
            clock_at(NOW).as_ref(),
        )
        .await
        .expect("an unknown account is what this entry point returns rather than refuses");

    assert_eq!(
        account,
        AccountId::new(ISS, "a-subject-nothing-here-has-ever-linked")
    );
}

// A device whose `links.json` could not be read must not link either:
// `record` is where that failure surfaces, and docs/11 gives a failed
// store no decline reason at all, since none of the three is true of it.
#[tokio::test]
async fn a_registry_that_could_not_be_built_declines_with_no_reason() {
    let alice = identity(1);
    let bob = identity(2);

    let secrets = Arc::new(MemoryStore::default());
    let trust = PeerTrust::new(profile(), CountingFetch::serving(&[published_key(KID)]));
    trust
        .install(&document(&[published_key(KID)]))
        .expect("a well-formed document");

    let invites = Arc::new(LinkInviteState::new());
    let sink = AnsweringSink::new(invites.clone(), LinkDecision::Approve);
    let service = LinkService::new(
        invites.clone(),
        LinkServiceParts {
            trust: Ok(Arc::new(trust)),
            registry: Err("link registry at links.json: malformed".to_string()),
            secrets: Ok(secrets.clone()),
        },
        sink,
        clock_at(NOW),
    );

    invites
        .open(an_invite(&alice, invite_id(9), half(0xA1)))
        .expect("nothing is pending");

    let written = Arc::new(Mutex::new(Vec::new()));
    let mut send = RecordingSend {
        written: written.clone(),
    };
    let outcome = service
        .serve(
            &mut send,
            a_reply(invite_id(9), &bob, half(0xB2)),
            bob.device_id(),
            MAX_FRAME,
        )
        .await
        .expect("a failed store is a completed exchange, not an error");

    match outcome {
        tauri_plugin_tradr::link_exchange::LinkOutcome::Declined { reason, detail } => {
            assert_eq!(
                reason, None,
                "none of the three reasons is true of a failed store"
            );
            assert!(
                detail.is_some(),
                "the local reason names the file the user has to fix"
            );
        }
        other => panic!("a store that fails must decline, got {other:?}"),
    }
}

// A person who never answers leaves a parked sender behind, and only the
// invite's own deadline ends the wait. Nothing else in this suite reaches
// that path, so without this test the slot left behind -- which refuses
// every later `open` forever -- would be invisible.
#[tokio::test(start_paused = true)]
async fn a_wait_that_reaches_the_deadline_leaves_no_parked_decision_behind() {
    let alice = identity(1);
    let bob = identity(2);

    let invites = Arc::new(LinkInviteState::new());
    let (f, _dir) = fixture(invites, Arc::new(UnansweringSink));
    f.invites
        .open(an_invite(&alice, invite_id(9), half(0xA1)))
        .expect("nothing is pending");

    let mut send = RecordingSend {
        written: f.written.clone(),
    };
    let outcome = f
        .service
        .serve(
            &mut send,
            a_reply(invite_id(9), &bob, half(0xB2)),
            bob.device_id(),
            MAX_FRAME,
        )
        .await
        .expect("a deadline reached is a completed exchange, not an error");

    match outcome {
        tauri_plugin_tradr::link_exchange::LinkOutcome::Declined { reason, detail } => {
            assert_eq!(reason, Some(LinkDeclineReason::InviteExpired));
            assert_eq!(detail, None, "the window closing is nobody's local failure");
        }
        other => panic!("an unanswered wait must decline, got {other:?}"),
    }

    assert!(
        f.invites.pending().is_none(),
        "an exchange that ended unanswered must not leave its slot behind"
    );
    f.invites
        .open(an_invite(&alice, invite_id(4), half(0xC3)))
        .expect("a fresh invite opens once the abandoned decision is gone");
}

//! Tests for WI-M6-006f: the replier's testable core (`execute_send_link_reply`)
//! and the dial target helper (`dial_target`). The Tauri commands wire these
//! together with no logic of their own, so nothing here drives them through
//! `tauri::State`. Fixtures are modelled on `tests/link_service.rs` (JWKS
//! and `MemoryStore`) and `tests/link_stream.rs` (the mock secure channel).

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
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

use tauri_plugin_tradr::link_commands::{ReplierDeps, dial_target, execute_send_link_reply};
use tauri_plugin_tradr::link_exchange::{LinkExchangeError, LinkOutcome};
use tauri_plugin_tradr::peer_trust::{JwksFetch, PeerTrust};
use tradr_core::{
    BoxFuture, Clock, DeviceId, HalfSecret, Invite, InviteId, KeyStore, LinkApprove, LinkDecline,
    LinkDeclineReason, Monotonic, PeerList, PublicIdentity, RecvStream, Rng, RngError, SecretStore,
    SecretStoreError, SecureChannel, SendStream, StorageLevel, TransportError, TransportId,
    UnixTime,
};
use tradr_identity::{
    Jwk, LinkRegistry, NonceBinding, ProviderProfile, SignatureAlgorithm, SoftwareKeyStore,
    attestation_nonce, derive_link_id, derive_link_secret, link_secret_slot,
};
use tradr_proto::framing::{Frame, FrameDecoder};
use tradr_proto::link::{
    decode_link_reply_frame, encode_link_approve_frame, encode_link_decline_frame,
};

// ---- Provider fixtures (modelled on tests/link_service.rs) ---------------

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

// A token binding `bound_to`'s two keys in its nonce -- the invite's own
// token proves alice controls the identity/agreement pair the invite carries.
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

// `verify_link_attestation`'s key join runs before any token parsing, so a
// test that never reaches step 1/2 can carry a token nobody ever checks.
const UNCHECKED_TOKEN: &str = "not-a-jwt-and-never-parsed-by-this-fixture";

struct FixedClock {
    wall: UnixTime,
}

impl Clock for FixedClock {
    fn now(&self) -> UnixTime {
        self.wall
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(Instant::now())
    }
}

fn clock_at(wall_secs: i64) -> FixedClock {
    FixedClock {
        wall: UnixTime::from_secs(wall_secs),
    }
}

struct SeededRng {
    state: AtomicU64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
        }
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        for slot in buf.iter_mut() {
            let mut x = self.state.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state.store(x, Ordering::Relaxed);
            *slot = (x >> 24) as u8;
        }
        Ok(())
    }
}

// Never reached once the cache is pre-warmed by `install`, so a real fetch
// would mean a test's fixture stopped matching the token it signed.
struct NoFetch;

impl JwksFetch for NoFetch {
    fn fetch<'a>(&'a self, _jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move { Err("no fetch is expected once the cache is warmed".to_string()) })
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

    fn is_empty(&self) -> bool {
        self.slots
            .lock()
            .expect("the slot map is never poisoned")
            .is_empty()
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

// ---- Fixture assembly ------------------------------------------------------

struct Fixture {
    trust: Arc<PeerTrust>,
    registry: Arc<Mutex<LinkRegistry>>,
    secrets: Arc<MemoryStore>,
}

// The `TempDir` comes back beside the fixture rather than inside it: it is a
// guard nothing reads, and a field nothing reads is a dead-code warning
// under `-D warnings` (the same reason tests/link_service.rs does this).
fn fixture() -> (Fixture, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let registry = Arc::new(Mutex::new(
        LinkRegistry::load(&dir.path().join("links.json")).expect("a missing file is empty"),
    ));
    let secrets = Arc::new(MemoryStore::default());
    let trust = PeerTrust::new(profile(), Arc::new(NoFetch));
    trust
        .install(&document(&[published_key(KID)]))
        .expect("a well-formed document");

    (
        Fixture {
            trust: Arc::new(trust),
            registry,
            secrets,
        },
        dir,
    )
}

fn half(byte: u8) -> HalfSecret {
    HalfSecret::from_bytes(&[byte; 16]).expect("16 bytes always fit a HalfSecret")
}

fn invite_id(byte: u8) -> InviteId {
    InviteId::from_bytes(&[byte; 16]).expect("16 bytes always fit an InviteId")
}

fn an_invite(
    inviter: &PublicIdentity,
    id: InviteId,
    half_a: HalfSecret,
    expires_at_secs: i64,
    attestation_token: String,
) -> Invite {
    Invite::new(
        id,
        inviter.identity_pub().clone(),
        inviter.agreement_pub().clone(),
        attestation_token,
        half_a,
        UnixTime::from_secs(expires_at_secs),
    )
}

// ---- The mock secure channel (modelled on tests/link_stream.rs) -----------

struct MemorySendStream {
    sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl SendStream for MemorySendStream {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let sender = self.sender.as_ref().ok_or(TransportError::Closed)?;
            sender
                .send(buf.to_vec())
                .await
                .map_err(|_| TransportError::Closed)?;
            Ok(())
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.sender = None;
            Ok(())
        })
    }
}

struct MemoryRecvStream {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buffered: Vec<u8>,
}

impl RecvStream for MemoryRecvStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            if self.buffered.is_empty() {
                match self.receiver.recv().await {
                    Some(chunk) => self.buffered = chunk,
                    None => return Ok(0),
                }
            }
            let to_read = self.buffered.len().min(buf.len());
            buf[..to_read].copy_from_slice(&self.buffered[..to_read]);
            self.buffered.drain(..to_read);
            Ok(to_read)
        })
    }
}

fn memory_stream_pair() -> (
    (MemorySendStream, MemoryRecvStream),
    (MemorySendStream, MemoryRecvStream),
) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(32);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(32);
    let peer_a = (
        MemorySendStream {
            sender: Some(tx_a_to_b),
        },
        MemoryRecvStream {
            receiver: rx_b_to_a,
            buffered: Vec::new(),
        },
    );
    let peer_b = (
        MemorySendStream {
            sender: Some(tx_b_to_a),
        },
        MemoryRecvStream {
            receiver: rx_a_to_b,
            buffered: Vec::new(),
        },
    );
    (peer_a, peer_b)
}

type StreamPair = (Box<dyn SendStream>, Box<dyn RecvStream>);

struct MockSecureChannel {
    peer_id: DeviceId,
    max_frame_size: u32,
    bi_tx: tokio::sync::mpsc::Sender<StreamPair>,
    bi_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<StreamPair>>,
}

impl SecureChannel for MockSecureChannel {
    fn peer(&self) -> DeviceId {
        self.peer_id
    }

    fn transport(&self) -> TransportId {
        TransportId::new("memory")
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(5)
    }

    fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    fn open_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        Box::pin(async move {
            let (peer_a, peer_b) = memory_stream_pair();
            let bi_b: StreamPair = (Box::new(peer_b.0), Box::new(peer_b.1));
            self.bi_tx
                .send(bi_b)
                .await
                .map_err(|_| TransportError::Closed)?;
            let bi_a: StreamPair = (Box::new(peer_a.0), Box::new(peer_a.1));
            Ok(bi_a)
        })
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        Box::pin(async move {
            let mut rx = self.bi_rx.lock().await;
            rx.recv().await.ok_or(TransportError::Closed)
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

// Builds two ends of one channel: `chan_a`'s `peer()` reports `peer_b_id`
// and vice versa, mirroring the pairing tests/link_stream.rs uses.
fn mock_channel_pair(
    peer_a_id: DeviceId,
    peer_b_id: DeviceId,
    max_frame_size: u32,
) -> (MockSecureChannel, MockSecureChannel) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(16);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(16);

    let chan_a = MockSecureChannel {
        peer_id: peer_b_id,
        max_frame_size,
        bi_tx: tx_a_to_b,
        bi_rx: tokio::sync::Mutex::new(rx_b_to_a),
    };
    let chan_b = MockSecureChannel {
        peer_id: peer_a_id,
        max_frame_size,
        bi_tx: tx_b_to_a,
        bi_rx: tokio::sync::Mutex::new(rx_a_to_b),
    };
    (chan_a, chan_b)
}

// A single-ended channel whose `open_bi` hands back a send half that
// records every byte written and a recv half nothing in these tests ever
// reads, for the two tests that never reach a round trip at all.
struct RecordingChannel {
    peer_id: DeviceId,
    max_frame_size: u32,
    written: Arc<Mutex<Vec<u8>>>,
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

struct ClosedRecv;

impl RecvStream for ClosedRecv {
    fn read<'a>(&'a mut self, _buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move { Ok(0) })
    }
}

impl SecureChannel for RecordingChannel {
    fn peer(&self) -> DeviceId {
        self.peer_id
    }

    fn transport(&self) -> TransportId {
        TransportId::new("memory")
    }

    fn rtt(&self) -> Duration {
        Duration::from_millis(5)
    }

    fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    fn open_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        Box::pin(async move {
            let send = RecordingSend {
                written: self.written.clone(),
            };
            Ok((
                Box::new(send) as Box<dyn SendStream>,
                Box::new(ClosedRecv) as Box<dyn RecvStream>,
            ))
        })
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<StreamPair, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async move { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

// Reads exactly one frame off a raw memory stream, the way tests/link_stream.rs's
// own helper does, generalised to `&mut dyn RecvStream` since it reads off a
// channel's boxed streams rather than the concrete memory type directly.
async fn read_one_frame(recv: &mut dyn RecvStream, max_frame_size: u32) -> Frame {
    let mut len_bytes = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = recv.read(&mut len_bytes[got..]).await.expect("read");
        assert!(n > 0, "stream closed before a full length prefix arrived");
        got += n;
    }
    let announced = u32::from_be_bytes(len_bytes);
    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    let mut got_payload = 0;
    while got_payload < announced as usize {
        let n = recv.read(&mut raw[4 + got_payload..]).await.expect("read");
        assert!(n > 0, "stream closed before the announced payload arrived");
        got_payload += n;
    }
    let mut decoder = FrameDecoder::new(max_frame_size);
    decoder.feed(&raw);
    decoder
        .next_frame()
        .expect("framing must decode")
        .expect("a whole frame was fed")
}

// ---- 1. An approve on the wire links, and the secret is stored ------------

#[tokio::test]
async fn an_approve_on_the_wire_links_and_the_secret_is_stored() {
    let alice = identity(1);
    let bob = identity(2);

    let invite = an_invite(
        &alice,
        invite_id(9),
        half(0xA1),
        NOW + 300,
        token(ALICE_SUB, &alice, NOW),
    );
    let (f, _dir) = fixture();
    let (chan_replier, chan_inviter) =
        mock_channel_pair(bob.device_id(), alice.device_id(), MAX_FRAME);

    let deps = ReplierDeps {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob-token-not-checked-here".to_string(),
        trust: f.trust.clone(),
        registry: f.registry.clone(),
        secrets: f.secrets.clone(),
    };
    let clock = clock_at(NOW);
    let rng = SeededRng::new(7);

    let replier_task = execute_send_link_reply(&chan_replier, deps, &clock, &rng);

    let inviter_task = async {
        let (mut send, mut recv) = chan_inviter
            .accept_bi()
            .await
            .expect("the replier opens a stream");
        let frame = read_one_frame(recv.as_mut(), MAX_FRAME).await;
        let reply = decode_link_reply_frame(&frame).expect("bob's reply decodes");
        let secret = derive_link_secret(invite.half_secret(), reply.half_secret());
        let link_id = derive_link_id(&secret);
        let approve = LinkApprove::new(*invite.invite_id(), link_id);
        let frame_bytes = encode_link_approve_frame(&approve, MAX_FRAME).expect("encodes");
        send.write_all(&frame_bytes).await.expect("write");
        (link_id, secret)
    };

    let (outcome, (expected_link_id, expected_secret)) = tokio::join!(replier_task, inviter_task);
    let outcome = outcome.expect("a scripted approve completes");
    assert_eq!(outcome, LinkOutcome::Linked(expected_link_id));

    assert!(
        f.registry
            .lock()
            .expect("not poisoned")
            .link(&expected_link_id)
            .is_some(),
        "the approved link is in the registry"
    );
    assert_eq!(
        f.secrets
            .get(&link_secret_slot(&expected_link_id))
            .as_deref(),
        Some(expected_secret.as_bytes().as_slice()),
        "the secret is stored under the slot the link_id names"
    );
}

// ---- 2. A decline on the wire stores nothing -------------------------------

#[tokio::test]
async fn a_decline_on_the_wire_stores_nothing() {
    let alice = identity(1);
    let bob = identity(2);

    let invite = an_invite(
        &alice,
        invite_id(9),
        half(0xA1),
        NOW + 300,
        token(ALICE_SUB, &alice, NOW),
    );
    let (f, _dir) = fixture();
    let (chan_replier, chan_inviter) =
        mock_channel_pair(bob.device_id(), alice.device_id(), MAX_FRAME);

    let deps = ReplierDeps {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob-token-not-checked-here".to_string(),
        trust: f.trust.clone(),
        registry: f.registry.clone(),
        secrets: f.secrets.clone(),
    };
    let clock = clock_at(NOW);
    let rng = SeededRng::new(7);

    let replier_task = execute_send_link_reply(&chan_replier, deps, &clock, &rng);

    let inviter_task = async {
        let (mut send, mut recv) = chan_inviter
            .accept_bi()
            .await
            .expect("the replier opens a stream");
        let _frame = read_one_frame(recv.as_mut(), MAX_FRAME).await;
        let decline = LinkDecline::new(*invite.invite_id(), Some(LinkDeclineReason::UserDeclined));
        let frame_bytes = encode_link_decline_frame(&decline, MAX_FRAME).expect("encodes");
        send.write_all(&frame_bytes).await.expect("write");
    };

    let (outcome, _) = tokio::join!(replier_task, inviter_task);
    let outcome = outcome.expect("a scripted decline completes");
    assert_eq!(
        outcome,
        LinkOutcome::Declined {
            reason: Some(LinkDeclineReason::UserDeclined),
            detail: None,
        }
    );

    assert!(
        f.registry.lock().expect("not poisoned").links().is_empty(),
        "a decline must not record a link"
    );
    assert!(
        f.secrets.is_empty(),
        "a decline must not store a secret under any slot"
    );
}

// ---- 3. An invite already past its window is refused before a byte is written --

#[tokio::test]
async fn an_expired_invite_is_refused_before_a_byte_is_written() {
    let alice = identity(1);
    let bob = identity(2);

    // Well past any caller's skew allowance, so this holds regardless of
    // the exact constant `execute_send_link_reply` passes as its own.
    let invite = an_invite(
        &alice,
        invite_id(9),
        half(0xA1),
        NOW - 10_000,
        UNCHECKED_TOKEN.to_string(),
    );
    let (f, _dir) = fixture();
    let written = Arc::new(Mutex::new(Vec::new()));
    let channel = RecordingChannel {
        peer_id: alice.device_id(),
        max_frame_size: MAX_FRAME,
        written: written.clone(),
    };

    let deps = ReplierDeps {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob-token-not-checked-here".to_string(),
        trust: f.trust.clone(),
        registry: f.registry.clone(),
        secrets: f.secrets.clone(),
    };
    let clock = clock_at(NOW);
    let rng = SeededRng::new(7);

    let outcome = execute_send_link_reply(&channel, deps, &clock, &rng).await;

    assert!(matches!(outcome, Err(LinkExchangeError::InviteExpired)));
    assert!(
        written.lock().expect("not poisoned").is_empty(),
        "nothing may reach the wire before the expiry check runs"
    );
}

// ---- 4. Verification is asked about the channel's DeviceId, never the invite's --

#[tokio::test]
async fn verification_is_asked_about_the_channels_device_id_never_one_recomputed_from_the_invite() {
    let alice = identity(1);
    let bob = identity(2);
    let carol = identity(3);

    let invite = an_invite(
        &alice,
        invite_id(9),
        half(0xA1),
        NOW + 300,
        UNCHECKED_TOKEN.to_string(),
    );
    let recomputed_from_invite =
        DeviceId::from_identity_digest(blake3::hash(invite.identity_pub().as_bytes()).as_bytes());
    assert_eq!(
        recomputed_from_invite,
        alice.device_id(),
        "the fixture's own invite must recompute to alice's id"
    );
    assert_ne!(
        carol.device_id(),
        recomputed_from_invite,
        "the fixture must keep the channel's id and the invite-derived id apart"
    );
    assert_ne!(carol.device_id(), bob.device_id());

    let (f, _dir) = fixture();
    let channel = RecordingChannel {
        peer_id: carol.device_id(),
        max_frame_size: MAX_FRAME,
        written: Arc::new(Mutex::new(Vec::new())),
    };

    let deps = ReplierDeps {
        invite: &invite,
        our_identity: &bob,
        our_attestation_token: "bob-token-not-checked-here".to_string(),
        trust: f.trust.clone(),
        registry: f.registry.clone(),
        secrets: f.secrets.clone(),
    };
    let clock = clock_at(NOW);
    let rng = SeededRng::new(7);

    let outcome = execute_send_link_reply(&channel, deps, &clock, &rng).await;

    match outcome {
        Err(LinkExchangeError::VerificationFailed(reason)) => {
            let expected = format!(
                "attestation claims device {recomputed_from_invite}, but the channel authenticated {}",
                carol.device_id()
            );
            assert_eq!(
                reason, expected,
                "verify_link must be asked about the channel's own DeviceId"
            );
        }
        other => {
            panic!("a channel authenticating a third device must fail verification, got {other:?}")
        }
    }
}

// ---- 5. A Device ID no observation carries is its own sentence ------------

#[test]
fn a_device_id_no_observation_carries_is_its_own_sentence() {
    let alice = identity(1);
    let invite = an_invite(
        &alice,
        invite_id(9),
        half(0xA1),
        NOW + 300,
        UNCHECKED_TOKEN.to_string(),
    );
    let list = PeerList::new();

    let err = dial_target(&invite, &list)
        .expect_err("an empty peer list carries no observation of the inviter's device");

    let expected_id =
        DeviceId::from_identity_digest(blake3::hash(invite.identity_pub().as_bytes()).as_bytes());
    assert!(
        err.contains(&expected_id.to_string()),
        "the error names the device id no observation carries: {err}"
    );
    assert!(
        err.contains("has not been discovered"),
        "the error reads as \"not discovered\": {err}"
    );
    assert!(
        !err.to_lowercase().contains("failed to connect"),
        "a not-found id must read differently from a dial failure: {err}"
    );
}

//! Registration and collecting against an in-memory Brokr: no network, no node.
//! The Attestation is the shared fake provider in `common`, with its JWKS
//! installed in a `PeerTrust` exactly as `peer_trust.rs` does.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

mod common;

use common::{
    AUD, CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, clock_at, device_store, document,
    identity, profile, published_key, token,
};
use futures_util::stream;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey};
use tradr_app::brokr::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, CollectContext,
    DeliveryId, InboxEntry, OutboxEntry, PlacedDeliveries, PlacedError, RegisterRequest, Session,
    collect_once, register,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_core::{
    ContentHash, DeviceId, DomainTag, KeyBinding, KeyStore, LinkSecret, PublicIdentity, RelPath,
    RootId, TransferId, UnixTime,
};
use tradr_identity::envelope::{EnvelopeItem, EnvelopeSender, EnvelopeWriter};
use tradr_identity::{AccountId, OsRng, SoftwareKeyStore};
use tradr_vfs::NativeVfs;

const SALT_HEX: &str = "00112233445566778899aabbccddeeff";
const NONCE_HEX: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const DAY: i64 = 24 * 3600;

struct FakeBrokr {
    registrations: Mutex<Vec<RegisterRequest>>,
    inbox: Vec<InboxEntry>,
    bodies: HashMap<String, Vec<u8>>,
    break_after: Option<usize>,
    acknowledged: Mutex<Vec<String>>,
    fail_ack_network: Mutex<usize>,
    downloads: Mutex<usize>,
}

impl FakeBrokr {
    fn new() -> Self {
        Self {
            registrations: Mutex::new(Vec::new()),
            inbox: Vec::new(),
            bodies: HashMap::new(),
            break_after: None,
            acknowledged: Mutex::new(Vec::new()),
            fail_ack_network: Mutex::new(0),
            downloads: Mutex::new(0),
        }
    }

    fn holding(mut self, id: &str, uploaded_at: i64, body: Vec<u8>) -> Self {
        self.inbox.push(InboxEntry {
            id: id.to_string(),
            sender_device_id: String::new(),
            size: body.len() as u64,
            uploaded_at,
        });
        self.bodies.insert(id.to_string(), body);
        self
    }

    fn fail_acknowledge_times(&self, times: usize) {
        *self
            .fail_ack_network
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = times;
    }

    fn download_count(&self) -> usize {
        *self.downloads.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn acknowledged(&self) -> Vec<String> {
        self.acknowledged
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl BrokrApi for FakeBrokr {
    fn info(&self) -> BrokrFuture<'_, BrokrInfo> {
        Box::pin(async {
            Ok(BrokrInfo {
                version: 1,
                account_salt: SALT_HEX.to_string(),
                delivery_ttl_days: 30,
                delivery_max_bytes: 1 << 30,
                storage_max_bytes: 1 << 40,
            })
        })
    }

    fn challenge(&self) -> BrokrFuture<'_, Challenge> {
        Box::pin(async {
            Ok(Challenge {
                nonce: NONCE_HEX.to_string(),
            })
        })
    }

    fn register(&self, request: RegisterRequest) -> BrokrFuture<'_, Session> {
        Box::pin(async move {
            self.registrations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(request);
            Ok(Session::new("session-token".to_string()))
        })
    }

    fn inbox<'a>(&'a self, _session: &'a Session) -> BrokrFuture<'a, Vec<InboxEntry>> {
        Box::pin(async move { Ok(self.inbox.clone()) })
    }

    fn download<'a>(
        &'a self,
        _session: &'a Session,
        id: &'a str,
    ) -> BrokrFuture<'a, ByteStream<'a>> {
        *self.downloads.lock().unwrap_or_else(|p| p.into_inner()) += 1;
        Box::pin(async move {
            let body = self
                .bodies
                .get(id)
                .ok_or_else(|| BrokrError::Rejected("no such delivery".to_string()))?;
            let mut items: Vec<Result<Vec<u8>, BrokrError>> =
                body.chunks(4096).map(|chunk| Ok(chunk.to_vec())).collect();
            if let Some(after) = self.break_after {
                items.truncate(after);
                items.push(Err(BrokrError::Network("connection reset".to_string())));
            }
            let stream: ByteStream<'a> = Box::pin(stream::iter(items));
            Ok(stream)
        })
    }

    fn acknowledge<'a>(&'a self, _session: &'a Session, id: &'a str) -> BrokrFuture<'a, ()> {
        let mut fail = self
            .fail_ack_network
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if *fail > 0 {
            *fail -= 1;
            return Box::pin(async {
                Err(BrokrError::Network("acknowledgement failed".to_string()))
            });
        }
        Box::pin(async move {
            self.acknowledged
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(id.to_string());
            Ok(())
        })
    }

    fn upload<'a>(
        &'a self,
        _session: &'a Session,
        _total_len: u64,
        _body: ByteStream<'static>,
    ) -> BrokrFuture<'a, DeliveryId> {
        Box::pin(async { Err(BrokrError::Rejected("not supported in fake".to_string())) })
    }

    fn outbox<'a>(&'a self, _session: &'a Session) -> BrokrFuture<'a, Vec<OutboxEntry>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn own_account() -> AccountId {
    AccountId::new(ISS, OWN_SUB)
}

fn transfer_id() -> TransferId {
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("transfer id")
}

fn sealed(sender_seed: u8, recipient: &PublicIdentity, files: &[(&str, &[u8])]) -> Vec<u8> {
    sealed_for_account(sender_seed, OWN_SUB, recipient, files)
}

fn sealed_for_account(
    sender_seed: u8,
    sub: &str,
    recipient: &PublicIdentity,
    files: &[(&str, &[u8])],
) -> Vec<u8> {
    let store = device_store(sender_seed);
    let sender_identity = identity(sender_seed);
    let signature = store
        .sign(
            DomainTag::KeyBind,
            sender_identity.agreement_pub().as_bytes(),
        )
        .expect("sign binding");
    let sender = EnvelopeSender::new(
        sender_identity.clone(),
        KeyBinding::new(
            sender_identity.agreement_pub().clone(),
            signature,
            UnixTime::from_secs(NOW + 30 * DAY),
        ),
        token(KID, sub, AUD, &sender_identity, NOW),
    );
    let items = files
        .iter()
        .map(|(name, bytes)| {
            EnvelopeItem::new(
                RelPath::new(name).expect("relpath"),
                bytes.len() as u64,
                ContentHash::from_bytes(blake3::hash(bytes).into()),
            )
        })
        .collect();
    let (mut writer, mut out) = EnvelopeWriter::new(
        recipient,
        &sender,
        &store,
        &OsRng,
        transfer_id(),
        UnixTime::from_secs(NOW),
        items,
    )
    .expect("writer");
    for (_, bytes) in files {
        out.extend(writer.push(bytes).expect("push"));
    }
    out.extend(writer.finish().expect("finish"));
    out
}

fn trust(installed: bool) -> (PeerTrust, Arc<CountingFetch>) {
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = PeerTrust::new(profile(), fetch.clone());
    if installed {
        trust
            .install(JWKS_URI, &document(&[published_key(KID)]))
            .expect("a well-formed document");
    }
    (trust, fetch)
}

struct Fixture {
    dir: tempfile::TempDir,
    _placed_dir: tempfile::TempDir,
    placed: PlacedDeliveries,
    vfs: NativeVfs,
    recipient_store: SoftwareKeyStore,
    recipient: PublicIdentity,
    arrivals: Mutex<Vec<(DeviceId, Vec<String>)>>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let placed_dir = tempfile::tempdir().expect("placed tempdir");
        let placed = PlacedDeliveries::new(placed_dir.path());
        let vfs = NativeVfs::new();
        vfs.register_root(RootId::new(1), dir.path().to_path_buf(), false)
            .expect("register root");
        Self {
            dir,
            _placed_dir: placed_dir,
            placed,
            vfs,
            recipient_store: device_store(2),
            recipient: identity(2),
            arrivals: Mutex::new(Vec::new()),
        }
    }

    fn arrivals(&self) -> Vec<(DeviceId, Vec<String>)> {
        self.arrivals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    async fn collect(
        &self,
        api: &FakeBrokr,
        trust: &PeerTrust,
    ) -> Result<tradr_app::brokr::CollectReport, BrokrError> {
        self.collect_linked(api, trust, &[]).await
    }

    async fn collect_linked(
        &self,
        api: &FakeBrokr,
        trust: &PeerTrust,
        linked: &[AccountId],
    ) -> Result<tradr_app::brokr::CollectReport, BrokrError> {
        let clock = clock_at(NOW);
        let agree = |peer: &_| self.recipient_store.agree(peer);
        let own = own_account();
        let on_arrival = |from: DeviceId, placed: &[RelPath]| {
            self.arrivals
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((from, placed.iter().map(|p| p.to_string()).collect()));
        };
        let ctx = CollectContext {
            vfs: &self.vfs,
            root: RootId::new(1),
            recipient: &self.recipient,
            agree: &agree,
            clock: &clock,
            trust,
            own_account: &own,
            linked_accounts: linked,
            on_arrival: &on_arrival,
            placed: &self.placed,
        };
        collect_once(api, &Session::new("session-token".to_string()), &ctx).await
    }

    fn assert_nothing_left_but_empty_staging(&self) {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.path())
            .expect("read root")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.retain(|n| n != ".tradr-partial");
        assert!(names.is_empty(), "unexpected files: {names:?}");
        let staging = self.dir.path().join(".tradr-partial");
        if staging.exists() {
            assert_eq!(
                std::fs::read_dir(&staging).expect("read staging").count(),
                0,
                "a partial directory was left behind"
            );
        }
    }
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).expect("placed file")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn registration_sends_tags_a_verifiable_signature_and_the_device_id() {
    let api = FakeBrokr::new();
    let store = device_store(2);
    let me = identity(2);
    let secret = LinkSecret::from_bytes(&[7u8; 32]).expect("link secret");

    let session = register(
        &api,
        &store,
        &me,
        &own_account(),
        &[secret],
        "the-join-token",
    )
    .await
    .expect("registered");

    assert_eq!(session.as_str(), "session-token");
    let sent = api
        .registrations
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    let mut account_input = own_account().to_bytes();
    account_input.extend(unhex(SALT_HEX));
    assert_eq!(
        request.account_tag,
        hex(blake3::hash(&account_input).as_bytes())
    );
    assert_eq!(
        request.link_tags,
        vec![hex(blake3::hash(&[7u8; 32]).as_bytes())]
    );
    assert_eq!(request.device_id, me.device_id().to_string());
    assert_eq!(request.identity_pub, hex(me.identity_pub().as_bytes()));
    assert_eq!(request.join_token, "the-join-token");
    assert_eq!(request.nonce, NONCE_HEX);

    let key = VerifyingKey::from_sec1_bytes(me.identity_pub().as_bytes()).expect("key");
    let raw = unhex(&request.signature);
    assert_eq!(raw.len(), 64);
    let signature = EcdsaSignature::from_slice(&raw).expect("r || s");
    let mut signed = b"tradr-brokr-v1".to_vec();
    signed.extend(unhex(NONCE_HEX));
    assert!(key.verify(&signed, &signature).is_ok());
    let mut other = b"tradr-brokr-v1".to_vec();
    other.extend([0u8; 32]);
    assert!(key.verify(&other, &signature).is_err());
}

#[tokio::test]
async fn a_delivery_is_collected_acknowledged_and_reported() {
    let fixture = Fixture::new();
    let content = vec![42u8; 2 * 1024 * 1024 + 17];
    let body = sealed(1, &fixture.recipient, &[("hello.bin", &content)]);
    let api = FakeBrokr::new().holding("aa01", 1, body);
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");

    assert_eq!(report.delivered, 1);
    assert!(report.refused.is_empty());
    assert_eq!(read(fixture.dir.path(), "hello.bin"), content);
    assert_eq!(api.acknowledged(), vec!["aa01".to_string()]);
    assert_eq!(
        fixture.arrivals(),
        vec![(identity(1).device_id(), vec!["hello.bin".to_string()])]
    );
    assert!(
        !fixture
            .dir
            .path()
            .join(".tradr-partial/deferred-aa01")
            .exists()
    );
}

#[tokio::test]
async fn a_colliding_name_lands_with_a_suffix() {
    let fixture = Fixture::new();
    let first = sealed(1, &fixture.recipient, &[("photo.jpg", b"first photo")]);
    let second = sealed(1, &fixture.recipient, &[("photo.jpg", b"second photo")]);
    let api = FakeBrokr::new()
        .holding("bb02", 2, second)
        .holding("bb01", 1, first);
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");

    assert_eq!(report.delivered, 2);
    assert_eq!(read(fixture.dir.path(), "photo.jpg"), b"first photo");
    assert_eq!(read(fixture.dir.path(), "photo (2).jpg"), b"second photo");
}

#[tokio::test]
async fn a_delivery_for_another_recipient_is_refused_and_acknowledged() {
    let fixture = Fixture::new();
    let body = sealed(1, &identity(3), &[("secret.txt", b"not for this device")]);
    let api = FakeBrokr::new().holding("cc01", 1, body);
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");

    assert_eq!(report.delivered, 0);
    assert_eq!(report.refused.len(), 1);
    assert_eq!(report.refused[0].0, "cc01");
    assert!(!report.refused[0].1.is_empty());
    assert_eq!(api.acknowledged(), vec!["cc01".to_string()]);
    assert!(fixture.arrivals().is_empty());
    fixture.assert_nothing_left_but_empty_staging();
}

#[tokio::test]
async fn a_stream_that_breaks_leaves_the_delivery_on_the_brokr() {
    let fixture = Fixture::new();
    let content = vec![9u8; 3 * 1024 * 1024];
    let body = sealed(1, &fixture.recipient, &[("big.bin", &content)]);
    let mut api = FakeBrokr::new().holding("dd01", 1, body);
    api.break_after = Some(200);
    let (trust, _) = trust(true);

    let outcome = fixture.collect(&api, &trust).await;

    assert!(
        matches!(outcome, Err(BrokrError::Network(_))),
        "{outcome:?}"
    );
    assert!(api.acknowledged().is_empty());
    assert!(fixture.arrivals().is_empty());
    fixture.assert_nothing_left_but_empty_staging();
}

#[tokio::test]
async fn a_missing_key_is_fetched_once_and_the_delivery_retried() {
    let fixture = Fixture::new();
    let body = sealed(1, &fixture.recipient, &[("late.txt", b"after a fetch")]);
    let api = FakeBrokr::new().holding("ee01", 1, body);
    let (trust, fetch) = trust(false);

    let report = fixture.collect(&api, &trust).await.expect("pass");

    assert_eq!(report.delivered, 1);
    assert_eq!(fetch.calls(), 1);
    assert_eq!(fetch.uris(), vec![JWKS_URI.to_string()]);
    assert_eq!(read(fixture.dir.path(), "late.txt"), b"after a fetch");
}

#[tokio::test]
async fn a_sender_of_an_unrelated_account_is_refused_and_acknowledged() {
    let fixture = Fixture::new();
    let body = sealed_for_account(
        1,
        "stranger-subject",
        &fixture.recipient,
        &[("intruder.txt", b"from nobody we know")],
    );
    let api = FakeBrokr::new().holding("ff01", 1, body);
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");

    assert_eq!(report.delivered, 0);
    assert_eq!(report.refused.len(), 1);
    assert_eq!(report.refused[0].0, "ff01");
    assert_eq!(api.acknowledged(), vec!["ff01".to_string()]);
    assert!(fixture.arrivals().is_empty());
    fixture.assert_nothing_left_but_empty_staging();
}

#[tokio::test]
async fn a_sender_of_a_linked_account_is_delivered() {
    let fixture = Fixture::new();
    let body = sealed_for_account(
        1,
        "linked-subject",
        &fixture.recipient,
        &[("from-link.txt", b"a linked account's file")],
    );
    let api = FakeBrokr::new().holding("ff02", 1, body);
    let (trust, _) = trust(true);
    let linked = [AccountId::new(ISS, "linked-subject")];

    let report = fixture
        .collect_linked(&api, &trust, &linked)
        .await
        .expect("pass");

    assert_eq!(report.delivered, 1);
    assert_eq!(
        read(fixture.dir.path(), "from-link.txt"),
        b"a linked account's file"
    );
    assert_eq!(api.acknowledged(), vec!["ff02".to_string()]);
}

#[tokio::test]
async fn failed_acknowledgement_leaves_delivery_remembered_and_placed_once() {
    let fixture = Fixture::new();
    let payload = sealed(1, &fixture.recipient, &[("hello.bin", b"hello content")]);
    let api = FakeBrokr::new().holding("ee01", NOW, payload);
    api.fail_acknowledge_times(1);
    let (trust, _) = trust(true);

    let err = fixture.collect(&api, &trust).await.expect_err("fail");
    assert!(matches!(err, BrokrError::Network(_)));
    assert_eq!(read(fixture.dir.path(), "hello.bin"), b"hello content");
    assert_eq!(fixture.arrivals().len(), 1);
    assert!(fixture.placed.contains("ee01").expect("contains"));
    assert!(api.acknowledged().is_empty());
    assert!(
        !fixture
            .dir
            .path()
            .join(".tradr-partial/deferred-ee01")
            .exists()
    );
}

#[tokio::test]
async fn pass_after_failed_acknowledgement_completes_without_redownload_or_duplicate() {
    let fixture = Fixture::new();
    let payload = sealed(1, &fixture.recipient, &[("hello.bin", b"hello content")]);
    let api = FakeBrokr::new().holding("ee01", NOW, payload);
    api.fail_acknowledge_times(1);
    let (trust, _) = trust(true);

    let err = fixture
        .collect(&api, &trust)
        .await
        .expect_err("first pass fails");
    assert!(matches!(err, BrokrError::Network(_)));

    let report = fixture.collect(&api, &trust).await.expect("pass");
    assert_eq!(api.download_count(), 1);
    assert!(!fixture.dir.path().join("hello (2).bin").exists());
    assert_eq!(api.acknowledged(), vec!["ee01".to_string()]);
    assert_eq!(fixture.arrivals().len(), 1);
    assert!(!fixture.placed.contains("ee01").expect("contains"));
    assert_eq!(report.delivered, 1);
}

#[tokio::test]
async fn a_remembered_id_has_its_staging_directory_removed() {
    let fixture = Fixture::new();
    let staging = fixture.dir.path().join(".tradr-partial/deferred-ee05");
    std::fs::create_dir_all(&staging).expect("create staging dir");
    std::fs::write(staging.join("leftover.bin"), b"leftover content").expect("write leftover");
    fixture.placed.remember("ee05").expect("remember");

    let api = FakeBrokr::new().holding("ee05", NOW, b"arbitrary body".to_vec());
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await;
    assert!(report.is_ok());
    assert_eq!(api.download_count(), 0);
    assert!(!staging.exists());
    assert_eq!(api.acknowledged(), vec!["ee05".to_string()]);
    assert!(!fixture.placed.contains("ee05").expect("contains"));
}

#[tokio::test]
async fn remembered_id_not_listed_in_inbox_is_forgotten_by_pass() {
    let fixture = Fixture::new();
    fixture.placed.remember("ee99").expect("remember");
    assert!(fixture.placed.contains("ee99").expect("contains"));

    let api = FakeBrokr::new();
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");
    assert_eq!(report.delivered, 0);
    assert!(!fixture.placed.contains("ee99").expect("forgotten"));
}

#[tokio::test]
async fn delivery_collected_with_nothing_failing_leaves_contains_false() {
    let fixture = Fixture::new();
    let payload = sealed(1, &fixture.recipient, &[("clean.bin", b"clean payload")]);
    let api = FakeBrokr::new().holding("ee02", NOW, payload);
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");
    assert_eq!(report.delivered, 1);
    assert!(!fixture.placed.contains("ee02").expect("contains"));
    assert_eq!(api.acknowledged(), vec!["ee02".to_string()]);
}

#[tokio::test]
async fn refused_delivery_is_never_remembered() {
    let fixture = Fixture::new();
    let corrupted_body = b"corrupted envelope bytes".to_vec();
    let api = FakeBrokr::new().holding("ee03", NOW, corrupted_body);
    let (trust, _) = trust(true);

    let report = fixture.collect(&api, &trust).await.expect("pass");
    assert_eq!(report.delivered, 0);
    assert_eq!(report.refused.len(), 1);
    assert_eq!(report.refused[0].0, "ee03");
    assert!(!fixture.placed.contains("ee03").expect("contains"));
    assert_eq!(api.acknowledged(), vec!["ee03".to_string()]);
}

#[test]
fn placed_deliveries_storage_and_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let placed1 = PlacedDeliveries::new(dir.path());
    let placed2 = PlacedDeliveries::new(dir.path());

    assert!(!placed1.contains("item-1").expect("missing reads as empty"));

    placed1.remember("item-1").expect("remember once");
    placed1.remember("item-1").expect("remember twice");
    assert!(placed1.contains("item-1").expect("contains"));
    let contents = std::fs::read_to_string(dir.path().join("collected.json")).expect("read file");
    let ids: Vec<String> = serde_json::from_str(&contents).expect("parse json");
    assert_eq!(ids, vec!["item-1"]);

    assert!(placed2.contains("item-1").expect("second instance sees it"));

    placed1.forget("item-1").expect("forget");
    assert!(!placed1.contains("item-1").expect("forgotten"));
    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["collected.json"]);

    std::fs::write(dir.path().join("collected.json"), br#"{"not":"an array"}"#)
        .expect("write bad json");
    let err = placed1.contains("item-1").expect_err("malformed");
    assert!(matches!(err, PlacedError::Malformed(_)));
}

//! Tests for the Brokr collector loop and session maintenance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;

use common::{
    AUD, CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, clock_at, device_store, document,
    identity, profile, published_key, token,
};
use futures_util::stream;
use tradr_app::brokr::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, CollectContext, Collector,
    CollectorParts, CollectorStatus, DeliveryId, InboxEntry, JoinToken, LinkView, OutboxEntry,
    PlacedDeliveries, RegisterRequest, Session, ensure_session, load_session, run_pass,
    save_join_token, save_session,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_core::{
    ContentHash, DeviceId, DomainTag, KeyBinding, KeyStore, LinkSecret, PublicIdentity, RelPath,
    RootId, SecretStore, SecretStoreError, StorageLevel, TransferId, UnixTime,
};
use tradr_identity::envelope::{EnvelopeItem, EnvelopeSender, EnvelopeWriter};
use tradr_identity::{AccountId, OsRng};
use tradr_vfs::NativeVfs;

const SALT_HEX: &str = "00112233445566778899aabbccddeeff";
const NONCE_HEX: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const DAY: i64 = 24 * 3600;

#[derive(Default)]
struct MemorySecrets {
    slots: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for MemorySecrets {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(slot.to_string(), secret.to_vec());
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self
            .slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(slot)
            .cloned())
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

struct FakeBrokr {
    registrations: Mutex<Vec<RegisterRequest>>,
    inbox: Mutex<Vec<InboxEntry>>,
    bodies: Mutex<HashMap<String, Vec<u8>>>,
    acknowledged: Mutex<Vec<String>>,
    rejected_sessions: Mutex<Vec<String>>,
    reject_all_sessions: Mutex<bool>,
    fail_inbox_network: Mutex<bool>,
    session_counter: Mutex<usize>,
}

impl FakeBrokr {
    fn new() -> Self {
        Self {
            registrations: Mutex::new(Vec::new()),
            inbox: Mutex::new(Vec::new()),
            bodies: Mutex::new(HashMap::new()),
            acknowledged: Mutex::new(Vec::new()),
            rejected_sessions: Mutex::new(Vec::new()),
            reject_all_sessions: Mutex::new(false),
            fail_inbox_network: Mutex::new(false),
            session_counter: Mutex::new(0),
        }
    }

    fn holding(&self, id: &str, uploaded_at: i64, body: Vec<u8>) {
        self.inbox
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(InboxEntry {
                id: id.to_string(),
                sender_device_id: String::new(),
                size: body.len() as u64,
                uploaded_at,
            });
        self.bodies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.to_string(), body);
    }

    fn reject_session(&self, session: &str) {
        self.rejected_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(session.to_string());
    }

    fn reject_all(&self) {
        *self
            .reject_all_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = true;
    }

    fn fail_network(&self, fail: bool) {
        *self
            .fail_inbox_network
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = fail;
    }

    fn registrations_count(&self) -> usize {
        self.registrations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
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
            let mut count = self
                .session_counter
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *count += 1;
            Ok(Session::new(format!("session-token-{}", *count)))
        })
    }

    fn inbox<'a>(&'a self, session: &'a Session) -> BrokrFuture<'a, Vec<InboxEntry>> {
        Box::pin(async move {
            if *self
                .fail_inbox_network
                .lock()
                .unwrap_or_else(|p| p.into_inner())
            {
                return Err(BrokrError::Network("network down".to_string()));
            }
            if *self
                .reject_all_sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
            {
                return Err(BrokrError::Unauthorized);
            }
            let rejected = self
                .rejected_sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if rejected.contains(&session.as_str().to_string()) {
                return Err(BrokrError::Unauthorized);
            }
            Ok(self.inbox.lock().unwrap_or_else(|p| p.into_inner()).clone())
        })
    }

    fn download<'a>(
        &'a self,
        _session: &'a Session,
        id: &'a str,
    ) -> BrokrFuture<'a, ByteStream<'a>> {
        Box::pin(async move {
            let bodies = self.bodies.lock().unwrap_or_else(|p| p.into_inner());
            let body = bodies
                .get(id)
                .ok_or_else(|| BrokrError::Rejected("no such delivery".to_string()))?
                .clone();
            let items: Vec<Result<Vec<u8>, BrokrError>> =
                body.chunks(4096).map(|chunk| Ok(chunk.to_vec())).collect();
            let stream: ByteStream<'a> = Box::pin(stream::iter(items));
            Ok(stream)
        })
    }

    fn acknowledge<'a>(&'a self, _session: &'a Session, id: &'a str) -> BrokrFuture<'a, ()> {
        Box::pin(async move {
            self.acknowledged
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(id.to_string());
            self.inbox
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|entry| entry.id != id);
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

fn test_trust() -> PeerTrust {
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = PeerTrust::new(profile(), fetch);
    trust
        .install(JWKS_URI, &document(&[published_key(KID)]))
        .expect("install jwks");
    trust
}

fn sealed(sender_seed: u8, recipient: &PublicIdentity, files: &[(&str, &[u8])]) -> Vec<u8> {
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
        token(KID, OWN_SUB, AUD, &sender_identity, NOW),
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
    let transfer_id: TransferId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("transfer id");
    let (mut writer, mut out) = EnvelopeWriter::new(
        recipient,
        &sender,
        &store,
        &OsRng,
        transfer_id,
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

#[tokio::test]
async fn ensure_session_registers_when_no_session_stored_and_reuses_stored() {
    let secrets = MemorySecrets::default();
    save_join_token(&secrets, &JoinToken::new("join-secret".to_string())).expect("save join token");

    let api = FakeBrokr::new();
    let key_store = device_store(2);
    let identity = identity(2);
    let account = own_account();
    let links: Vec<LinkSecret> = Vec::new();

    let session1 = ensure_session(&api, &secrets, &key_store, &identity, &account, &links)
        .await
        .expect("first ensure_session");
    assert_eq!(api.registrations_count(), 1);
    assert_eq!(session1.as_str(), "session-token-1");

    let stored = load_session(&secrets)
        .expect("load session")
        .expect("session present");
    assert_eq!(stored.as_str(), "session-token-1");

    let session2 = ensure_session(&api, &secrets, &key_store, &identity, &account, &links)
        .await
        .expect("second ensure_session");
    assert_eq!(api.registrations_count(), 1);
    assert_eq!(session2.as_str(), "session-token-1");
}

#[tokio::test]
async fn run_pass_reregisters_once_after_unauthorized_and_succeeds() {
    let secrets = MemorySecrets::default();
    save_join_token(&secrets, &JoinToken::new("join-secret".to_string())).expect("save join token");
    save_session(&secrets, &Session::new("stale-session".to_string())).expect("save stale session");

    let api = FakeBrokr::new();
    api.reject_session("stale-session");

    let recipient_store = device_store(2);
    let recipient_id = identity(2);
    let payload = sealed(1, &recipient_id, &[("note.txt", b"delivery data")]);
    api.holding("aa01", NOW, payload);

    let dir = tempfile::tempdir().expect("tempdir");
    let placed_dir = tempfile::tempdir().expect("tempdir");
    let placed = PlacedDeliveries::new(placed_dir.path());
    let vfs = NativeVfs::new();
    vfs.register_root(RootId::new(1), dir.path().to_path_buf(), false)
        .expect("register root");

    let trust = test_trust();
    let clock = clock_at(NOW);
    let own = own_account();
    let agree = |peer: &_| recipient_store.agree(peer);
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    let arrivals_cb = arrivals.clone();
    let on_arrival = move |from: DeviceId, paths: &[RelPath]| {
        arrivals_cb
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((from, paths.to_vec()));
    };

    let ctx = CollectContext {
        vfs: &vfs,
        root: RootId::new(1),
        recipient: &recipient_id,
        agree: &agree,
        clock: &clock,
        trust: &trust,
        own_account: &own,
        linked_accounts: &[],
        on_arrival: &on_arrival,
        placed: &placed,
    };

    let report = run_pass(&api, &secrets, &recipient_store, &[], &ctx)
        .await
        .expect("run_pass");
    assert_eq!(report.delivered, 1);
    assert_eq!(api.registrations_count(), 1);
    let current_session = load_session(&secrets)
        .expect("load session")
        .expect("session stored");
    assert_eq!(current_session.as_str(), "session-token-1");
    assert_eq!(arrivals.lock().unwrap_or_else(|p| p.into_inner()).len(), 1);
}

#[tokio::test]
async fn second_unauthorized_after_reregistering_is_error_not_loop() {
    let secrets = MemorySecrets::default();
    save_join_token(&secrets, &JoinToken::new("join-secret".to_string())).expect("save join token");
    save_session(&secrets, &Session::new("stale-session".to_string())).expect("save stale session");

    let api = FakeBrokr::new();
    api.reject_all();

    let recipient_store = device_store(2);
    let recipient_id = identity(2);

    let dir = tempfile::tempdir().expect("tempdir");
    let placed_dir = tempfile::tempdir().expect("tempdir");
    let placed = PlacedDeliveries::new(placed_dir.path());
    let vfs = NativeVfs::new();
    vfs.register_root(RootId::new(1), dir.path().to_path_buf(), false)
        .expect("register root");

    let trust = test_trust();
    let clock = clock_at(NOW);
    let own = own_account();
    let agree = |peer: &_| recipient_store.agree(peer);
    let on_arrival = |_: DeviceId, _: &[RelPath]| {};

    let ctx = CollectContext {
        vfs: &vfs,
        root: RootId::new(1),
        recipient: &recipient_id,
        agree: &agree,
        clock: &clock,
        trust: &trust,
        own_account: &own,
        linked_accounts: &[],
        on_arrival: &on_arrival,
        placed: &placed,
    };

    let result = run_pass(&api, &secrets, &recipient_store, &[], &ctx).await;
    assert!(matches!(result, Err(BrokrError::Unauthorized)));
    assert_eq!(api.registrations_count(), 1);
}

#[tokio::test]
async fn collector_runs_at_start_and_after_wake_with_paused_time() {
    tokio::time::pause();

    let secrets = Arc::new(MemorySecrets::default());
    save_join_token(secrets.as_ref(), &JoinToken::new("join-secret".to_string()))
        .expect("save join token");

    let api = Arc::new(FakeBrokr::new());
    let recipient_store = Arc::new(device_store(2));
    let recipient_id = identity(2);

    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = Arc::new(NativeVfs::new());
    vfs.register_root(RootId::new(1), dir.path().to_path_buf(), false)
        .expect("register root");

    let payload1 = sealed(1, &recipient_id, &[("file1.txt", b"first payload")]);
    api.holding("aa01", NOW, payload1);

    let trust = Arc::new(test_trust());
    let clock = Arc::new(clock_at(NOW));
    let own = own_account();
    let own_account_fn = Arc::new(move || Some(own.clone()));
    let links_fn = Arc::new(|| Ok(LinkView::default()));
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    let arrivals_cb = arrivals.clone();
    let on_arrival = Arc::new(move |from: DeviceId, paths: &[RelPath]| {
        arrivals_cb
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((from, paths.to_vec()));
    });

    let placed_dir = tempfile::tempdir().expect("tempdir");
    let placed = Arc::new(PlacedDeliveries::new(placed_dir.path()));

    let parts = CollectorParts {
        api: api.clone(),
        secrets: secrets.clone(),
        key_store: recipient_store.clone(),
        identity: recipient_id.clone(),
        vfs: vfs.clone(),
        root: RootId::new(1),
        clock: clock.clone(),
        trust: trust.clone(),
        own_account: own_account_fn,
        links: links_fn,
        on_arrival,
        placed,
    };

    let collector = Collector::new(parts);
    let mut rx = collector.subscribe();
    let run_handle = tokio::spawn(collector.clone().run());

    async fn wait_for<F>(
        rx: &mut tokio::sync::watch::Receiver<CollectorStatus>,
        description: &str,
        condition: F,
    ) -> CollectorStatus
    where
        F: Fn(&CollectorStatus) -> bool,
    {
        let wait = async {
            loop {
                if condition(&rx.borrow_and_update()) {
                    return rx.borrow().clone();
                }
                rx.changed().await.expect("collector status channel closed");
            }
        };
        tokio::time::timeout(Duration::from_secs(60), wait)
            .await
            .unwrap_or_else(|_| panic!("timed out after 60s waiting for: {description}"))
    }

    let status = wait_for(&mut rx, "initial pass", |s| {
        s.pass_count >= 1 && s.last_pass.is_some()
    })
    .await;
    assert_eq!(status.delivered, 1);
    assert_eq!(status.last_error, None);

    let payload2 = sealed(1, &recipient_id, &[("file2.txt", b"second payload")]);
    api.holding("aa02", NOW, payload2);
    let prev_count = status.pass_count;
    collector.wake();

    let status = wait_for(&mut rx, "second pass after wake", |s| {
        s.pass_count > prev_count
    })
    .await;
    assert_eq!(status.delivered, 1);
    assert_eq!(status.last_error, None);

    api.fail_network(true);
    let prev_count = status.pass_count;
    collector.wake();

    let status = wait_for(&mut rx, "third pass after network fail", |s| {
        s.pass_count > prev_count
    })
    .await;
    assert_eq!(status.delivered, 0);
    assert!(status.last_error.is_some());
    assert!(status.last_error.unwrap().contains("brokr unreachable"));

    collector.stop();
    tokio::time::advance(Duration::from_secs(300)).await;
    run_handle.await.expect("collector task cleanly finished");
}

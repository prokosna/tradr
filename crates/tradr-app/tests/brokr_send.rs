//! Integration tests for deferred sending and local outbox tracking (docs/13).

use std::sync::{Arc, Mutex};

mod common;

use common::{AUD, KID, NOW, OWN_SUB, clock_at, device_store, identity, token};
use futures_util::StreamExt;
use tradr_app::brokr::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, DeliveryId, InboxEntry,
    OutboxEntry, OutboxState, RegisterRequest, SendDeferredContext, SentDeliveries, Session,
    send_deferred,
};
use tradr_app::send::SendItem;
use tradr_core::{DeviceId, KeyStore, PublicIdentity, RelPath, RootId, TrustTier, UnixTime};
use tradr_identity::KnownDevice;
use tradr_identity::OsRng;
use tradr_identity::envelope::open_envelope;
use tradr_vfs::NativeVfs;

#[derive(Clone)]
struct UploadedPayload {
    id: String,
    total_len: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct FakeBrokr {
    uploaded: Arc<Mutex<Option<UploadedPayload>>>,
    upload_chunks: Arc<Mutex<Vec<usize>>>,
    outbox: Arc<Mutex<Vec<OutboxEntry>>>,
}

impl BrokrApi for FakeBrokr {
    fn info(&self) -> BrokrFuture<'_, BrokrInfo> {
        Box::pin(async {
            Ok(BrokrInfo {
                version: 1,
                account_salt: "0011".to_string(),
                delivery_ttl_days: 30,
                delivery_max_bytes: 100 * 1024 * 1024,
                storage_max_bytes: 1024 * 1024 * 1024,
            })
        })
    }

    fn challenge(&self) -> BrokrFuture<'_, Challenge> {
        Box::pin(async {
            Ok(Challenge {
                nonce: "nonce".to_string(),
            })
        })
    }

    fn register(&self, _request: RegisterRequest) -> BrokrFuture<'_, Session> {
        Box::pin(async { Ok(Session::new("test-session".to_string())) })
    }

    fn upload<'a>(
        &'a self,
        _session: &'a Session,
        total_len: u64,
        mut body: ByteStream<'static>,
    ) -> BrokrFuture<'a, DeliveryId> {
        let uploaded = self.uploaded.clone();
        let upload_chunks = self.upload_chunks.clone();
        Box::pin(async move {
            let mut streamed = Vec::new();
            while let Some(chunk_res) = body.next().await {
                let chunk = chunk_res?;
                upload_chunks.lock().unwrap().push(chunk.len());
                streamed.extend(chunk);
            }
            let id = "test-delivery-id".to_string();
            *uploaded.lock().unwrap() = Some(UploadedPayload {
                id: id.clone(),
                total_len,
                bytes: streamed,
            });
            Ok(id)
        })
    }

    fn inbox<'a>(&'a self, _session: &'a Session) -> BrokrFuture<'a, Vec<InboxEntry>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn download<'a>(
        &'a self,
        _session: &'a Session,
        _id: &'a str,
    ) -> BrokrFuture<'a, ByteStream<'a>> {
        Box::pin(async {
            let stream: ByteStream<'a> = Box::pin(futures_util::stream::empty());
            Ok(stream)
        })
    }

    fn acknowledge<'a>(&'a self, _session: &'a Session, _id: &'a str) -> BrokrFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn outbox<'a>(&'a self, _session: &'a Session) -> BrokrFuture<'a, Vec<OutboxEntry>> {
        let outbox = self.outbox.clone();
        Box::pin(async move { Ok(outbox.lock().unwrap().clone()) })
    }
}

#[tokio::test]
async fn deferred_send_uploads_verifiable_envelope_with_bounded_chunks() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let file1_len = 2 * 1024 * 1024 + 12_345;
    let file1_bytes: Vec<u8> = (0..file1_len).map(|i| (i % 251) as u8).collect();
    let file2_bytes: Vec<u8> = Vec::new();

    std::fs::write(temp_dir.path().join("large.bin"), &file1_bytes).expect("write large");
    std::fs::write(temp_dir.path().join("empty.txt"), &file2_bytes).expect("write empty");

    let vfs = NativeVfs::new();
    let root = RootId::new(42);
    vfs.register_root(root, temp_dir.path().to_path_buf(), false)
        .expect("register root");

    let items = vec![
        SendItem {
            root,
            rel_path: RelPath::new("large.bin").expect("rel path"),
            size_bytes: file1_bytes.len() as u64,
        },
        SendItem {
            root,
            rel_path: RelPath::new("empty.txt").expect("rel path"),
            size_bytes: 0,
        },
    ];

    let sender_store = device_store(1);
    let sender_identity = identity(1);
    let attestation_token = token(KID, OWN_SUB, AUD, &sender_identity, NOW);

    let recipient_store = device_store(2);
    let recipient_identity = identity(2);
    let recipient_device = KnownDevice::new(
        recipient_identity.device_id(),
        recipient_identity.clone(),
        None,
        TrustTier::SameAccount,
        UnixTime::from_secs(NOW),
    );

    let clock = clock_at(NOW);
    let rng = OsRng;
    let ctx = SendDeferredContext {
        vfs: &vfs,
        identity: &sender_identity,
        key_store: &sender_store,
        attestation_token,
        rng: &rng,
        clock: &clock,
    };

    let fake = FakeBrokr::default();
    let session = Session::new("dummy-session".to_string());

    let sent = send_deferred(&fake, &session, &ctx, &recipient_device, &items)
        .await
        .expect("send_deferred");

    assert_eq!(sent.id, "test-delivery-id");
    assert_eq!(sent.recipient, recipient_identity.device_id());
    assert_eq!(sent.names, vec!["large.bin", "empty.txt"]);

    let uploaded = fake.uploaded.lock().unwrap().clone().expect("uploaded");
    assert_eq!(uploaded.id, sent.id);
    assert_eq!(sent.total_len, uploaded.total_len);
    assert_eq!(uploaded.total_len, uploaded.bytes.len() as u64);

    let chunks = fake.upload_chunks.lock().unwrap().clone();
    assert!(
        chunks.len() >= 3,
        "expected at least 3 chunks, got {}",
        chunks.len()
    );
    const MAX_CHUNK_LIMIT: usize = 1024 * 1024 + 1024;
    for &chunk_len in &chunks {
        assert!(
            chunk_len <= MAX_CHUNK_LIMIT,
            "chunk size {chunk_len} exceeds limit {MAX_CHUNK_LIMIT}"
        );
    }

    let agree = |peer: &_| recipient_store.agree(peer);
    let verify_attestation =
        |_token: &str, _id: &PublicIdentity, _now: UnixTime| Ok(TrustTier::SameAccount);

    let opened = open_envelope(
        &uploaded.bytes,
        &recipient_identity,
        &agree,
        UnixTime::from_secs(NOW),
        &verify_attestation,
    )
    .expect("open_envelope");

    assert_eq!(opened.sender(), &sender_identity);
    assert_eq!(opened.items().len(), 2);
    assert_eq!(opened.items()[0].rel_path().as_str(), "large.bin");
    assert_eq!(opened.items()[0].size(), file1_bytes.len() as u64);
    assert_eq!(opened.contents()[0], file1_bytes);
    assert_eq!(opened.items()[1].rel_path().as_str(), "empty.txt");
    assert_eq!(opened.items()[1].size(), 0);
    assert!(opened.contents()[1].is_empty());
}

#[tokio::test]
async fn nearby_ephemeral_recipient_is_refused_before_upload() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(43);
    vfs.register_root(root, temp_dir.path().to_path_buf(), false)
        .expect("register root");

    std::fs::write(temp_dir.path().join("test.txt"), b"data").expect("write");
    let items = vec![SendItem {
        root,
        rel_path: RelPath::new("test.txt").expect("rel path"),
        size_bytes: 4,
    }];

    let sender_store = device_store(3);
    let sender_identity = identity(3);
    let attestation_token = token(KID, OWN_SUB, AUD, &sender_identity, NOW);

    let recipient_identity = identity(4);
    let nearby_device = KnownDevice::new(
        recipient_identity.device_id(),
        recipient_identity,
        None,
        TrustTier::NearbyEphemeral,
        UnixTime::from_secs(NOW),
    );

    let clock = clock_at(NOW);
    let rng = OsRng;
    let ctx = SendDeferredContext {
        vfs: &vfs,
        identity: &sender_identity,
        key_store: &sender_store,
        attestation_token,
        rng: &rng,
        clock: &clock,
    };

    let fake = FakeBrokr::default();
    let session = Session::new("session".to_string());

    let err = send_deferred(&fake, &session, &ctx, &nearby_device, &items)
        .await
        .expect_err("should refuse nearby recipient");

    assert!(matches!(err, BrokrError::Rejected(_)));
    assert!(fake.uploaded.lock().unwrap().is_none());
}

#[tokio::test]
async fn file_with_mismatched_disk_size_is_refused() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(44);
    vfs.register_root(root, temp_dir.path().to_path_buf(), false)
        .expect("register root");

    std::fs::write(temp_dir.path().join("test.txt"), b"real-content").expect("write");
    let items = vec![SendItem {
        root,
        rel_path: RelPath::new("test.txt").expect("rel path"),
        size_bytes: 100,
    }];

    let sender_store = device_store(5);
    let sender_identity = identity(5);
    let attestation_token = token(KID, OWN_SUB, AUD, &sender_identity, NOW);

    let recipient_identity = identity(6);
    let recipient_device = KnownDevice::new(
        recipient_identity.device_id(),
        recipient_identity,
        None,
        TrustTier::SameAccount,
        UnixTime::from_secs(NOW),
    );

    let clock = clock_at(NOW);
    let rng = OsRng;
    let ctx = SendDeferredContext {
        vfs: &vfs,
        identity: &sender_identity,
        key_store: &sender_store,
        attestation_token,
        rng: &rng,
        clock: &clock,
    };

    let fake = FakeBrokr::default();
    let session = Session::new("session".to_string());

    let err = send_deferred(&fake, &session, &ctx, &recipient_device, &items)
        .await
        .expect_err("should refuse size mismatch");

    assert!(matches!(err, BrokrError::Rejected(_)));
    assert!(fake.uploaded.lock().unwrap().is_none());
}

#[test]
fn sent_deliveries_round_trips_and_prunes_stale_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut journal = SentDeliveries::load(dir.path()).expect("initial load");
    assert!(journal.all().is_empty());

    let recipient = DeviceId::from_bytes(&[1u8; 16]).expect("device id");
    let sent_at = UnixTime::from_secs(NOW);

    journal
        .record(
            "deliv-01",
            recipient,
            vec!["file1.png".to_string(), "file2.jpg".to_string()],
            sent_at,
        )
        .expect("record deliv-01");

    let loaded = SentDeliveries::load(dir.path()).expect("reload");
    assert_eq!(loaded.all().len(), 1);
    assert_eq!(loaded.all()[0].id(), "deliv-01");
    assert_eq!(loaded.all()[0].recipient(), recipient);
    assert_eq!(
        loaded.all()[0].names(),
        &["file1.png".to_string(), "file2.jpg".to_string()]
    );
    assert_eq!(loaded.all()[0].sent_at(), sent_at);

    let day = 24 * 3600;
    let sixty_five_days_ago = UnixTime::from_secs(NOW - 65 * day);
    journal
        .record(
            "deliv-old",
            recipient,
            vec!["ancient.txt".to_string()],
            sixty_five_days_ago,
        )
        .expect("record old");
    assert_eq!(journal.all().len(), 2);

    journal
        .record(
            "deliv-02",
            recipient,
            vec!["new.txt".to_string()],
            UnixTime::from_secs(NOW),
        )
        .expect("record new");

    let all_after_prune = journal.all();
    assert_eq!(all_after_prune.len(), 2);
    assert!(all_after_prune.iter().any(|r| r.id() == "deliv-01"));
    assert!(all_after_prune.iter().any(|r| r.id() == "deliv-02"));
    assert!(!all_after_prune.iter().any(|r| r.id() == "deliv-old"));
}

#[test]
fn merge_with_evaluates_waiting_delivered_and_expired_states() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut journal = SentDeliveries::load(dir.path()).expect("load");
    let recipient = DeviceId::from_bytes(&[2u8; 16]).expect("device id");
    let day = 24 * 3600;

    journal
        .record(
            "deliv-wait",
            recipient,
            vec!["w.txt".to_string()],
            UnixTime::from_secs(NOW - day),
        )
        .expect("record");
    journal
        .record(
            "deliv-done",
            recipient,
            vec!["d.txt".to_string()],
            UnixTime::from_secs(NOW - 2 * day),
        )
        .expect("record");
    journal
        .record(
            "deliv-exp-listed",
            recipient,
            vec!["el.txt".to_string()],
            UnixTime::from_secs(NOW - 3 * day),
        )
        .expect("record");
    journal
        .record(
            "deliv-unlisted-fresh",
            recipient,
            vec!["uf.txt".to_string()],
            UnixTime::from_secs(NOW - 5 * day),
        )
        .expect("record");
    journal
        .record(
            "deliv-unlisted-stale",
            recipient,
            vec!["us.txt".to_string()],
            UnixTime::from_secs(NOW - 35 * day),
        )
        .expect("record");

    let outbox = vec![
        OutboxEntry {
            id: "deliv-wait".to_string(),
            recipient_device_id: recipient.to_string(),
            size: 10,
            uploaded_at: (NOW - day) * 1000,
            state: OutboxState::Waiting,
            collected_at: None,
        },
        OutboxEntry {
            id: "deliv-done".to_string(),
            recipient_device_id: recipient.to_string(),
            size: 20,
            uploaded_at: (NOW - 2 * day) * 1000,
            state: OutboxState::Delivered,
            collected_at: Some(NOW * 1000),
        },
        OutboxEntry {
            id: "deliv-exp-listed".to_string(),
            recipient_device_id: recipient.to_string(),
            size: 30,
            uploaded_at: (NOW - 3 * day) * 1000,
            state: OutboxState::Expired,
            collected_at: None,
        },
    ];

    let statuses = journal.merge_with_at(&outbox, UnixTime::from_secs(NOW));
    assert_eq!(statuses.len(), 5);

    let find = |id: &str| statuses.iter().find(|s| s.id() == id).expect("status");

    let s_wait = find("deliv-wait");
    assert_eq!(s_wait.state(), OutboxState::Waiting);
    assert_eq!(s_wait.collected_at(), None);

    let s_done = find("deliv-done");
    assert_eq!(s_done.state(), OutboxState::Delivered);
    assert_eq!(s_done.collected_at(), Some(NOW * 1000));

    let s_exp_listed = find("deliv-exp-listed");
    assert_eq!(s_exp_listed.state(), OutboxState::Expired);
    assert_eq!(s_exp_listed.collected_at(), None);

    let s_unlisted_fresh = find("deliv-unlisted-fresh");
    assert_eq!(s_unlisted_fresh.state(), OutboxState::Waiting);
    assert_eq!(s_unlisted_fresh.collected_at(), None);

    let s_unlisted_stale = find("deliv-unlisted-stale");
    assert_eq!(s_unlisted_stale.state(), OutboxState::Expired);
    assert_eq!(s_unlisted_stale.collected_at(), None);
}

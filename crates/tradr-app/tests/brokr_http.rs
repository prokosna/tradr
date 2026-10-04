//! The Brokr HTTP adapter against a minimal HTTP/1.1 responder on loopback:
//! no node, no external server.

use std::sync::{Arc, Mutex};

mod common;

use common::{
    CountingFetch, ISS, JWKS_URI, KID, NOW, OWN_SUB, clock_at, device_store, document, identity,
    profile, published_key,
};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tradr_app::brokr::{
    BrokrApi, BrokrError, BrokrSettings, CollectContext, HttpBrokrApi, JoinToken, RegisterRequest,
    Session, clear_join_token, clear_session, clear_settings, collect_once, load_join_token,
    load_session, load_settings, save_join_token, save_session, save_settings,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_core::{DeviceId, KeyStore, RelPath, RootId};
use tradr_identity::AccountId;
use tradr_secrets::FileStore;
use tradr_vfs::NativeVfs;

#[derive(Clone, Debug)]
struct Seen {
    request_line: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn ok(body: &[u8]) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

struct Responder {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Responder {
    async fn start(handler: impl Fn(&Seen, u16) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let recorded = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = handler.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    serve(stream, port, handler, recorded).await;
                });
            }
        });
        Self { port, seen }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_string();
    let mut authorization = None;
    let mut length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value.trim().to_string()),
            "content-length" => length = value.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    while buf.len() < head_end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(Seen {
        request_line,
        authorization,
        body: buf[head_end..head_end + length].to_vec(),
    })
}

async fn serve(
    mut stream: TcpStream,
    port: u16,
    handler: Arc<impl Fn(&Seen, u16) -> Reply + Send + Sync + 'static>,
    recorded: Arc<Mutex<Vec<Seen>>>,
) -> Option<()> {
    let seen = read_request(&mut stream).await?;
    let reply = handler(&seen, port);
    recorded
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(seen);
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.ok()?;
    for piece in reply.body.chunks(16 * 1024) {
        stream.write_all(piece).await.ok()?;
    }
    stream.shutdown().await.ok()
}

fn session() -> Session {
    Session::new("session-secret".to_string())
}

#[tokio::test]
async fn info_and_challenge_are_parsed() {
    let responder = Responder::start(|seen, _| {
        if seen.request_line.starts_with("GET /v1/info ") {
            Reply::ok(
                br#"{"version":1,"account_salt":"00ff","delivery_ttl_days":30,"delivery_max_bytes":100,"storage_max_bytes":1000}"#,
            )
        } else if seen.request_line.starts_with("POST /v1/challenge ") {
            Reply::ok(br#"{"nonce":"abcd"}"#)
        } else {
            Reply::status(404)
        }
    })
    .await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    let info = api.info().await.expect("info");
    assert_eq!(info.version, 1);
    assert_eq!(info.account_salt, "00ff");
    assert_eq!(info.delivery_ttl_days, 30);
    assert_eq!(info.delivery_max_bytes, 100);
    assert_eq!(info.storage_max_bytes, 1000);
    assert_eq!(api.challenge().await.expect("challenge").nonce, "abcd");
}

#[tokio::test]
async fn an_answer_of_the_wrong_shape_is_malformed() {
    let responder = Responder::start(|_, _| Reply::ok(br#"{"unexpected":true}"#)).await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    assert!(matches!(api.info().await, Err(BrokrError::Malformed(_))));
}

#[tokio::test]
async fn register_posts_the_expected_json() {
    let responder = Responder::start(|seen, _| {
        if seen.request_line.starts_with("POST /v1/register ") {
            Reply::ok(br#"{"session":"issued-session"}"#)
        } else {
            Reply::status(404)
        }
    })
    .await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    let session = api
        .register(RegisterRequest {
            device_id: "d1".to_string(),
            identity_pub: "04aa".to_string(),
            join_token: "joining".to_string(),
            account_tag: "ac".to_string(),
            link_tags: vec!["l1".to_string(), "l2".to_string()],
            nonce: "n0".to_string(),
            signature: "5151".to_string(),
        })
        .await
        .expect("registered");

    assert_eq!(session.as_str(), "issued-session");
    let requests = responder.requests();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).expect("json");
    assert_eq!(
        body,
        serde_json::json!({
            "device_id": "d1",
            "identity_pub": "04aa",
            "join_token": "joining",
            "account_tag": "ac",
            "link_tags": ["l1", "l2"],
            "nonce": "n0",
            "signature": "5151",
        })
    );
}

#[tokio::test]
async fn inbox_sends_the_bearer_token_and_parses_the_entries() {
    let responder = Responder::start(|seen, _| {
        if seen.request_line.starts_with("GET /v1/deliveries/inbox ") {
            Reply::ok(br#"[{"id":"aa01","sender_device_id":"bb","size":7,"uploaded_at":1234}]"#)
        } else {
            Reply::status(404)
        }
    })
    .await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    let entries = api.inbox(&session()).await.expect("inbox");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "aa01");
    assert_eq!(entries[0].sender_device_id, "bb");
    assert_eq!(entries[0].size, 7);
    assert_eq!(entries[0].uploaded_at, 1234);
    assert_eq!(
        responder.requests()[0].authorization.as_deref(),
        Some("Bearer session-secret")
    );
}

#[tokio::test]
async fn a_401_is_unauthorized_and_other_refusals_name_the_status_only() {
    let responder = Responder::start(|seen, _| {
        if seen.request_line.starts_with("GET /v1/deliveries/inbox ") {
            Reply::status(401)
        } else {
            Reply::status(503)
        }
    })
    .await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    assert!(matches!(
        api.inbox(&session()).await,
        Err(BrokrError::Unauthorized)
    ));
    let refused = api.acknowledge(&session(), "aa01").await.expect_err("503");
    assert!(matches!(&refused, BrokrError::Rejected(m) if m.contains("503")));
    assert!(!format!("{refused} {refused:?}").contains("session-secret"));
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let responder = Responder::start(|seen, port| {
        if seen.request_line.starts_with("GET /v1/info ") {
            Reply {
                status: 302,
                headers: vec![(
                    "Location".to_string(),
                    format!("http://127.0.0.1:{port}/target"),
                )],
                body: Vec::new(),
            }
        } else {
            Reply::ok(b"{}")
        }
    })
    .await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    let refused = api.info().await.expect_err("a redirect is a refusal");

    assert!(matches!(&refused, BrokrError::Rejected(m) if m.contains("302")));
    let requests = responder.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests.iter().all(|r| !r.request_line.contains("/target")));
}

#[tokio::test]
async fn download_streams_a_large_body_in_several_chunks_and_acknowledge_deletes() {
    let body: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let served = body.clone();
    let responder = Responder::start(move |seen, _| {
        if seen.request_line.starts_with("GET /v1/deliveries/aa01 ") {
            Reply::ok(&served)
        } else if seen.request_line.starts_with("DELETE /v1/deliveries/aa01 ") {
            Reply::ok(b"{}")
        } else {
            Reply::status(404)
        }
    })
    .await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");
    let session = session();

    let mut stream = api.download(&session, "aa01").await.expect("download");
    let mut chunks = 0;
    let mut got = Vec::new();
    while let Some(chunk) = stream.next().await {
        got.extend(chunk.expect("chunk"));
        chunks += 1;
    }
    drop(stream);
    api.acknowledge(&session, "aa01")
        .await
        .expect("acknowledged");

    assert!(chunks > 1, "the body arrived as {chunks} chunk");
    assert_eq!(got, body);
    let requests = responder.requests();
    assert!(
        requests
            .iter()
            .all(|r| r.authorization.as_deref() == Some("Bearer session-secret"))
    );
    assert!(
        requests[1]
            .request_line
            .starts_with("DELETE /v1/deliveries/aa01 ")
    );
}

#[tokio::test]
async fn a_delivery_id_cannot_escape_its_path_segment() {
    let responder = Responder::start(|_, _| Reply::ok(b"")).await;
    let api = HttpBrokrApi::new(&responder.url()).expect("adapter");

    api.acknowledge(&session(), "../info").await.expect("sent");

    let line = &responder.requests()[0].request_line;
    assert!(
        line.starts_with("DELETE /v1/deliveries/..%2Finfo "),
        "{line}"
    );
}

#[test]
fn only_http_and_https_addresses_without_a_path_are_accepted() {
    for refused in [
        "ftp://host",
        "file:///etc/passwd",
        "host",
        "http://host/sub",
        "data:text/plain,x",
    ] {
        assert!(
            HttpBrokrApi::new(refused).is_err(),
            "{refused} was accepted"
        );
    }
    assert!(HttpBrokrApi::new("http://127.0.0.1:8080").is_ok());
    assert!(HttpBrokrApi::new("https://brokr.example/").is_ok());
}

fn assert_send<T: Send>(_: T) {}

#[test]
fn collecting_is_a_send_future() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    vfs.register_root(RootId::new(1), dir.path().to_path_buf(), false)
        .expect("register root");
    let store = device_store(2);
    let recipient = identity(2);
    let fetch = CountingFetch::serving(&[published_key(KID)]);
    let trust = PeerTrust::new(profile(), fetch);
    trust
        .install(JWKS_URI, &document(&[published_key(KID)]))
        .expect("installed");
    let clock = clock_at(NOW);
    let agree = |peer: &_| store.agree(peer);
    let own = AccountId::new(ISS, OWN_SUB);
    let on_arrival = |_: DeviceId, _: &[RelPath]| {};
    let ctx = CollectContext {
        vfs: &vfs,
        root: RootId::new(1),
        recipient: &recipient,
        agree: &agree,
        clock: &clock,
        trust: &trust,
        own_account: &own,
        linked_accounts: &[],
        on_arrival: &on_arrival,
    };
    let api = HttpBrokrApi::new("http://127.0.0.1:1").expect("adapter");
    let session = session();

    assert_send(collect_once(&api, &session, &ctx));
}

#[test]
fn settings_round_trip_and_clear() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = tempfile::tempdir().expect("tempdir");
    let store = FileStore::new(secrets.path().to_path_buf());

    assert_eq!(load_settings(dir.path()).expect("load"), None);
    assert!(load_join_token(&store).expect("load").is_none());
    assert!(load_session(&store).expect("load").is_none());

    let settings = BrokrSettings {
        url: "https://brokr.example".to_string(),
    };
    save_settings(dir.path(), &settings).expect("save");
    save_join_token(&store, &JoinToken::new("join-secret".to_string())).expect("save");
    save_session(&store, &Session::new("session-secret".to_string())).expect("save");

    assert_eq!(load_settings(dir.path()).expect("load"), Some(settings));
    assert_eq!(
        load_join_token(&store)
            .expect("load")
            .expect("saved")
            .as_str(),
        "join-secret"
    );
    assert_eq!(
        load_session(&store).expect("load").expect("saved").as_str(),
        "session-secret"
    );

    clear_settings(dir.path()).expect("clear");
    clear_join_token(&store).expect("clear");
    clear_session(&store).expect("clear");
    clear_settings(dir.path()).expect("clearing twice");

    assert_eq!(load_settings(dir.path()).expect("load"), None);
    assert!(load_join_token(&store).expect("load").is_none());
    assert!(load_session(&store).expect("load").is_none());
}

#[test]
fn no_token_reaches_the_settings_file_or_a_debug_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secrets = tempfile::tempdir().expect("tempdir");
    let store = FileStore::new(secrets.path().to_path_buf());
    save_settings(
        dir.path(),
        &BrokrSettings {
            url: "http://127.0.0.1:9".to_string(),
        },
    )
    .expect("save");
    let join = JoinToken::new("join-secret".to_string());
    let session = Session::new("session-secret".to_string());
    save_join_token(&store, &join).expect("save");
    save_session(&store, &session).expect("save");

    let bytes = std::fs::read(dir.path().join("brokr.json")).expect("file");
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("join-secret") && !text.contains("session-secret"));
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .expect("dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(names.len(), 1, "a temporary file was left: {names:?}");
    let shown = format!("{join:?} {session:?}");
    assert!(!shown.contains("join-secret") && !shown.contains("session-secret"));
}

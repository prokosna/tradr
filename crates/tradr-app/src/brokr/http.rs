use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode, Url, redirect};
use serde::{Deserialize, Serialize};

use super::api::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, DeliveryId, InboxEntry,
    OutboxEntry, OutboxState, RegisterRequest, Session,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A Brokr reached over HTTP or HTTPS. It follows no redirect and fetches no
/// JWKS: the only host it ever talks to is the one it was given.
#[derive(Debug)]
pub struct HttpBrokrApi {
    client: Client,
    base: Url,
}

#[derive(Deserialize)]
struct InfoBody {
    version: u32,
    account_salt: String,
    delivery_ttl_days: u32,
    delivery_max_bytes: u64,
    storage_max_bytes: u64,
}

#[derive(Deserialize)]
struct ChallengeBody {
    nonce: String,
}

#[derive(Serialize)]
struct RegisterBody<'a> {
    device_id: &'a str,
    identity_pub: &'a str,
    join_token: &'a str,
    account_tag: &'a str,
    link_tags: &'a [String],
    nonce: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
struct SessionBody {
    session: String,
}

#[derive(Deserialize)]
struct InboxBody {
    id: String,
    sender_device_id: String,
    size: u64,
    uploaded_at: i64,
}

#[derive(Deserialize)]
struct UploadBody {
    id: String,
}

#[derive(Deserialize)]
struct OutboxEntryBody {
    id: String,
    recipient_device_id: String,
    size: u64,
    uploaded_at: i64,
    state: OutboxState,
    collected_at: Option<i64>,
}

fn network(e: reqwest::Error) -> BrokrError {
    BrokrError::Network(e.without_url().to_string())
}

fn malformed(e: reqwest::Error) -> BrokrError {
    BrokrError::Malformed(e.without_url().to_string())
}

fn check(response: Response) -> Result<Response, BrokrError> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else if status == StatusCode::UNAUTHORIZED {
        Err(BrokrError::Unauthorized)
    } else if status == StatusCode::FORBIDDEN {
        Err(BrokrError::NotEligible)
    } else if status == StatusCode::PAYLOAD_TOO_LARGE {
        Err(BrokrError::StorageFull)
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        Err(BrokrError::TooManyWaiting)
    } else {
        Err(BrokrError::Rejected(format!("status {}", status.as_u16())))
    }
}

impl HttpBrokrApi {
    /// Builds an adapter for the Brokr at `base_url`, which must be an `http`
    /// or `https` URL with no path.
    pub fn new(base_url: &str) -> Result<Self, BrokrError> {
        let base = Url::parse(base_url)
            .map_err(|e| BrokrError::Rejected(format!("the Brokr address is not a URL: {e}")))?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(BrokrError::Rejected(
                "the Brokr address must be http or https".to_string(),
            ));
        }
        if base.path() != "/" || base.cannot_be_a_base() {
            return Err(BrokrError::Rejected(
                "the Brokr address must have no path".to_string(),
            ));
        }
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(network)?;
        Ok(Self { client, base })
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder, BrokrError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| BrokrError::Rejected("the Brokr address cannot take a path".to_string()))?
            .extend(segments);
        Ok(self.client.request(method, url))
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, BrokrError> {
        check(request.send().await.map_err(network)?)
    }
}

impl BrokrApi for HttpBrokrApi {
    fn info(&self) -> BrokrFuture<'_, BrokrInfo> {
        Box::pin(async move {
            let response = self
                .send(self.request(Method::GET, &["v1", "info"])?)
                .await?;
            let body: InfoBody = response.json().await.map_err(malformed)?;
            Ok(BrokrInfo {
                version: body.version,
                account_salt: body.account_salt,
                delivery_ttl_days: body.delivery_ttl_days,
                delivery_max_bytes: body.delivery_max_bytes,
                storage_max_bytes: body.storage_max_bytes,
            })
        })
    }

    fn challenge(&self) -> BrokrFuture<'_, Challenge> {
        Box::pin(async move {
            let response = self
                .send(self.request(Method::POST, &["v1", "challenge"])?)
                .await?;
            let body: ChallengeBody = response.json().await.map_err(malformed)?;
            Ok(Challenge { nonce: body.nonce })
        })
    }

    fn register(&self, request: RegisterRequest) -> BrokrFuture<'_, Session> {
        Box::pin(async move {
            let body = RegisterBody {
                device_id: &request.device_id,
                identity_pub: &request.identity_pub,
                join_token: &request.join_token,
                account_tag: &request.account_tag,
                link_tags: &request.link_tags,
                nonce: &request.nonce,
                signature: &request.signature,
            };
            let response = self
                .send(self.request(Method::POST, &["v1", "register"])?.json(&body))
                .await?;
            let body: SessionBody = response.json().await.map_err(malformed)?;
            Ok(Session::new(body.session))
        })
    }

    fn inbox<'a>(&'a self, session: &'a Session) -> BrokrFuture<'a, Vec<InboxEntry>> {
        Box::pin(async move {
            let request = self
                .request(Method::GET, &["v1", "deliveries", "inbox"])?
                .bearer_auth(session.as_str());
            let body: Vec<InboxBody> = self.send(request).await?.json().await.map_err(malformed)?;
            Ok(body
                .into_iter()
                .map(|e| InboxEntry {
                    id: e.id,
                    sender_device_id: e.sender_device_id,
                    size: e.size,
                    uploaded_at: e.uploaded_at,
                })
                .collect())
        })
    }

    fn upload<'a>(
        &'a self,
        session: &'a Session,
        total_len: u64,
        body: ByteStream<'static>,
    ) -> BrokrFuture<'a, DeliveryId> {
        Box::pin(async move {
            let request = self
                .request(Method::PUT, &["v1", "deliveries"])?
                .bearer_auth(session.as_str())
                .header("content-type", "application/octet-stream")
                .header("content-length", total_len)
                .body(reqwest::Body::wrap_stream(body));
            let response = self.send(request).await?;
            let body: UploadBody = response.json().await.map_err(malformed)?;
            Ok(body.id)
        })
    }

    fn download<'a>(
        &'a self,
        session: &'a Session,
        id: &'a str,
    ) -> BrokrFuture<'a, ByteStream<'a>> {
        Box::pin(async move {
            let request = self
                .request(Method::GET, &["v1", "deliveries", id])?
                .bearer_auth(session.as_str());
            let response = self.send(request).await?;
            let stream: ByteStream<'a> = Box::pin(
                response
                    .bytes_stream()
                    .map(|chunk| chunk.map(|b| b.to_vec()).map_err(network)),
            );
            Ok(stream)
        })
    }

    fn acknowledge<'a>(&'a self, session: &'a Session, id: &'a str) -> BrokrFuture<'a, ()> {
        Box::pin(async move {
            let request = self
                .request(Method::DELETE, &["v1", "deliveries", id])?
                .bearer_auth(session.as_str());
            self.send(request).await?;
            Ok(())
        })
    }

    fn outbox<'a>(&'a self, session: &'a Session) -> BrokrFuture<'a, Vec<OutboxEntry>> {
        Box::pin(async move {
            let request = self
                .request(Method::GET, &["v1", "deliveries", "outbox"])?
                .bearer_auth(session.as_str());
            let body: Vec<OutboxEntryBody> =
                self.send(request).await?.json().await.map_err(malformed)?;
            Ok(body
                .into_iter()
                .map(|e| OutboxEntry {
                    id: e.id,
                    recipient_device_id: e.recipient_device_id,
                    size: e.size,
                    uploaded_at: e.uploaded_at,
                    state: e.state,
                    collected_at: e.collected_at,
                })
                .collect())
        })
    }
}

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tradr_core::{
    Clock, DeviceId, KeyStore, LinkSecret, PublicIdentity, RelPath, RootId, SecretStore, UnixTime,
    Vfs,
};
use tradr_identity::AccountId;

use crate::peer_trust::PeerTrust;

use super::api::{BrokrApi, BrokrError, Session};
use super::collect::{CollectContext, CollectReport, collect_once};
use super::placed::PlacedDeliveries;
use super::register::register;
use super::settings::{clear_session, load_join_token, load_session, save_session};

const PASS_INTERVAL: Duration = Duration::from_secs(5 * 60);

fn local(e: impl std::fmt::Display) -> BrokrError {
    BrokrError::Local(e.to_string())
}

/// Answers the stored session, or registers with the stored join token and
/// stores the session that answers.
pub async fn ensure_session(
    api: &dyn BrokrApi,
    secrets: &(dyn SecretStore + Sync),
    key_store: &dyn KeyStore,
    identity: &PublicIdentity,
    own_account: &AccountId,
    link_secrets: &[LinkSecret],
) -> Result<Session, BrokrError> {
    if let Some(session) = load_session(secrets).map_err(local)? {
        return Ok(session);
    }
    let join_token = load_join_token(secrets)
        .map_err(local)?
        .ok_or_else(|| BrokrError::Local("no join token is stored".to_string()))?;
    let session = register(
        api,
        key_store,
        identity,
        own_account,
        link_secrets,
        join_token.as_str(),
    )
    .await?;
    save_session(secrets, &session).map_err(local)?;
    Ok(session)
}

/// One collecting pass. A refused session is dropped, registered anew and the
/// pass retried once, so a Brokr that keeps refusing is an error, not a loop.
pub async fn run_pass<V: Vfs>(
    api: &dyn BrokrApi,
    secrets: &(dyn SecretStore + Sync),
    key_store: &dyn KeyStore,
    link_secrets: &[LinkSecret],
    ctx: &CollectContext<'_, V>,
) -> Result<CollectReport, BrokrError> {
    let session = ensure_session(
        api,
        secrets,
        key_store,
        ctx.recipient,
        ctx.own_account,
        link_secrets,
    )
    .await?;
    match collect_once(api, &session, ctx).await {
        Err(BrokrError::Unauthorized) => {
            clear_session(secrets).map_err(local)?;
            let session = ensure_session(
                api,
                secrets,
                key_store,
                ctx.recipient,
                ctx.own_account,
                link_secrets,
            )
            .await?;
            collect_once(api, &session, ctx).await
        }
        outcome => outcome,
    }
}

/// The accounts and Link Secrets of this device's Links, as of one pass.
#[derive(Debug, Default)]
pub struct LinkView {
    /// The accounts a delivery's sender may belong to besides this device's own.
    pub accounts: Vec<AccountId>,
    /// The secrets whose tags the Brokr files this device's Link deliveries under.
    pub secrets: Vec<LinkSecret>,
}

/// Reads this device's signed-in account, or `None` when signed out.
pub type OwnAccountFn = Arc<dyn Fn() -> Option<AccountId> + Send + Sync>;

/// Reads this device's Links and their Link Secrets, or why they cannot be read.
pub type LinksFn = Arc<dyn Fn() -> Result<LinkView, String> + Send + Sync>;

/// Called with the sender and the placed paths once a delivery is complete.
pub type ArrivalHook = Arc<dyn Fn(DeviceId, &[RelPath]) + Send + Sync>;

/// What a collector reads fresh at each pass, so a sign-in or a Link made
/// after start-up takes effect on the next one.
pub struct CollectorParts<V> {
    /// The Brokr.
    pub api: Arc<dyn BrokrApi>,
    /// Where the session and join token live.
    pub secrets: Arc<dyn SecretStore + Send + Sync>,
    /// The device's key store.
    pub key_store: Arc<dyn KeyStore>,
    /// The device's own identity.
    pub identity: PublicIdentity,
    /// Where deliveries are placed.
    pub vfs: Arc<V>,
    /// The root they are placed in.
    pub root: RootId,
    /// The device's clock.
    pub clock: Arc<dyn Clock + Send + Sync>,
    /// Classifies each sender's Attestation.
    pub trust: Arc<PeerTrust>,
    /// This device's account, `None` while it is not signed in.
    pub own_account: OwnAccountFn,
    /// This device's Links, or why they cannot be read.
    pub links: LinksFn,
    /// Called with the sender and the placed paths once a delivery is complete.
    pub on_arrival: ArrivalHook,
    /// Tracks placed delivery identifiers to prevent duplicated downloads.
    pub placed: Arc<PlacedDeliveries>,
}

/// What the last collecting pass did. Never carries a token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectorStatus {
    /// How many passes have completed.
    pub pass_count: u64,
    /// When the last pass ended, or `None` before the first.
    pub last_pass: Option<UnixTime>,
    /// Deliveries the last pass placed.
    pub delivered: usize,
    /// A short message when the last pass failed.
    pub last_error: Option<String>,
}

struct Shared {
    wake: Notify,
    stop: Notify,
    status_tx: watch::Sender<CollectorStatus>,
}

/// Collects Deferred Deliveries at start, on `wake()` and every five minutes.
pub struct Collector<V> {
    parts: Arc<CollectorParts<V>>,
    shared: Arc<Shared>,
}

impl<V> Clone for Collector<V> {
    fn clone(&self) -> Self {
        Self {
            parts: Arc::clone(&self.parts),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<V: Vfs + 'static> Collector<V> {
    /// Builds a collector that has not run yet.
    pub fn new(parts: CollectorParts<V>) -> Self {
        Self {
            parts: Arc::new(parts),
            shared: Arc::new(Shared {
                wake: Notify::new(),
                stop: Notify::new(),
                status_tx: watch::Sender::new(CollectorStatus::default()),
            }),
        }
    }

    /// Asks for a pass now instead of waiting out the interval.
    pub fn wake(&self) {
        self.shared.wake.notify_one();
    }

    /// Ends `run` once the pass in progress, if any, is over.
    pub fn stop(&self) {
        self.shared.stop.notify_one();
    }

    /// What the last pass did.
    pub fn status(&self) -> CollectorStatus {
        self.shared.status_tx.borrow().clone()
    }

    /// Subscribes to status updates emitted after each pass.
    pub fn subscribe(&self) -> watch::Receiver<CollectorStatus> {
        self.shared.status_tx.subscribe()
    }

    /// Runs passes until `stop()`.
    pub async fn run(self) {
        loop {
            let outcome = self.pass().await;
            self.record(outcome);
            tokio::select! {
                biased;
                () = self.shared.stop.notified() => return,
                () = self.shared.wake.notified() => {}
                () = tokio::time::sleep(PASS_INTERVAL) => {}
            }
        }
    }

    async fn pass(&self) -> Result<CollectReport, BrokrError> {
        let parts = &self.parts;
        let own_account = (parts.own_account)()
            .ok_or_else(|| BrokrError::Local("sign in before collecting".to_string()))?;
        let links = (parts.links)().map_err(local)?;
        let key_store = Arc::clone(&parts.key_store);
        let agree = |peer: &_| key_store.agree(peer);
        let ctx = CollectContext {
            vfs: parts.vfs.as_ref(),
            root: parts.root,
            recipient: &parts.identity,
            agree: &agree,
            clock: parts.clock.as_ref(),
            trust: parts.trust.as_ref(),
            own_account: &own_account,
            linked_accounts: &links.accounts,
            on_arrival: parts.on_arrival.as_ref(),
            placed: parts.placed.as_ref(),
        };
        run_pass(
            parts.api.as_ref(),
            parts.secrets.as_ref(),
            parts.key_store.as_ref(),
            &links.secrets,
            &ctx,
        )
        .await
    }

    fn record(&self, outcome: Result<CollectReport, BrokrError>) {
        let (delivered, last_error) = match outcome {
            Ok(report) => (report.delivered, None),
            Err(e) => (0, Some(e.to_string())),
        };
        self.shared.status_tx.send_modify(|s| {
            s.pass_count += 1;
            s.last_pass = Some(self.parts.clock.now());
            s.delivered = delivered;
            s.last_error = last_error;
        });
    }
}

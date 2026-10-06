use std::cell::RefCell;

use futures_util::StreamExt;
use tradr_core::{
    Clock, DeviceId, KeyStoreError, PublicIdentity, PublicKeyPoint, RelPath, RootId, SharedSecret,
    UnixTime, Vfs, VfsError, WriteAt,
};
use tradr_identity::AccountId;
use tradr_identity::envelope::{EnvelopeReader, ReaderEvent};

use crate::peer_trust::{ClassifyCachedError, PeerTrust};
use crate::transfer::{TransferSessionError, place_verified_file};

use super::api::{BrokrApi, BrokrError, InboxEntry, Session};

const MAX_DELIVERY_ID_LEN: usize = 64;

/// What one collecting pass needs of this device.
pub struct CollectContext<'a, V: Vfs> {
    /// Where deliveries are placed.
    pub vfs: &'a V,
    /// The root they are placed in.
    pub root: RootId,
    /// The recipient's own identity, which envelopes are sealed to.
    pub recipient: &'a PublicIdentity,
    /// `KeyStore::agree` for the recipient's agreement key.
    pub agree: &'a dyn Fn(&PublicKeyPoint) -> Result<SharedSecret, KeyStoreError>,
    /// The device's clock.
    pub clock: &'a (dyn Clock + Sync),
    /// Classifies each sender's Attestation and holds the JWKS cache.
    pub trust: &'a PeerTrust,
    /// The account this device is signed in to.
    pub own_account: &'a AccountId,
    /// The accounts of this device's Links.
    pub linked_accounts: &'a [AccountId],
    /// Called with the sender and the placed paths once a delivery is complete.
    pub on_arrival: &'a (dyn Fn(DeviceId, &[RelPath]) + Send + Sync),
}

/// What one collecting pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CollectReport {
    /// Deliveries opened, placed and acknowledged.
    pub delivered: usize,
    /// Deliveries that could never verify, each with its id and a one-line reason.
    pub refused: Vec<(String, String)>,
}

enum Step {
    Opened {
        sender: DeviceId,
        placed: Vec<RelPath>,
    },
    Refused(String),
    JwksNeeded(String),
}

struct Partials {
    dir: RelPath,
    dests: Vec<RelPath>,
    current: Option<(usize, Box<dyn WriteAt>, u64)>,
    placed: Vec<RelPath>,
}

fn local(e: impl std::fmt::Display) -> BrokrError {
    BrokrError::Local(e.to_string())
}

fn partial_path(dir: &RelPath, index: usize) -> Result<RelPath, BrokrError> {
    RelPath::new(&format!("{dir}/item-{index}")).map_err(local)
}

/// Collects every delivery waiting in the inbox, oldest first. A failure to
/// reach the Brokr or to write locally leaves the delivery in place and ends
/// the pass with an error; a delivery that cannot verify is acknowledged and
/// reported instead.
pub async fn collect_once<V: Vfs>(
    api: &dyn BrokrApi,
    session: &Session,
    ctx: &CollectContext<'_, V>,
) -> Result<CollectReport, BrokrError> {
    let mut entries = api.inbox(session).await?;
    entries.sort_by_key(|e| e.uploaded_at);

    let mut report = CollectReport::default();
    for entry in &entries {
        match collect_delivery(api, session, ctx, entry).await? {
            None => report.delivered += 1,
            Some(reason) => report.refused.push((entry.id.clone(), reason)),
        }
    }
    Ok(report)
}

// Answers `None` when delivered and the refusal reason otherwise.
async fn collect_delivery<V: Vfs>(
    api: &dyn BrokrApi,
    session: &Session,
    ctx: &CollectContext<'_, V>,
    entry: &InboxEntry,
) -> Result<Option<String>, BrokrError> {
    // The id comes from the Brokr and becomes a path component.
    let id = entry.id.as_str();
    if id.is_empty() || id.len() > MAX_DELIVERY_ID_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(Some("the delivery id is not hex".to_string()));
    }
    let dir = RelPath::new(&format!(".tradr-partial/deferred-{id}")).map_err(local)?;

    let mut step = attempt(api, session, ctx, id, &dir).await;
    if let Ok(Step::JwksNeeded(uri)) = &step {
        ctx.trust
            .warm(uri)
            .await
            .map_err(|e| BrokrError::Network(format!("the provider's keys: {e}")))?;
        step = attempt(api, session, ctx, id, &dir).await.map(|s| match s {
            Step::JwksNeeded(_) => {
                Step::Refused("the provider's keys do not verify this token".to_string())
            }
            other => other,
        });
    }

    match step {
        Err(e) => {
            remove_partial(ctx, &dir).await?;
            Err(e)
        }
        Ok(Step::Refused(reason)) => {
            remove_partial(ctx, &dir).await?;
            api.acknowledge(session, id).await?;
            Ok(Some(reason))
        }
        Ok(Step::Opened { sender, placed }) => {
            api.acknowledge(session, id).await?;
            remove_partial(ctx, &dir).await?;
            (ctx.on_arrival)(sender, &placed);
            Ok(None)
        }
        Ok(Step::JwksNeeded(_)) => Err(BrokrError::Malformed(
            "a retry reported a missing key twice".to_string(),
        )),
    }
}

async fn attempt<V: Vfs>(
    api: &dyn BrokrApi,
    session: &Session,
    ctx: &CollectContext<'_, V>,
    id: &str,
    dir: &RelPath,
) -> Result<Step, BrokrError> {
    // A partial left by an interrupted pass would be written over, not truncated.
    remove_partial(ctx, dir).await?;

    let jwks_needed: RefCell<Option<String>> = RefCell::new(None);
    let verify = |token: &str, sender: &PublicIdentity, created_at: UnixTime| {
        ctx.trust
            .classify_cached(
                token,
                sender.identity_pub(),
                sender.agreement_pub(),
                ctx.own_account,
                ctx.linked_accounts,
                created_at,
            )
            .map_err(|e| {
                if let ClassifyCachedError::JwksNeeded { jwks_uri } = &e {
                    *jwks_needed.borrow_mut() = Some(jwks_uri.clone());
                }
                e.to_string()
            })
    };
    let mut reader = EnvelopeReader::new(ctx.recipient, ctx.agree, ctx.clock.now(), &verify);

    let mut stream = api.download(session, id).await?;
    let mut partials = Partials {
        dir: dir.clone(),
        dests: Vec::new(),
        current: None,
        placed: Vec::new(),
    };

    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        let events = match reader.feed(&bytes) {
            Ok(events) => events,
            Err(e) => {
                return Ok(match jwks_needed.take() {
                    Some(uri) => Step::JwksNeeded(uri),
                    None => Step::Refused(e.to_string()),
                });
            }
        };
        for event in events {
            if let Some(step) = apply(ctx, &mut partials, event).await? {
                return Ok(step);
            }
        }
    }
    drop(stream);

    match reader.finish() {
        Ok(manifest) => Ok(Step::Opened {
            sender: manifest.sender().device_id(),
            placed: partials.placed,
        }),
        Err(e) => Ok(Step::Refused(e.to_string())),
    }
}

async fn apply<V: Vfs>(
    ctx: &CollectContext<'_, V>,
    partials: &mut Partials,
    event: ReaderEvent,
) -> Result<Option<Step>, BrokrError> {
    match event {
        ReaderEvent::Manifest(manifest) => {
            partials.dests = manifest
                .items()
                .iter()
                .map(|item| item.rel_path().clone())
                .collect();
            ctx.vfs
                .create_dir(ctx.root, &partials.dir)
                .await
                .map_err(local)?;
        }
        ReaderEvent::ItemData { index, bytes } => {
            ensure_open(ctx, partials, index).await?;
            if let Some((_, writer, offset)) = partials.current.as_mut() {
                writer.write_at(*offset, &bytes).await.map_err(local)?;
                *offset += bytes.len() as u64;
            }
        }
        ReaderEvent::ItemVerified { index } => {
            ensure_open(ctx, partials, index).await?;
            if let Some((_, mut writer, _)) = partials.current.take() {
                writer.sync().await.map_err(local)?;
            }
            let from = partial_path(&partials.dir, index)?;
            let dest = partials
                .dests
                .get(index)
                .ok_or_else(|| BrokrError::Malformed("item index outside the manifest".into()))?;
            match place_verified_file(ctx.vfs, ctx.root, &from, dest).await {
                Ok(placed) => partials.placed.push(placed),
                Err(TransferSessionError::Vfs(e)) => return Err(local(e)),
                Err(e) => return Ok(Some(Step::Refused(e.to_string()))),
            }
        }
    }
    Ok(None)
}

async fn ensure_open<V: Vfs>(
    ctx: &CollectContext<'_, V>,
    partials: &mut Partials,
    index: usize,
) -> Result<(), BrokrError> {
    if matches!(&partials.current, Some((open, _, _)) if *open == index) {
        return Ok(());
    }
    let path = partial_path(&partials.dir, index)?;
    let writer = ctx.vfs.open_write(ctx.root, &path).await.map_err(local)?;
    partials.current = Some((index, writer, 0));
    Ok(())
}

async fn remove_partial<V: Vfs>(
    ctx: &CollectContext<'_, V>,
    dir: &RelPath,
) -> Result<(), BrokrError> {
    let entries = match ctx.vfs.list(ctx.root, dir).await {
        Ok(entries) => entries,
        Err(VfsError::NotFound) => return Ok(()),
        Err(e) => return Err(local(e)),
    };
    for entry in entries {
        let path = RelPath::new(&format!("{dir}/{}", entry.name)).map_err(local)?;
        match ctx.vfs.remove(ctx.root, &path).await {
            Ok(()) | Err(VfsError::NotFound) => {}
            Err(e) => return Err(local(e)),
        }
    }
    match ctx.vfs.remove(ctx.root, dir).await {
        Ok(()) | Err(VfsError::NotFound) => Ok(()),
        Err(e) => Err(local(e)),
    }
}

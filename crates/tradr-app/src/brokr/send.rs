use futures_util::stream;
use tradr_core::{
    Clock, ContentHash, DeviceId, KeyStore, PublicIdentity, ReadAt, Rng, TrustTier, Vfs,
};
use tradr_identity::KnownDevice;
use tradr_identity::envelope::{EnvelopeItem, EnvelopeSender, EnvelopeWriter};

use super::api::{BrokrApi, BrokrError, ByteStream, DeliveryId, Session};
use crate::send::SendItem;

const CHUNK_SIZE: usize = 1024 * 1024;

/// Ambient services and credentials required to seal and upload a Deferred Delivery.
pub struct SendDeferredContext<'a, V: Vfs> {
    /// The virtual filesystem from which send items are read.
    pub vfs: &'a V,
    /// This device's public identity.
    pub identity: &'a PublicIdentity,
    /// Key store capable of signing with this device's identity key.
    pub key_store: &'a (dyn KeyStore + Sync),
    /// Unverified attestation token issued for this device.
    pub attestation_token: String,
    /// Random number generator for generating envelope ephemeral keys and transfer IDs.
    pub rng: &'a (dyn Rng + Sync),
    /// Clock for timestamping transfer manifest and key binding.
    pub clock: &'a (dyn Clock + Sync),
}

/// Convenience alias for the deferred send context.
pub type SendContext<'a, V> = SendDeferredContext<'a, V>;

/// The outcome of handing an encrypted envelope to the Brokr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentDelivery {
    /// The delivery identifier assigned by the Brokr.
    pub id: DeliveryId,
    /// The recipient's Device ID.
    pub recipient: DeviceId,
    /// Relative filenames included in the delivery.
    pub names: Vec<String>,
    /// Total envelope length uploaded in bytes.
    pub total_len: u64,
}

impl SentDelivery {
    /// The delivery identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The recipient device identifier.
    pub fn recipient(&self) -> DeviceId {
        self.recipient
    }

    /// The recipient device identifier.
    pub fn recipient_device_id(&self) -> DeviceId {
        self.recipient
    }

    /// Relative filenames carried in the delivery.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Total envelope byte length uploaded.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }
}

struct StreamState {
    writer: Option<EnvelopeWriter>,
    head: Option<Vec<u8>>,
    handles: Vec<(Box<dyn ReadAt>, u64)>,
    current_idx: usize,
    current_offset: u64,
    finished: bool,
}

/// Seals and uploads an encrypted envelope to the Brokr for an offline recipient.
pub async fn send_deferred<V: Vfs>(
    api: &dyn BrokrApi,
    session: &Session,
    ctx: &SendDeferredContext<'_, V>,
    recipient: &KnownDevice,
    items: &[SendItem],
) -> Result<SentDelivery, BrokrError> {
    if !matches!(recipient.tier(), TrustTier::SameAccount | TrustTier::Linked) {
        return Err(BrokrError::Rejected(
            "recipient trust tier is not eligible for deferred delivery".to_string(),
        ));
    }

    let mut envelope_items = Vec::with_capacity(items.len());
    for item in items {
        let read_handle = ctx
            .vfs
            .open_read(item.root, &item.rel_path)
            .await
            .map_err(|e| BrokrError::Local(format!("vfs open error: {e}")))?;

        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut offset = 0u64;

        loop {
            let n = read_handle
                .read_at(offset, &mut buf)
                .await
                .map_err(|e| BrokrError::Local(format!("vfs read error: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            offset = match offset.checked_add(n as u64) {
                Some(next) => next,
                None => return Err(BrokrError::Local("file size overflow".to_string())),
            };
        }

        if offset != item.size_bytes {
            return Err(BrokrError::Rejected(format!(
                "file size on disk ({offset}) differs from declared SendItem ({})",
                item.size_bytes
            )));
        }

        let content_hash = ContentHash::from_bytes(*hasher.finalize().as_bytes());
        envelope_items.push(EnvelopeItem::new(
            item.rel_path.clone(),
            offset,
            content_hash,
        ));
    }

    let key_binding = crate::listener::build_key_binding(ctx.key_store, ctx.identity, ctx.clock)
        .map_err(|e| match e {
            crate::handshake::HandshakeError::KeyStore(k) => BrokrError::Key(k),
            other => BrokrError::Rejected(other.to_string()),
        })?;

    let sender = EnvelopeSender::new(
        ctx.identity.clone(),
        key_binding,
        ctx.attestation_token.clone(),
    );

    let transfer_id = crate::send::generate_transfer_id(ctx.rng, ctx.clock)
        .map_err(|e| BrokrError::Rejected(format!("failed to generate transfer id: {e}")))?;

    let (writer, head) = EnvelopeWriter::new(
        recipient.identity(),
        &sender,
        ctx.key_store,
        ctx.rng,
        transfer_id,
        ctx.clock.now(),
        envelope_items,
    )
    .map_err(|e| BrokrError::Rejected(format!("envelope setup failed: {e}")))?;

    let total_len = writer.total_len();

    let mut handles = Vec::with_capacity(items.len());
    for item in items {
        let handle = ctx
            .vfs
            .open_read(item.root, &item.rel_path)
            .await
            .map_err(|e| BrokrError::Local(format!("vfs open error: {e}")))?;
        handles.push((handle, item.size_bytes));
    }

    let state = StreamState {
        writer: Some(writer),
        head: Some(head),
        handles,
        current_idx: 0,
        current_offset: 0,
        finished: false,
    };

    let body_stream: ByteStream<'static> =
        Box::pin(stream::unfold(state, |mut state| async move {
            loop {
                if let Some(head) = state.head.take() {
                    return Some((Ok(head), state));
                }

                if state.current_idx < state.handles.len() {
                    let (handle, declared_size) = &state.handles[state.current_idx];
                    if state.current_offset >= *declared_size {
                        state.current_idx += 1;
                        state.current_offset = 0;
                        continue;
                    }
                    let remaining = (*declared_size - state.current_offset) as usize;
                    let to_read = remaining.min(CHUNK_SIZE);
                    let mut buf = vec![0u8; to_read];
                    let n = match handle.read_at(state.current_offset, &mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            return Some((
                                Err(BrokrError::Local(format!("vfs read error: {e}"))),
                                state,
                            ));
                        }
                    };
                    if n == 0 {
                        return Some((
                            Err(BrokrError::Local(
                                "unexpected end of file during stream read".to_string(),
                            )),
                            state,
                        ));
                    }
                    state.current_offset += n as u64;
                    let sealed = match state.writer.as_mut() {
                        Some(w) => match w.push(&buf[..n]) {
                            Ok(s) => s,
                            Err(e) => {
                                return Some((
                                    Err(BrokrError::Local(format!("envelope push error: {e}"))),
                                    state,
                                ));
                            }
                        },
                        None => {
                            return Some((
                                Err(BrokrError::Local("envelope writer unavailable".to_string())),
                                state,
                            ));
                        }
                    };
                    if !sealed.is_empty() {
                        return Some((Ok(sealed), state));
                    }
                    continue;
                }

                if !state.finished {
                    state.finished = true;
                    let writer = match state.writer.take() {
                        Some(w) => w,
                        None => {
                            return Some((
                                Err(BrokrError::Local(
                                    "envelope writer already consumed".to_string(),
                                )),
                                state,
                            ));
                        }
                    };
                    let final_record = match writer.finish() {
                        Ok(f) => f,
                        Err(e) => {
                            return Some((
                                Err(BrokrError::Local(format!("envelope finish error: {e}"))),
                                state,
                            ));
                        }
                    };
                    return Some((Ok(final_record), state));
                }

                return None;
            }
        }));

    let id = api.upload(session, total_len, body_stream).await?;

    let names = items
        .iter()
        .map(|it| it.rel_path.as_str().to_string())
        .collect();

    Ok(SentDelivery {
        id,
        recipient: recipient.device_id(),
        names,
        total_len,
    })
}

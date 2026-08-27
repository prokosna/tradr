//! Listener half of the composition root (docs/04-protocol.md, docs/03).
//! Accepts incoming channels, runs the Hello handshake, negotiates transfer offers,
//! derives chunk resumption from disk, and drives file reception.

use std::fmt;
use std::future::Future;

use tradr_core::{
    Capabilities, ChunkIndex, Clock, ContentVerifier, Incoming, ItemAcceptance,
    ItemAcceptanceError, ItemResumption, KeyBinding, KeyStore, OfferItem, PublicIdentity,
    REFERENCE_CHUNK_SIZE_BYTES, RecvStream, RelPath, Rng, RootId, SecureChannel, TransferAccept,
    TransferAcceptError, TransferId, TransferOffer, TransportError, TrustTier, VersionRange, Vfs,
    VfsError,
};
use tradr_identity::hello::AttestationRequest;
use tradr_proto::control::{
    OfferFrameError, decode_transfer_offer_frame, encode_transfer_accept_frame,
};
use tradr_proto::framing::{Frame, FrameDecoder, FrameError};
use tradr_proto::message_type::{Classification, MessageType, Plane, classify};
use tradr_vfs::partial_file_rel_path;

use crate::handshake::{HandshakeError, HandshakeParams, perform_handshake};
use crate::transfer::{ReceiveRequest, SessionStreams, TransferSessionError, receive_file};

/// Configuration parameters for the listener half of the composition root.
#[derive(Clone)]
pub struct ListenerParams<'a> {
    /// The VFS root where incoming and partial files are placed.
    pub root: RootId,
    /// Our public identity (identity_pub and agreement_pub).
    pub our_identity: &'a PublicIdentity,
    /// Our OIDC provider-signed ID token.
    pub our_attestation_token: String,
    /// Our key binding linking agreement key to identity key.
    pub our_key_binding: KeyBinding,
    /// Supported protocol version range.
    pub our_versions: VersionRange,
    /// Supported transport and plane capabilities.
    pub our_capabilities: Capabilities,
}

/// Errors occurring during incoming transfer acceptance and session execution.
#[derive(Debug)]
pub enum ListenerError {
    /// Transport-level error while performing stream I/O or accepting channels.
    Transport(TransportError),
    /// Handshake failure during the 4-step Hello exchange.
    Handshake(HandshakeError),
    /// Framing, encoding, or decoding error during Offer exchange.
    OfferFrame(OfferFrameError),
    /// Transfer acceptance validation error against the received offer.
    AcceptValidation(TransferAcceptError),
    /// Item acceptance construction error.
    ItemAcceptance(ItemAcceptanceError),
    /// Transfer session failure while receiving files.
    TransferSession(TransferSessionError),
    /// Filesystem error during resumption inspection or directory creation.
    Vfs(VfsError),
    /// Protocol violation or unexpected message on the control stream.
    ProtocolViolation(String),
}

impl fmt::Display for ListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Handshake(e) => write!(f, "handshake error: {e}"),
            Self::OfferFrame(e) => write!(f, "offer framing error: {e}"),
            Self::AcceptValidation(e) => write!(f, "transfer accept validation error: {e}"),
            Self::ItemAcceptance(e) => write!(f, "item acceptance error: {e}"),
            Self::TransferSession(e) => write!(f, "transfer session error: {e}"),
            Self::Vfs(e) => write!(f, "vfs error: {e}"),
            Self::ProtocolViolation(msg) => write!(f, "protocol violation: {msg}"),
        }
    }
}

impl std::error::Error for ListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Handshake(e) => Some(e),
            Self::OfferFrame(e) => Some(e),
            Self::AcceptValidation(e) => Some(e),
            Self::ItemAcceptance(e) => Some(e),
            Self::TransferSession(e) => Some(e),
            Self::Vfs(e) => Some(e),
            Self::ProtocolViolation(_) => None,
        }
    }
}

impl From<TransportError> for ListenerError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
    }
}

impl From<HandshakeError> for ListenerError {
    fn from(err: HandshakeError) -> Self {
        Self::Handshake(err)
    }
}

impl From<OfferFrameError> for ListenerError {
    fn from(err: OfferFrameError) -> Self {
        Self::OfferFrame(err)
    }
}

impl From<TransferAcceptError> for ListenerError {
    fn from(err: TransferAcceptError) -> Self {
        Self::AcceptValidation(err)
    }
}

impl From<ItemAcceptanceError> for ListenerError {
    fn from(err: ItemAcceptanceError) -> Self {
        Self::ItemAcceptance(err)
    }
}

impl From<TransferSessionError> for ListenerError {
    fn from(err: TransferSessionError) -> Self {
        Self::TransferSession(err)
    }
}

impl From<VfsError> for ListenerError {
    fn from(err: VfsError) -> Self {
        Self::Vfs(err)
    }
}

// Reading exact byte count prevents stream offset misalignment on subsequent frames.
async fn read_exact(
    recv: &mut (impl RecvStream + ?Sized),
    mut buf: &mut [u8],
) -> Result<(), ListenerError> {
    while !buf.is_empty() {
        let n = recv.read(buf).await.map_err(ListenerError::Transport)?;
        if n == 0 {
            return Err(ListenerError::Transport(TransportError::Closed));
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

// Length prefix is bounded before buffer allocation to prevent memory exhaustion.
async fn read_frame(
    recv: &mut (impl RecvStream + ?Sized),
    max_frame_size: u32,
) -> Result<Frame, ListenerError> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    if announced == 0 {
        return Err(ListenerError::OfferFrame(OfferFrameError::Framing(
            FrameError::Empty,
        )));
    }
    if announced > max_frame_size {
        return Err(ListenerError::OfferFrame(OfferFrameError::Framing(
            FrameError::Oversized {
                announced: announced as u64,
                limit: max_frame_size,
            },
        )));
    }

    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    read_exact(recv, &mut raw[4..]).await?;

    let mut decoder = FrameDecoder::new(max_frame_size);
    decoder.feed(&raw);
    let frame = decoder
        .next_frame()
        .map_err(OfferFrameError::Framing)
        .map_err(ListenerError::OfferFrame)?
        .ok_or_else(|| {
            ListenerError::ProtocolViolation("incomplete frame in buffer".to_string())
        })?;
    Ok(frame)
}

// Ignores unassigned control messages for forward compatibility while refusing bad planes.
async fn read_transfer_offer(
    control_recv: &mut (impl RecvStream + ?Sized),
    max_frame_size: u32,
) -> Result<TransferOffer, ListenerError> {
    loop {
        let frame = read_frame(control_recv, max_frame_size).await?;
        match classify(frame.type_code(), Plane::Control) {
            Classification::Known(MessageType::TransferOffer) => {
                let offer =
                    decode_transfer_offer_frame(&frame).map_err(ListenerError::OfferFrame)?;
                return Ok(offer);
            }
            Classification::Ignorable => continue,
            Classification::Refused(e) => {
                return Err(ListenerError::ProtocolViolation(e.to_string()));
            }
            Classification::Known(other) => {
                return Err(ListenerError::ProtocolViolation(format!(
                    "unexpected control plane message: {other:?}"
                )));
            }
        }
    }
}

/// Derives the resumption state for an offered item by inspecting partial files on disk.
pub async fn derive_item_resumption(
    vfs: &impl Vfs,
    root: RootId,
    transfer_id: TransferId,
    item: &OfferItem,
) -> Result<ItemResumption, VfsError> {
    let partial_path = partial_file_rel_path(transfer_id, item.item_id());
    let mut resumption = ItemResumption::new(*item.item_id(), item.size());
    let total_chunks = item.chunk_count();

    match vfs.stat(root, &partial_path).await {
        Ok(meta) => {
            let full_chunks = (meta.size_bytes / REFERENCE_CHUNK_SIZE_BYTES).min(total_chunks);
            for idx in 0..full_chunks {
                if let Ok(chunk_sz) = resumption.chunk_size(ChunkIndex::new(idx)) {
                    let _ = resumption.record_piece(ChunkIndex::new(idx), 0, chunk_sz);
                    let _ = resumption.mark_verified(ChunkIndex::new(idx));
                }
            }
            if full_chunks < total_chunks && meta.size_bytes >= item.size() {
                let last_idx = total_chunks.saturating_sub(1);
                if let Ok(chunk_sz) = resumption.chunk_size(ChunkIndex::new(last_idx)) {
                    let _ = resumption.record_piece(ChunkIndex::new(last_idx), 0, chunk_sz);
                    let _ = resumption.mark_verified(ChunkIndex::new(last_idx));
                }
            }
            Ok(resumption)
        }
        Err(VfsError::NotFound) => Ok(resumption),
        Err(e) => Err(e),
    }
}

/// Handles a single incoming secure channel through handshake, offer exchange, and file reception.
#[allow(clippy::too_many_arguments)]
pub async fn handle_incoming_channel<V, F, Fut>(
    channel: &dyn SecureChannel,
    vfs: &V,
    params: ListenerParams<'_>,
    key_store: &dyn KeyStore,
    rng: &dyn Rng,
    clock: &dyn Clock,
    verifier: &dyn ContentVerifier,
    verify_attestation: F,
    item_filter: Option<&(dyn Fn(&OfferItem) -> bool + Send + Sync)>,
) -> Result<Vec<RelPath>, ListenerError>
where
    V: Vfs,
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let (mut control_send, mut control_recv) = channel
        .accept_bi()
        .await
        .map_err(ListenerError::Transport)?;

    let handshake_params = HandshakeParams {
        authenticated_peer: channel.peer(),
        our_channel_max_frame_size: channel.max_frame_size(),
        our_identity: params.our_identity,
        our_attestation_token: params.our_attestation_token,
        our_key_binding: params.our_key_binding,
        our_versions: params.our_versions,
        our_capabilities: params.our_capabilities,
    };

    let session = perform_handshake(
        control_send.as_mut(),
        control_recv.as_mut(),
        handshake_params,
        key_store,
        rng,
        clock,
        verify_attestation,
    )
    .await
    .map_err(ListenerError::Handshake)?;

    let offer = read_transfer_offer(control_recv.as_mut(), channel.max_frame_size()).await?;

    let mut accepted_items = Vec::new();
    let mut items_to_receive = Vec::new();

    for item in offer.items() {
        let is_accepted = item_filter.is_none_or(|f| f(item));
        if is_accepted {
            let resumption =
                derive_item_resumption(vfs, params.root, offer.transfer_id(), item).await?;
            let resume_chunk = match resumption.next_chunk_request(1) {
                Some((c, _)) => c.value(),
                None => item.chunk_count().saturating_sub(1),
            };
            let item_acc = ItemAcceptance::new(*item.item_id(), true, resume_chunk, Vec::new())
                .map_err(ListenerError::ItemAcceptance)?;
            accepted_items.push(item_acc);
            items_to_receive.push(item);
        }
    }

    if accepted_items.is_empty() {
        for item in offer.items() {
            let item_acc = ItemAcceptance::new(*item.item_id(), false, 0, Vec::new())
                .map_err(ListenerError::ItemAcceptance)?;
            accepted_items.push(item_acc);
        }
    }

    let transfer_accept = TransferAccept::new(offer.transfer_id(), accepted_items, None)
        .map_err(ListenerError::AcceptValidation)?;
    transfer_accept
        .for_offer(&offer)
        .map_err(ListenerError::AcceptValidation)?;

    let accept_frame =
        encode_transfer_accept_frame(&transfer_accept, session.peer_max_frame_size())
            .map_err(ListenerError::OfferFrame)?;
    control_send
        .write_all(&accept_frame)
        .await
        .map_err(ListenerError::Transport)?;

    let mut placed_paths = Vec::with_capacity(items_to_receive.len());
    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());

    for item in items_to_receive {
        let (mut data_send, mut data_recv) = channel
            .accept_bi()
            .await
            .map_err(ListenerError::Transport)?;

        let recv_req = ReceiveRequest {
            root: params.root,
            dest_rel_path: item.rel_path(),
            total_bytes: item.size(),
            content_hash: item.content_hash(),
            transfer_id: offer.transfer_id(),
            item_id: *item.item_id(),
            max_frame_size: negotiated_frame_bound,
        };

        let mut streams = SessionStreams {
            control_send: control_send.as_mut(),
            control_recv: control_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };

        let placed = receive_file(vfs, &recv_req, verifier, &mut streams)
            .await
            .map_err(ListenerError::TransferSession)?;
        placed_paths.push(placed);
    }

    Ok(placed_paths)
}

/// Accepts the next channel from `incoming` and handles the transfer session.
#[allow(clippy::too_many_arguments)]
pub async fn accept_and_handle_transfer<V, F, Fut>(
    incoming: &mut (impl Incoming + ?Sized),
    vfs: &V,
    params: ListenerParams<'_>,
    key_store: &dyn KeyStore,
    rng: &dyn Rng,
    clock: &dyn Clock,
    verifier: &dyn ContentVerifier,
    verify_attestation: F,
    item_filter: Option<&(dyn Fn(&OfferItem) -> bool + Send + Sync)>,
) -> Result<Vec<RelPath>, ListenerError>
where
    V: Vfs,
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let channel = incoming.accept().await.map_err(ListenerError::Transport)?;
    handle_incoming_channel(
        channel.as_ref(),
        vfs,
        params,
        key_store,
        rng,
        clock,
        verifier,
        verify_attestation,
        item_filter,
    )
    .await
}

/// Continuously accepts incoming channels from `incoming` and processes transfers.
#[allow(clippy::too_many_arguments)]
pub async fn listen_for_transfers<V, F, Fut>(
    incoming: &mut (impl Incoming + ?Sized),
    vfs: &V,
    params: ListenerParams<'_>,
    key_store: &(dyn KeyStore + Sync),
    rng: &(dyn Rng + Sync),
    clock: &(dyn Clock + Sync),
    verifier: &(dyn ContentVerifier + Sync),
    verify_attestation: F,
    item_filter: Option<&(dyn Fn(&OfferItem) -> bool + Send + Sync)>,
) -> Result<(), ListenerError>
where
    V: Vfs,
    F: Fn(AttestationRequest) -> Fut + Clone,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    loop {
        let channel = match incoming.accept().await {
            Ok(c) => c,
            Err(TransportError::Closed) => break Ok(()),
            Err(e) => return Err(ListenerError::Transport(e)),
        };
        let _ = handle_incoming_channel(
            channel.as_ref(),
            vfs,
            params.clone(),
            key_store,
            rng,
            clock,
            verifier,
            verify_attestation.clone(),
            item_filter,
        )
        .await?;
    }
}

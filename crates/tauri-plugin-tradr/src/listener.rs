//! Listener half of the composition root (docs/04-protocol.md, docs/03).
//! Accepts incoming channels, runs the Hello handshake, negotiates transfer offers,
//! derives chunk resumption from disk, and drives file reception.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use tradr_core::{
    BoxFuture, Capabilities, ChunkIndex, Clock, ContentVerifier, DeviceId, DomainTag, Incoming,
    ItemAcceptance, ItemAcceptanceError, ItemResumption, KeyBinding, KeyStore, LinkReply,
    OfferItem, PublicIdentity, REFERENCE_CHUNK_SIZE_BYTES, RecvStream, RelPath, ResumptionError,
    Rng, RootId, SecureChannel, SendStream, TransferAccept, TransferAcceptError, TransferId,
    TransferOffer, TransportError, TrustTier, UnixTime, VersionRange, Vfs, VfsError,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_integrity::BaoVerifier;
use tradr_proto::control::{
    OfferFrameError, decode_transfer_offer_frame, encode_transfer_accept_frame,
};
use tradr_proto::framing::{Frame, FrameDecoder, FrameError};
use tradr_proto::hello::decode_hello_frame;
use tradr_proto::link::{LinkFrameError, decode_link_reply_frame};
use tradr_proto::message_type::{Classification, MessageType, Plane, classify};
use tradr_vfs::{NativeVfs, partial_file_rel_path};

use crate::handshake::{HandshakeError, HandshakeParams, perform_handshake_after_peer_hello};
use crate::link_exchange::{LinkExchangeError, LinkOutcome};
use crate::peer_trust::OwnAttestation;
use crate::transfer::{ReceiveRequest, SessionStreams, TransferSessionError, receive_file};

/// Serves a Control stream that opened with a `LinkReply` (docs/04). A
/// listener with none refuses such a stream, which is what a device with
/// no open invite must do.
pub trait LinkStreamService: Send + Sync {
    /// Runs the exchange over `send`, given the `LinkReply` already read
    /// and decoded, the `DeviceId` the channel authenticated, and the
    /// peer's `max_frame_size`.
    fn serve<'a>(
        &'a self,
        send: &'a mut dyn SendStream,
        reply: LinkReply,
        authenticated_peer: DeviceId,
        max_frame_size: u32,
    ) -> BoxFuture<'a, Result<LinkOutcome, LinkExchangeError>>;
}

/// Configuration parameters for the listener half of the composition root.
#[derive(Clone)]
pub struct ListenerParams<'a> {
    /// The VFS root where incoming and partial files are placed.
    pub root: RootId,
    /// Our public identity (identity_pub and agreement_pub).
    pub our_identity: &'a PublicIdentity,
    /// Where this device's own OIDC provider-signed ID token is read from,
    /// fresh for each connection rather than captured once at startup.
    pub our_attestation_token: Arc<dyn OwnAttestation>,
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
    /// A `LinkReply` frame failed to decode.
    LinkFrame(LinkFrameError),
    /// The link exchange service refused or failed to serve a `LinkReply`.
    LinkExchange(LinkExchangeError),
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
            Self::LinkFrame(e) => write!(f, "link reply framing error: {e}"),
            Self::LinkExchange(e) => write!(f, "link exchange error: {e}"),
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
            Self::LinkFrame(e) => Some(e),
            Self::LinkExchange(e) => Some(e),
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

impl From<LinkFrameError> for ListenerError {
    fn from(err: LinkFrameError) -> Self {
        Self::LinkFrame(err)
    }
}

impl From<LinkExchangeError> for ListenerError {
    fn from(err: LinkExchangeError) -> Self {
        Self::LinkExchange(err)
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
            let derive_res: Result<(), ResumptionError> = (|| {
                let full_chunks = (meta.size_bytes / REFERENCE_CHUNK_SIZE_BYTES).min(total_chunks);
                for idx in 0..full_chunks {
                    let chunk_sz = resumption.chunk_size(ChunkIndex::new(idx))?;
                    resumption.record_piece(ChunkIndex::new(idx), 0, chunk_sz)?;
                    resumption.mark_verified(ChunkIndex::new(idx))?;
                }
                if full_chunks < total_chunks && meta.size_bytes >= item.size() {
                    let last_idx = total_chunks.saturating_sub(1);
                    let chunk_sz = resumption.chunk_size(ChunkIndex::new(last_idx))?;
                    resumption.record_piece(ChunkIndex::new(last_idx), 0, chunk_sz)?;
                    resumption.mark_verified(ChunkIndex::new(last_idx))?;
                }
                Ok(())
            })();
            if let Err(e) = derive_res {
                eprintln!("listener: deriving resumption state failed: {e}");
                resumption = ItemResumption::new(*item.item_id(), item.size());
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
    key_store: &(dyn KeyStore + Sync),
    rng: &(dyn Rng + Sync),
    clock: &(dyn Clock + Sync),
    verifier: &(dyn ContentVerifier + Sync),
    verify_attestation: F,
    item_filter: Option<&(dyn Fn(&OfferItem) -> bool + Send + Sync)>,
    link_service: Option<&dyn LinkStreamService>,
) -> Result<Vec<RelPath>, ListenerError>
where
    V: Vfs,
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    // Read fresh per connection rather than trusting a value captured at
    // startup; a device with no completed sign-in has nothing to put on
    // the wire and must say so rather than send an empty token.
    let our_token = params.our_attestation_token.id_token().ok_or_else(|| {
        ListenerError::Handshake(HandshakeError::Attestation(
            "sign in on this device before accepting a transfer".to_string(),
        ))
    })?;

    let (mut control_send, mut control_recv) = channel
        .accept_bi()
        .await
        .map_err(ListenerError::Transport)?;

    // docs/04: the receiver reads before it writes, and only on this one
    // frame, to decide whether this stream is an ordinary session or the
    // no-session link exchange. Nothing is skipped to reach that decision
    // (DCR-073): an unassigned code here names no shape at all.
    let first_frame = read_frame(control_recv.as_mut(), channel.max_frame_size()).await?;

    match classify(first_frame.type_code(), Plane::Control) {
        Classification::Known(MessageType::Hello) => {
            let peer_hello = decode_hello_frame(&first_frame)
                .map_err(HandshakeError::Proto)
                .map_err(ListenerError::Handshake)?;

            let handshake_params = HandshakeParams {
                authenticated_peer: channel.peer(),
                our_channel_max_frame_size: channel.max_frame_size(),
                our_identity: params.our_identity,
                our_attestation_token: our_token,
                our_key_binding: params.our_key_binding,
                our_versions: params.our_versions,
                our_capabilities: params.our_capabilities,
            };

            let session = perform_handshake_after_peer_hello(
                control_send.as_mut(),
                control_recv.as_mut(),
                peer_hello,
                handshake_params,
                key_store,
                rng,
                clock,
                verify_attestation,
            )
            .await
            .map_err(ListenerError::Handshake)?;

            tokio::select! {
                offer_res = read_transfer_offer(control_recv.as_mut(), channel.max_frame_size()) => {
                    let offer = offer_res?;

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

                    if let Err(e) = control_send.finish().await {
                        eprintln!("listener: closing the control stream failed: {e}");
                    }

                    let mut dummy = [0u8; 1];
                    if let Err(e) = control_recv.read(&mut dummy).await {
                        eprintln!("listener: waiting for control stream close failed: {e}");
                    }

                    Ok(placed_paths)
                }
                stream_res = channel.accept_bi() => {
                    if let Ok((mut browse_send, mut browse_recv)) = stream_res {
                        let codec = tradr_proto::browse::ProtoBrowseCodec::new(channel.max_frame_size());
                        if let Err(e) = tradr_core::handle_browse_stream(
                            browse_recv.as_mut(),
                            browse_send.as_mut(),
                            &codec,
                            vfs,
                            params.root,
                            channel.max_frame_size(),
                        )
                        .await
                        {
                            eprintln!("listener: handle browse stream failed: {e}");
                        }
                    }
                    Ok(Vec::new())
                }
            }
        }
        Classification::Known(MessageType::LinkReply) => {
            let reply = decode_link_reply_frame(&first_frame).map_err(ListenerError::LinkFrame)?;
            let service = link_service.ok_or_else(|| {
                ListenerError::ProtocolViolation("no invite is open on this device".to_string())
            })?;
            service
                .serve(
                    control_send.as_mut(),
                    reply,
                    channel.peer(),
                    channel.max_frame_size(),
                )
                .await
                .map_err(ListenerError::LinkExchange)?;
            // docs/04: no transfer, no browse and no offer read is
            // reachable from a link stream, and it ends when serve returns.
            Ok(Vec::new())
        }
        other => Err(ListenerError::ProtocolViolation(format!(
            "unexpected first frame on control stream: {other}"
        ))),
    }
}

/// Accepts the next channel from `incoming` and handles the transfer session.
#[allow(clippy::too_many_arguments)]
pub async fn accept_and_handle_transfer<V, F, Fut>(
    incoming: &mut (impl Incoming + ?Sized),
    vfs: &V,
    params: ListenerParams<'_>,
    key_store: &(dyn KeyStore + Sync),
    rng: &(dyn Rng + Sync),
    clock: &(dyn Clock + Sync),
    verifier: &(dyn ContentVerifier + Sync),
    verify_attestation: F,
    item_filter: Option<&(dyn Fn(&OfferItem) -> bool + Send + Sync)>,
    link_service: Option<&dyn LinkStreamService>,
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
        link_service,
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
    link_service: Option<&dyn LinkStreamService>,
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
        match handle_incoming_channel(
            channel.as_ref(),
            vfs,
            params.clone(),
            key_store,
            rng,
            clock,
            verifier,
            verify_attestation.clone(),
            item_filter,
            link_service,
        )
        .await
        {
            Ok(_) => {}
            Err(e) => eprintln!("transfer failed: {e}"),
        }
    }
}

/// Runs the listener loop for incoming transfers on an `Incoming` stream.
#[allow(clippy::too_many_arguments)]
pub async fn run_listener<F, Fut>(
    mut incoming: Box<dyn Incoming>,
    vfs: Arc<NativeVfs>,
    key_store: Arc<dyn KeyStore>,
    identity: PublicIdentity,
    our_attestation: Arc<dyn OwnAttestation>,
    root: RootId,
    verify_attestation: F,
    link_service: Option<Arc<dyn LinkStreamService>>,
) -> Result<(), ListenerError>
where
    F: Fn(AttestationRequest) -> Fut + Clone,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let clock = SystemClock;
    let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
    let keybind_sig = key_store
        .sign(DomainTag::KeyBind, identity.agreement_pub().as_bytes())
        .map_err(HandshakeError::KeyStore)?;
    let key_binding = KeyBinding::new(identity.agreement_pub().clone(), keybind_sig, not_after);

    let versions = VersionRange::new(1, 1)
        .map_err(|_| ListenerError::ProtocolViolation("invalid version range".to_string()))?;

    let params = ListenerParams {
        root,
        our_identity: &identity,
        our_attestation_token: our_attestation,
        our_key_binding: key_binding,
        our_versions: versions,
        our_capabilities: Capabilities::DIRECT_QUIC,
    };

    listen_for_transfers(
        incoming.as_mut(),
        vfs.as_ref(),
        params,
        key_store.as_ref(),
        &OsRng,
        &SystemClock,
        &BaoVerifier,
        verify_attestation,
        None,
        link_service.as_deref(),
    )
    .await
}

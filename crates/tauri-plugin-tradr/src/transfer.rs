//! End-to-end file transfer session engine (docs/04-protocol.md, "The Data plane").
//! Drives chunk requests, stream parsing, partial-file writes, and atomic placement.

use std::fmt;

use tradr_core::{
    ChunkDataHeader, ChunkIndex, ChunkRequest, ContentHash, ContentVerifier, ItemComplete, ItemId,
    ItemResumption, REFERENCE_CHUNK_SIZE_BYTES, RecvStream, RelPath, RootId, SendStream,
    TransferId, TransportError, Vfs, VfsError,
};
use tradr_integrity::{outboard, slice};
use tradr_proto::data::{
    TransferFrameError, decode_chunk_data_header_frame, decode_chunk_request_frame,
    decode_chunk_rerequest_frame, decode_item_complete_frame, encode_chunk_data_header_frame,
    encode_chunk_request_frame, encode_item_complete_frame,
};
use tradr_proto::framing::{Frame, FrameDecoder, FrameError};
use tradr_proto::message_type::{Classification, MessageType, Plane, Refusal, classify};
use tradr_vfs::resolve_collision;
use tradr_vfs::sanitization::{partial_file_rel_path, sanitize_destination_path};

/// Errors occurring during an end-to-end file transfer session.
#[derive(Debug)]
pub enum TransferSessionError {
    /// Transport-level failure during stream read or write.
    Transport(TransportError),
    /// Framing, encoding, or decoding failure.
    Proto(TransferFrameError),
    /// Filesystem error while reading, writing, or moving files.
    Vfs(VfsError),
    /// The stream closed unexpectedly before the transfer completed.
    StreamClosed,
    /// The peer sent an unexpected frame or invalid payload.
    ProtocolViolation(String),
    /// Content hash verification failed.
    VerificationFailed,
}

impl fmt::Display for TransferSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Proto(e) => write!(f, "proto error: {e}"),
            Self::Vfs(e) => write!(f, "vfs error: {e}"),
            Self::StreamClosed => write!(f, "stream closed unexpectedly"),
            Self::ProtocolViolation(msg) => write!(f, "protocol violation: {msg}"),
            Self::VerificationFailed => write!(f, "verification failed"),
        }
    }
}

impl std::error::Error for TransferSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Proto(e) => Some(e),
            Self::Vfs(e) => Some(e),
            Self::StreamClosed | Self::ProtocolViolation(_) | Self::VerificationFailed => None,
        }
    }
}

impl From<TransportError> for TransferSessionError {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::Closed => Self::StreamClosed,
            other => Self::Transport(other),
        }
    }
}

impl From<TransferFrameError> for TransferSessionError {
    fn from(err: TransferFrameError) -> Self {
        Self::Proto(err)
    }
}

impl From<VfsError> for TransferSessionError {
    fn from(err: VfsError) -> Self {
        Self::Vfs(err)
    }
}

// Reading exact byte count prevents unaligned stream offsets on subsequent frames.
async fn read_exact(
    recv: &mut (impl RecvStream + ?Sized),
    mut buf: &mut [u8],
) -> Result<(), TransferSessionError> {
    while !buf.is_empty() {
        let n = recv.read(buf).await.map_err(|e| match e {
            TransportError::Closed => TransferSessionError::StreamClosed,
            other => TransferSessionError::Transport(other),
        })?;
        if n == 0 {
            return Err(TransferSessionError::StreamClosed);
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

// Length prefix is decoded before payload to enforce frame size boundaries.
async fn read_frame(
    recv: &mut (impl RecvStream + ?Sized),
    max_frame_size: u32,
) -> Result<Frame, TransferSessionError> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    if announced == 0 {
        return Err(TransferSessionError::Proto(TransferFrameError::Framing(
            FrameError::Empty,
        )));
    }
    if announced > max_frame_size {
        return Err(TransferSessionError::Proto(TransferFrameError::Framing(
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
        .map_err(TransferFrameError::Framing)
        .map_err(TransferSessionError::Proto)?
        .ok_or_else(|| {
            TransferSessionError::ProtocolViolation("incomplete frame in buffer".to_string())
        })?;
    Ok(frame)
}

// Sanitizes destination paths and resolves collisions using VFS.
async fn resolve_destination_path(
    vfs: &impl Vfs,
    root: RootId,
    dest_rel_path: &RelPath,
) -> Result<RelPath, TransferSessionError> {
    let sanitized = sanitize_destination_path(dest_rel_path.as_str())
        .map_err(|e| TransferSessionError::ProtocolViolation(e.to_string()))?;
    resolve_collision(vfs, root, &sanitized)
        .await
        .map_err(TransferSessionError::Vfs)
}

// Removes abandoned partial files to prevent unverified artifacts remaining on disk.
async fn cleanup_partial(
    vfs: &impl Vfs,
    root: RootId,
    partial_file_rel: &RelPath,
    partial_dir: &RelPath,
) -> Result<(), VfsError> {
    match vfs.remove(root, partial_file_rel).await {
        Ok(()) | Err(VfsError::NotFound) => {}
        Err(e) => return Err(e),
    }
    match vfs.remove(root, partial_dir).await {
        Ok(()) | Err(VfsError::NotFound) | Err(VfsError::WrongKind) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

struct SendSession<'a> {
    file_content: &'a [u8],
    outboard_data: &'a [u8],
    total_bytes: u64,
    transfer_id: TransferId,
    item_id: ItemId,
    max_frame_size: u32,
}

async fn send_chunk_pieces(
    session: &SendSession<'_>,
    chunk_indices: impl Iterator<Item = u64>,
    send: &mut (impl SendStream + ?Sized),
) -> Result<(), TransferSessionError> {
    for c in chunk_indices {
        let chunk_offset = c.saturating_mul(REFERENCE_CHUNK_SIZE_BYTES);
        if chunk_offset >= session.total_bytes {
            continue;
        }
        let remaining = session.total_bytes.saturating_sub(chunk_offset);
        let chunk_len = remaining.min(REFERENCE_CHUNK_SIZE_BYTES);

        let piece_slice = slice(
            session.file_content,
            session.outboard_data,
            chunk_offset,
            chunk_len,
        )
        .map_err(|e| TransferSessionError::ProtocolViolation(e.to_string()))?;

        let is_last = (chunk_offset + chunk_len) >= session.total_bytes;
        let header = ChunkDataHeader::new(
            session.transfer_id,
            session.item_id,
            ChunkIndex::new(c),
            piece_slice.len() as u32,
            is_last,
            0,
        )
        .map_err(|e| TransferSessionError::ProtocolViolation(e.to_string()))?;

        let header_frame = encode_chunk_data_header_frame(&header, session.max_frame_size)
            .map_err(TransferSessionError::Proto)?;
        send.write_all(&header_frame)
            .await
            .map_err(TransferSessionError::from)?;
        send.write_all(&piece_slice)
            .await
            .map_err(TransferSessionError::from)?;
    }
    Ok(())
}

/// Drives the sending side of a file transfer session over connected streams.
#[allow(clippy::too_many_arguments)]
pub async fn send_file(
    vfs: &impl Vfs,
    root: RootId,
    rel_path: &RelPath,
    send: &mut impl SendStream,
    recv: &mut impl RecvStream,
    transfer_id: TransferId,
    item_id: ItemId,
    max_frame_size: u32,
) -> Result<bool, TransferSessionError> {
    let read_handle = vfs.open_read(root, rel_path).await?;
    let meta = vfs.stat(root, rel_path).await?;
    let total_bytes = meta.size_bytes;

    let mut file_content = vec![0u8; total_bytes as usize];
    let mut read_bytes = 0;
    while read_bytes < file_content.len() {
        let n = read_handle
            .read_at(read_bytes as u64, &mut file_content[read_bytes..])
            .await
            .map_err(TransferSessionError::Vfs)?;
        if n == 0 {
            return Err(TransferSessionError::ProtocolViolation(
                "unexpected EOF while reading local file".to_string(),
            ));
        }
        read_bytes += n;
    }

    let (outboard_data, _) = outboard(&file_content);
    let session = SendSession {
        file_content: &file_content,
        outboard_data: &outboard_data,
        total_bytes,
        transfer_id,
        item_id,
        max_frame_size,
    };

    loop {
        let frame = read_frame(recv, max_frame_size).await?;
        match classify(frame.type_code(), Plane::Data) {
            Classification::Known(MessageType::ChunkRequest) => {
                let req =
                    decode_chunk_request_frame(&frame).map_err(TransferSessionError::Proto)?;
                let from = req.from_chunk().value();
                let count = req.count() as u64;
                send_chunk_pieces(&session, from..(from + count), send).await?;
            }
            Classification::Known(MessageType::ChunkRerequest) => {
                let req =
                    decode_chunk_rerequest_frame(&frame).map_err(TransferSessionError::Proto)?;
                send_chunk_pieces(&session, req.chunks().iter().map(|idx| idx.value()), send)
                    .await?;
            }
            Classification::Known(MessageType::FlowControl) => {}
            Classification::Ignorable => {}
            Classification::Refused(Refusal::WrongPlane { .. })
                if frame.type_code() == MessageType::ItemComplete.code() =>
            {
                let item_complete =
                    decode_item_complete_frame(&frame).map_err(TransferSessionError::Proto)?;
                if item_complete.is_verified() {
                    return Ok(true);
                } else {
                    return Err(TransferSessionError::VerificationFailed);
                }
            }
            Classification::Refused(e) => {
                return Err(TransferSessionError::ProtocolViolation(e.to_string()));
            }
            Classification::Known(other) => {
                return Err(TransferSessionError::ProtocolViolation(format!(
                    "unexpected message on data stream: {other:?}"
                )));
            }
        }
    }
}

struct ReceiveSession<'a, V: Vfs> {
    vfs: &'a V,
    root: RootId,
    dest_rel_path: &'a RelPath,
    total_bytes: u64,
    content_hash: &'a ContentHash,
    verifier: &'a dyn ContentVerifier,
    transfer_id: TransferId,
    item_id: ItemId,
    max_frame_size: u32,
    partial_file_rel: &'a RelPath,
}

// Processes incoming chunk streams and verifies cryptographic integrity before disk placement.
async fn receive_file_inner<V: Vfs>(
    session: &ReceiveSession<'_, V>,
    send: &mut impl SendStream,
    recv: &mut impl RecvStream,
) -> Result<RelPath, TransferSessionError> {
    let mut write_handle = session
        .vfs
        .open_write(session.root, session.partial_file_rel)
        .await?;
    let mut resumption = ItemResumption::new(session.item_id, session.total_bytes);
    let total_chunks = resumption.total_chunks();

    while !resumption.is_item_complete() {
        let (from_chunk, count) = match resumption.next_chunk_request(64) {
            Some(req) => req,
            None => break,
        };

        let req = ChunkRequest::new(session.transfer_id, session.item_id, from_chunk, count);
        let req_frame = encode_chunk_request_frame(&req, session.max_frame_size)
            .map_err(TransferSessionError::Proto)?;
        send.write_all(&req_frame)
            .await
            .map_err(TransferSessionError::from)?;

        for _ in 0..count {
            let frame = read_frame(recv, session.max_frame_size).await?;
            if frame.type_code() != MessageType::ChunkData.code() {
                return Err(TransferSessionError::ProtocolViolation(format!(
                    "expected ChunkData frame, got type 0x{:02x}",
                    frame.type_code()
                )));
            }

            let header =
                decode_chunk_data_header_frame(&frame).map_err(TransferSessionError::Proto)?;

            if header.transfer_id() != session.transfer_id {
                return Err(TransferSessionError::ProtocolViolation(format!(
                    "transfer_id mismatch: expected {}, got {}",
                    session.transfer_id,
                    header.transfer_id()
                )));
            }

            if header.item_id() != &session.item_id {
                return Err(TransferSessionError::ProtocolViolation(format!(
                    "item_id mismatch: expected {}, got {}",
                    session.item_id,
                    header.item_id()
                )));
            }

            // Bounding payload length before buffer allocation prevents memory exhaustion from hostile peers.
            let payload_len = header.payload_len();
            if payload_len > session.max_frame_size {
                return Err(TransferSessionError::ProtocolViolation(format!(
                    "payload_len {payload_len} exceeds max_frame_size {}",
                    session.max_frame_size
                )));
            }

            let mut slice_payload = vec![0u8; payload_len as usize];
            read_exact(recv, &mut slice_payload).await?;

            // Bounding chunk index against total chunks prevents sparse file expansion from huge indices.
            if header.chunk_index().value() >= total_chunks {
                return Err(TransferSessionError::ProtocolViolation(format!(
                    "chunk index {} is out of bounds for item with {total_chunks} chunks",
                    header.chunk_index().value()
                )));
            }

            let offset = header.chunk_index().value() * REFERENCE_CHUNK_SIZE_BYTES
                + header.offset_in_chunk() as u64;

            if offset >= session.total_bytes {
                return Err(TransferSessionError::ProtocolViolation(
                    "piece offset is beyond total item length".to_string(),
                ));
            }

            // Computing expected content length locally prevents trusting peer size claims.
            let remaining_item = session.total_bytes.saturating_sub(offset);
            let remaining_chunk =
                REFERENCE_CHUNK_SIZE_BYTES.saturating_sub(header.offset_in_chunk() as u64);
            let content_len = remaining_item.min(remaining_chunk);

            // Verifying before placement prevents unverified bytes from reaching durable storage.
            let verified_bytes = session
                .verifier
                .verify(session.content_hash, offset, content_len, &slice_payload)
                .map_err(|_| TransferSessionError::VerificationFailed)?;

            write_handle
                .write_at(offset, &verified_bytes)
                .await
                .map_err(TransferSessionError::Vfs)?;
            write_handle
                .sync()
                .await
                .map_err(TransferSessionError::Vfs)?;

            // Resumption tracking is updated only after cryptographic proof succeeds.
            let is_chunk_complete = resumption
                .record_piece(
                    header.chunk_index(),
                    header.offset_in_chunk(),
                    verified_bytes.len() as u32,
                )
                .map_err(|e| TransferSessionError::ProtocolViolation(e.to_string()))?;

            if is_chunk_complete {
                resumption
                    .mark_verified(header.chunk_index())
                    .map_err(|e| TransferSessionError::ProtocolViolation(e.to_string()))?;
            }

            if resumption.is_item_complete() {
                break;
            }
        }
    }

    drop(write_handle);

    let is_verified = resumption.is_item_complete();
    if !is_verified {
        let item_complete = ItemComplete::new(session.transfer_id, session.item_id, false, None);
        let complete_bytes = encode_item_complete_frame(&item_complete, session.max_frame_size)
            .map_err(TransferSessionError::Proto)?;
        send.write_all(&complete_bytes)
            .await
            .map_err(TransferSessionError::from)?;
        return Err(TransferSessionError::VerificationFailed);
    }

    let final_path =
        resolve_destination_path(session.vfs, session.root, session.dest_rel_path).await?;
    session
        .vfs
        .rename(session.root, session.partial_file_rel, &final_path)
        .await?;

    let item_complete = ItemComplete::new(
        session.transfer_id,
        session.item_id,
        true,
        Some(final_path.clone()),
    );
    let complete_bytes = encode_item_complete_frame(&item_complete, session.max_frame_size)
        .map_err(TransferSessionError::Proto)?;
    send.write_all(&complete_bytes)
        .await
        .map_err(TransferSessionError::from)?;

    Ok(final_path)
}

/// Drives the receiving side of a file transfer session over connected streams.
#[allow(clippy::too_many_arguments)]
pub async fn receive_file(
    vfs: &impl Vfs,
    root: RootId,
    dest_rel_path: &RelPath,
    total_bytes: u64,
    content_hash: &ContentHash,
    verifier: &dyn ContentVerifier,
    send: &mut impl SendStream,
    recv: &mut impl RecvStream,
    transfer_id: TransferId,
    item_id: ItemId,
    max_frame_size: u32,
) -> Result<RelPath, TransferSessionError> {
    let partial_dir = RelPath::new(&format!(".tradr-partial/{transfer_id}"))
        .map_err(|e| TransferSessionError::ProtocolViolation(e.to_string()))?;
    vfs.create_dir(root, &partial_dir).await?;

    let partial_file_rel = partial_file_rel_path(transfer_id, &item_id);

    let session = ReceiveSession {
        vfs,
        root,
        dest_rel_path,
        total_bytes,
        content_hash,
        verifier,
        transfer_id,
        item_id,
        max_frame_size,
        partial_file_rel: &partial_file_rel,
    };

    let res = receive_file_inner(&session, send, recv).await;

    if res.is_err()
        && let Err(clean_err) = cleanup_partial(vfs, root, &partial_file_rel, &partial_dir).await
    {
        match clean_err {
            VfsError::NotFound | VfsError::WrongKind => {}
            other => return Err(TransferSessionError::Vfs(other)),
        }
    }

    res
}

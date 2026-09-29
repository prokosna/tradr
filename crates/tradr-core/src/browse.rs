//! Browse plane handler and domain types.
//! Maps `browse.proto` messages to `Vfs` calls.

use crate::{
    BoxFuture, ContentHash, EntryKind, RelPath, RelPathError, RootId, ShareId, ShareIdError, Vfs,
    VfsError,
    channel::{RecvStream, SendStream},
};

// Types corresponding to browse messages.

/// Request to list a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListDir {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
    /// Pagination cursor.
    pub cursor: String,
    /// Max entries to return.
    pub limit: u32,
    /// Whether to compute hashes.
    pub with_hash: bool,
}

/// Response containing a directory listing page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirListing {
    /// Listed entries.
    pub entries: Vec<crate::vfs::DirEntry>,
    /// Cursor for the next page.
    pub next_cursor: String,
    /// Total estimated entries.
    pub total_estimate: u64,
}

/// Request to stat a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
}

/// Response containing stat results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResult {
    /// Stat entry.
    pub entry: crate::vfs::DirEntry,
}

/// Request to begin a file read over a Data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFile {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
    /// Read offset.
    pub offset: u64,
    /// Read length.
    pub length: u64,
}

/// Initial response to a `ReadFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFileBegin {
    /// Total file size.
    pub total_size: u64,
    /// BLAKE3 hash.
    pub content_hash: ContentHash,
    /// Chunk size for data stream.
    pub chunk_size: u32,
}

/// Request to write a file over a Data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFile {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
    /// Total size.
    pub size: u64,
    /// BLAKE3 hash.
    pub content_hash: ContentHash,
    /// Write mode.
    pub mode: WriteMode,
}

/// Mode for `WriteFile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Create new.
    CreateNew,
    /// Overwrite.
    Overwrite,
    /// Rename if exists.
    RenameIfExists,
}

/// Request to create a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mkdir {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
    /// Create parents.
    pub parents: bool,
}

/// Request to delete a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
    /// Recursive delete.
    pub recursive: bool,
}

/// Request to rename a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rename {
    /// Share ID.
    pub share_id: ShareId,
    /// From path.
    pub from: RelPath,
    /// To path.
    pub to: RelPath,
}

/// Acknowledgement of a modifying operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// Request ID.
    pub request_id: String,
}

/// Category explaining why a browse operation was refused by the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// Peer lacks access to the requested share root.
    NoAccess,
    /// Requested path was not found on the peer.
    NotFound,
    /// Target path already exists where creation was required.
    AlreadyExists,
    /// Entry kind is incompatible with the operation or directory is not empty.
    WrongKind,
    /// Operation violates boundary containment, denylist, or filesystem policy.
    NotAllowed,
    /// Unspecified error or internal failure on the serving side.
    Failed,
}

/// Refusal response sent when a browse request cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Request identifier matching the incoming browse request.
    pub request_id: String,
    /// Reason explaining why the request was refused.
    pub reason: RefusalReason,
}

/// Request to watch for file system changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    /// Share ID.
    pub share_id: ShareId,
    /// Relative path.
    pub path: RelPath,
    /// Watch recursively.
    pub recursive: bool,
    /// Cancel watch.
    pub cancel: bool,
}

/// A batch of file system changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    /// Share ID.
    pub share_id: ShareId,
    /// List of changes.
    pub changes: Vec<FsChange>,
}

/// A single file system change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsChange {
    /// Change kind.
    pub kind: FsChangeKind,
    /// Target path.
    pub path: RelPath,
    /// Old path for rename.
    pub old_path: Option<RelPath>,
}

/// Kinds of file system changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsChangeKind {
    /// File created.
    Created,
    /// File modified.
    Modified,
    /// File deleted.
    Deleted,
    /// File renamed.
    Renamed,
    /// Watcher overflowed.
    Overflow,
}

/// Errors when validating a browse message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseDomainError {
    /// Share ID is invalid.
    InvalidShareId(ShareIdError),
    /// Path is invalid.
    InvalidRelPath(RelPathError),
    /// Content hash is invalid length.
    InvalidContentHash(usize),
    /// Write mode is invalid.
    InvalidWriteMode,
    /// Fs change kind is invalid.
    InvalidFsChangeKind,
    /// A codec encoding or decoding error.
    CodecError(String),
    /// An unsupported message was received.
    UnsupportedMessage,
}

impl std::fmt::Display for BrowseDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidShareId(e) => write!(f, "invalid share_id: {}", e),
            Self::InvalidRelPath(e) => write!(f, "invalid path: {}", e),
            Self::InvalidContentHash(len) => write!(f, "invalid content hash length: {}", len),
            Self::InvalidWriteMode => write!(f, "invalid write mode"),
            Self::InvalidFsChangeKind => write!(f, "invalid fs change kind"),
            Self::CodecError(s) => write!(f, "codec error: {}", s),
            Self::UnsupportedMessage => write!(f, "unsupported message"),
        }
    }
}
impl std::error::Error for BrowseDomainError {}
/// Any request or response in the Browse plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseMessage {
    /// ListDir request.
    ListDir(ListDir),
    /// DirListing response.
    DirListing(DirListing),
    /// Stat request.
    Stat(Stat),
    /// StatResult response.
    StatResult(StatResult),
    /// ReadFile request.
    ReadFile(ReadFile),
    /// ReadFileBegin response.
    ReadFileBegin(ReadFileBegin),
    /// WriteFile request.
    WriteFile(WriteFile),
    /// Mkdir request.
    Mkdir(Mkdir),
    /// Delete request.
    Delete(Delete),
    /// Rename request.
    Rename(Rename),
    /// Ack response.
    Ack(Ack),
    /// Refused response.
    Refused(Refused),
    /// Watch request.
    Watch(Watch),
    /// FsEvent response.
    FsEvent(FsEvent),
}

/// Allows `tradr-core` to decode framed wire bytes into domain types without taking
/// a cyclic dependency on `tradr-proto` where the protobuf types and framing live.
pub trait BrowseCodec: Send + Sync {
    /// Extracts the next complete frame from `buf` and decodes it.
    /// Returns `Ok(Some((message, bytes_consumed)))` if a complete frame was read,
    /// `Ok(None)` if more bytes are needed, or an error if decoding fails.
    fn decode_frame(
        &self,
        buf: &[u8],
        max_frame_size: u32,
    ) -> Result<Option<(BrowseMessage, usize)>, BrowseDomainError>;

    /// Encodes a domain message into a framed byte vector.
    fn encode_frame(
        &self,
        msg: &BrowseMessage,
        max_frame_size: u32,
    ) -> Result<Vec<u8>, BrowseDomainError>;
}

/// Supplies staging paths and collision-free names for browse uploads.
pub trait UploadPaths: Send + Sync {
    /// Returns a fresh (directory, file) pair under the partial root.
    fn staging(&self) -> Result<(RelPath, RelPath), VfsError>;

    /// Resolves a collision-free target path according to the receive collision rule.
    fn free_name<'a>(
        &'a self,
        vfs: &'a dyn Vfs,
        root: RootId,
        wanted: &'a RelPath,
    ) -> BoxFuture<'a, Result<RelPath, VfsError>>;
}

struct BrowseContext<'a> {
    codec: &'a dyn BrowseCodec,
    vfs: &'a dyn Vfs,
    root: RootId,
    max_frame_size: u32,
    uploads: &'a dyn UploadPaths,
}

struct StreamBuffer {
    buf: Vec<u8>,
    pos: usize,
}

struct StagedUpload<'a> {
    target_path: &'a RelPath,
    staging_dir: &'a RelPath,
    staging_file: &'a RelPath,
    size: u64,
}

#[derive(Debug)]
enum BrowseFailure {
    Refused(RefusalReason),
    Stream(crate::channel::TransportError),
}

impl From<crate::channel::TransportError> for BrowseFailure {
    fn from(err: crate::channel::TransportError) -> Self {
        Self::Stream(err)
    }
}

fn refusal_for(err: VfsError) -> RefusalReason {
    match err {
        VfsError::NotFound => RefusalReason::NotFound,
        VfsError::OutsideRoot
        | VfsError::DenyListed
        | VfsError::UnsupportedEntry
        | VfsError::ReadOnly => RefusalReason::NotAllowed,
        VfsError::WrongKind => RefusalReason::WrongKind,
        VfsError::Io(_) => RefusalReason::Failed,
    }
}

/// The Browse plane handler, reading requests from `recv` and writing responses to `send`.
pub async fn handle_browse_stream<'a>(
    recv: &'a mut dyn RecvStream,
    send: &'a mut dyn SendStream,
    codec: &'a dyn BrowseCodec,
    vfs: &'a dyn Vfs,
    root: crate::RootId,
    max_frame_size: u32,
    uploads: &'a dyn UploadPaths,
) -> Result<(), crate::channel::TransportError> {
    let ctx = BrowseContext {
        codec,
        vfs,
        root,
        max_frame_size,
        uploads,
    };
    let mut buffer = StreamBuffer {
        buf: vec![0u8; max_frame_size as usize * 2],
        pos: 0,
    };

    loop {
        // Read into buffer if we don't have enough to decode
        let read_len = recv.read(&mut buffer.buf[buffer.pos..]).await?;
        if read_len == 0 {
            break; // EOF
        }
        buffer.pos += read_len;

        // Try decoding
        while buffer.pos > 0 {
            match ctx
                .codec
                .decode_frame(&buffer.buf[..buffer.pos], ctx.max_frame_size)
            {
                Ok(Some((msg, consumed))) => {
                    buffer.buf.copy_within(consumed..buffer.pos, 0);
                    buffer.pos -= consumed;
                    if let Err(failure) = handle_message(msg, recv, send, &ctx, &mut buffer).await {
                        match failure {
                            BrowseFailure::Refused(reason) => {
                                let resp = BrowseMessage::Refused(Refused {
                                    request_id: String::new(),
                                    reason,
                                });
                                let encoded = ctx
                                    .codec
                                    .encode_frame(&resp, ctx.max_frame_size)
                                    .map_err(|_| {
                                        crate::channel::TransportError::Io(
                                            std::io::ErrorKind::InvalidData,
                                        )
                                    })?;
                                send.write_all(&encoded).await?;
                                send.finish().await?;
                                return Ok(());
                            }
                            BrowseFailure::Stream(e) => return Err(e),
                        }
                    }
                }
                Ok(None) => break, // Need more data
                Err(_) => {
                    // Invalid message or framing error, close connection.
                    return Err(crate::channel::TransportError::Closed);
                }
            }
        }
    }
    Ok(())
}

async fn send_ack(send: &mut dyn SendStream, ctx: &BrowseContext<'_>) -> Result<(), BrowseFailure> {
    let resp = BrowseMessage::Ack(Ack {
        request_id: String::new(),
    });
    let encoded = ctx
        .codec
        .encode_frame(&resp, ctx.max_frame_size)
        .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData))?;
    send.write_all(&encoded).await?;
    Ok(())
}

fn remove_dir_recursive<'a>(
    vfs: &'a dyn Vfs,
    root: RootId,
    path: &'a RelPath,
) -> BoxFuture<'a, Result<(), VfsError>> {
    Box::pin(async move {
        let entries = vfs.list(root, path).await?;
        for entry in entries {
            let child_str = if path.as_str().is_empty() {
                entry.name
            } else {
                format!("{}/{}", path.as_str(), entry.name)
            };
            let child_rel = RelPath::new(&child_str).map_err(|_| VfsError::OutsideRoot)?;
            match entry.kind {
                EntryKind::Directory => {
                    remove_dir_recursive(vfs, root, &child_rel).await?;
                }
                EntryKind::File => {
                    vfs.remove(root, &child_rel).await?;
                }
            }
        }
        vfs.remove(root, path).await?;
        Ok(())
    })
}

async fn handle_write_file(
    req: WriteFile,
    recv: &mut dyn RecvStream,
    send: &mut dyn SendStream,
    ctx: &BrowseContext<'_>,
    buffer: &mut StreamBuffer,
) -> Result<(), BrowseFailure> {
    let target_path = match req.mode {
        WriteMode::CreateNew => match ctx.vfs.stat(ctx.root, &req.path).await {
            Ok(_) => {
                return Err(BrowseFailure::Refused(RefusalReason::AlreadyExists));
            }
            Err(VfsError::NotFound) => req.path,
            Err(e) => return Err(BrowseFailure::Refused(refusal_for(e))),
        },
        WriteMode::Overwrite => match ctx.vfs.stat(ctx.root, &req.path).await {
            Ok(meta) => {
                if meta.kind == EntryKind::Directory {
                    return Err(BrowseFailure::Refused(RefusalReason::WrongKind));
                }
                req.path
            }
            Err(VfsError::NotFound) => req.path,
            Err(e) => return Err(BrowseFailure::Refused(refusal_for(e))),
        },
        WriteMode::RenameIfExists => ctx
            .uploads
            .free_name(ctx.vfs, ctx.root, &req.path)
            .await
            .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?,
    };

    let (staging_dir, staging_file) = ctx
        .uploads
        .staging()
        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
    ctx.vfs
        .create_dir(ctx.root, &staging_dir)
        .await
        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;

    let staged = StagedUpload {
        target_path: &target_path,
        staging_dir: &staging_dir,
        staging_file: &staging_file,
        size: req.size,
    };

    let write_res = write_staged_content(&staged, recv, send, ctx, buffer).await;

    match write_res {
        Ok(()) => Ok(()),
        Err(err) => {
            let cleanup_res = async {
                match ctx.vfs.remove(ctx.root, &staging_file).await {
                    Ok(()) | Err(VfsError::NotFound) => {}
                    Err(e) => return Err(e),
                }
                match ctx.vfs.remove(ctx.root, &staging_dir).await {
                    Ok(()) | Err(VfsError::NotFound) => {}
                    Err(e) => return Err(e),
                }
                Ok(())
            }
            .await;

            match cleanup_res {
                Ok(()) => Err(err),
                Err(clean_err) => Err(BrowseFailure::Refused(refusal_for(clean_err))),
            }
        }
    }
}

async fn write_staged_content(
    staged: &StagedUpload<'_>,
    recv: &mut dyn RecvStream,
    send: &mut dyn SendStream,
    ctx: &BrowseContext<'_>,
    buffer: &mut StreamBuffer,
) -> Result<(), BrowseFailure> {
    let mut writer = ctx
        .vfs
        .open_write(ctx.root, staged.staging_file)
        .await
        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;

    let mut written = 0u64;
    let from_buf = (buffer.pos as u64).min(staged.size) as usize;
    if from_buf > 0 {
        writer
            .write_at(written, &buffer.buf[..from_buf])
            .await
            .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
        written += from_buf as u64;
        buffer.buf.copy_within(from_buf..buffer.pos, 0);
        buffer.pos -= from_buf;
    }

    if written < staged.size {
        let mut chunk = vec![0u8; 64 * 1024];
        while written < staged.size {
            let needed = ((staged.size - written).min(chunk.len() as u64)) as usize;
            let n = recv.read(&mut chunk[..needed]).await?;
            if n == 0 {
                return Err(BrowseFailure::Stream(
                    crate::channel::TransportError::Closed,
                ));
            }
            writer
                .write_at(written, &chunk[..n])
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
            written += n as u64;
        }
    }

    writer
        .sync()
        .await
        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
    drop(writer);

    ctx.vfs
        .rename(ctx.root, staged.staging_file, staged.target_path)
        .await
        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;

    ctx.vfs
        .remove(ctx.root, staged.staging_dir)
        .await
        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;

    send_ack(send, ctx).await
}

async fn handle_message(
    msg: BrowseMessage,
    recv: &mut dyn RecvStream,
    send: &mut dyn SendStream,
    ctx: &BrowseContext<'_>,
    buffer: &mut StreamBuffer,
) -> Result<(), BrowseFailure> {
    match msg {
        BrowseMessage::ListDir(req) => {
            let entries = ctx
                .vfs
                .list(ctx.root, &req.path)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;

            let mut sorted = entries;
            sorted.sort_by(|a, b| a.name.cmp(&b.name));

            let start_idx = if req.cursor.is_empty() {
                0
            } else {
                sorted
                    .iter()
                    .position(|e| e.name == req.cursor)
                    .map(|i| i + 1)
                    .unwrap_or(0)
            };

            let limit = if req.limit == 0 {
                500
            } else {
                req.limit as usize
            };
            let mut end_idx = start_idx + limit;
            let has_more = end_idx < sorted.len();
            if end_idx > sorted.len() {
                end_idx = sorted.len();
            }

            let page = sorted[start_idx..end_idx].to_vec();
            let next_cursor = if has_more {
                page.last().map(|e| e.name.clone()).unwrap_or_default()
            } else {
                String::new()
            };

            let resp = BrowseMessage::DirListing(DirListing {
                entries: page,
                next_cursor,
                total_estimate: sorted.len() as u64,
            });

            let encoded = ctx
                .codec
                .encode_frame(&resp, ctx.max_frame_size)
                .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData))?;
            send.write_all(&encoded).await?;
        }
        BrowseMessage::Stat(req) => {
            let metadata = ctx
                .vfs
                .stat(ctx.root, &req.path)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
            let name = req
                .path
                .as_str()
                .split('/')
                .next_back()
                .unwrap_or("")
                .to_string();
            let entry = crate::vfs::DirEntry {
                name,
                kind: metadata.kind,
                size_bytes: metadata.size_bytes,
                modified: metadata.modified,
            };
            let resp = BrowseMessage::StatResult(StatResult { entry });
            let encoded = ctx
                .codec
                .encode_frame(&resp, ctx.max_frame_size)
                .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData))?;
            send.write_all(&encoded).await?;
        }
        BrowseMessage::ReadFile(req) => {
            let metadata = ctx
                .vfs
                .stat(ctx.root, &req.path)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
            if metadata.kind != crate::vfs::EntryKind::File {
                return Err(BrowseFailure::Refused(RefusalReason::WrongKind));
            }
            let reader = ctx
                .vfs
                .open_read(ctx.root, &req.path)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;

            let total_size = metadata.size_bytes;
            let offset = req.offset;
            let bytes_to_read = if req.length == 0 || offset.saturating_add(req.length) > total_size
            {
                total_size.saturating_sub(offset)
            } else {
                req.length
            };

            let resp = BrowseMessage::ReadFileBegin(ReadFileBegin {
                total_size,
                content_hash: crate::ContentHash::from_bytes([0u8; 32]),
                chunk_size: 64 * 1024,
            });
            let encoded = ctx
                .codec
                .encode_frame(&resp, ctx.max_frame_size)
                .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData))?;
            send.write_all(&encoded).await?;

            let mut current_offset = offset;
            let mut remaining = bytes_to_read;
            let mut read_buf = vec![0u8; 64 * 1024];

            while remaining > 0 {
                let to_read = (remaining as usize).min(read_buf.len());
                let n = reader
                    .read_at(current_offset, &mut read_buf[..to_read])
                    .await
                    .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::Other))?;
                if n == 0 {
                    break;
                }
                send.write_all(&read_buf[..n]).await?;
                current_offset += n as u64;
                remaining -= n as u64;
            }
            send.finish().await?;
        }
        BrowseMessage::WriteFile(req) => {
            handle_write_file(req, recv, send, ctx, buffer).await?;
        }
        BrowseMessage::Mkdir(req) => {
            match ctx.vfs.stat(ctx.root, &req.path).await {
                Ok(meta) => {
                    if meta.kind == EntryKind::Directory {
                        send_ack(send, ctx).await?;
                        return Ok(());
                    } else {
                        return Err(BrowseFailure::Refused(RefusalReason::AlreadyExists));
                    }
                }
                Err(VfsError::NotFound) => {}
                Err(e) => return Err(BrowseFailure::Refused(refusal_for(e))),
            }

            if !req.parents {
                let parent_is_dir = if let Some(idx) = req.path.as_str().rfind('/') {
                    let parent_str = &req.path.as_str()[..idx];
                    if parent_str.is_empty() {
                        true
                    } else {
                        let parent_path = RelPath::new(parent_str)
                            .map_err(|_| BrowseFailure::Refused(RefusalReason::Failed))?;
                        match ctx.vfs.stat(ctx.root, &parent_path).await {
                            Ok(meta) => meta.kind == EntryKind::Directory,
                            Err(_) => false,
                        }
                    }
                } else {
                    true
                };

                if !parent_is_dir {
                    return Err(BrowseFailure::Refused(RefusalReason::NotFound));
                }
            }

            ctx.vfs
                .create_dir(ctx.root, &req.path)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
            send_ack(send, ctx).await?;
        }
        BrowseMessage::Delete(req) => {
            let meta = ctx
                .vfs
                .stat(ctx.root, &req.path)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
            match meta.kind {
                EntryKind::File => {
                    ctx.vfs
                        .remove(ctx.root, &req.path)
                        .await
                        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
                }
                EntryKind::Directory => {
                    let entries = ctx
                        .vfs
                        .list(ctx.root, &req.path)
                        .await
                        .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
                    if entries.is_empty() {
                        ctx.vfs
                            .remove(ctx.root, &req.path)
                            .await
                            .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
                    } else if req.recursive {
                        remove_dir_recursive(ctx.vfs, ctx.root, &req.path)
                            .await
                            .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
                    } else {
                        return Err(BrowseFailure::Refused(RefusalReason::WrongKind));
                    }
                }
            }
            send_ack(send, ctx).await?;
        }
        BrowseMessage::Rename(req) => {
            let from_str = req.from.as_str();
            let to_str = req.to.as_str();
            if to_str == from_str || to_str.starts_with(&format!("{from_str}/")) {
                return Err(BrowseFailure::Refused(RefusalReason::NotAllowed));
            }
            match ctx.vfs.stat(ctx.root, &req.to).await {
                Ok(_) => {
                    return Err(BrowseFailure::Refused(RefusalReason::AlreadyExists));
                }
                Err(VfsError::NotFound) => {}
                Err(e) => return Err(BrowseFailure::Refused(refusal_for(e))),
            }
            ctx.vfs
                .rename(ctx.root, &req.from, &req.to)
                .await
                .map_err(|e| BrowseFailure::Refused(refusal_for(e)))?;
            send_ack(send, ctx).await?;
        }
        _ => {
            return Err(BrowseFailure::Refused(RefusalReason::Failed));
        }
    }
    Ok(())
}

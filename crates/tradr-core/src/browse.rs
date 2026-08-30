//! Browse plane handler and domain types.
//! Maps `browse.proto` messages to `Vfs` calls.

use crate::{
    ContentHash, RelPath, RelPathError, ShareId, ShareIdError, Vfs,
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

/// The Browse plane handler, reading requests from `recv` and writing responses to `send`.
pub async fn handle_browse_stream<'a>(
    recv: &'a mut dyn RecvStream,
    send: &'a mut dyn SendStream,
    codec: &'a dyn BrowseCodec,
    vfs: &'a dyn Vfs,
    root: crate::RootId,
    max_frame_size: u32,
) -> Result<(), crate::channel::TransportError> {
    let mut buf = vec![0u8; max_frame_size as usize * 2];
    let mut pos = 0;

    loop {
        // Read into buffer if we don't have enough to decode
        let read_len = recv.read(&mut buf[pos..]).await?;
        if read_len == 0 {
            break; // EOF
        }
        pos += read_len;

        // Try decoding
        while pos > 0 {
            match codec.decode_frame(&buf[..pos], max_frame_size) {
                Ok(Some((msg, consumed))) => {
                    buf.copy_within(consumed..pos, 0);
                    pos -= consumed;
                    handle_message(msg, send, codec, vfs, root, max_frame_size).await?;
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

async fn handle_message<'a>(
    msg: BrowseMessage,
    send: &'a mut dyn SendStream,
    codec: &'a dyn BrowseCodec,
    vfs: &'a dyn Vfs,
    root: crate::RootId,
    max_frame_size: u32,
) -> Result<(), crate::channel::TransportError> {
    match msg {
        BrowseMessage::ListDir(req) => {
            let entries_result = vfs.list(root, &req.path).await;
            match entries_result {
                Ok(entries) => {
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

                    let encoded = codec.encode_frame(&resp, max_frame_size).map_err(|_| {
                        crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData)
                    })?;
                    send.write_all(&encoded).await?;
                }
                Err(_) => {
                    let resp = BrowseMessage::DirListing(DirListing {
                        entries: vec![],
                        next_cursor: String::new(),
                        total_estimate: 0,
                    });
                    let encoded = codec.encode_frame(&resp, max_frame_size).map_err(|_| {
                        crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData)
                    })?;
                    send.write_all(&encoded).await?;
                }
            }
        }
        BrowseMessage::Stat(req) => {
            let metadata = vfs
                .stat(root, &req.path)
                .await
                .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::NotFound))?;
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
            let encoded = codec
                .encode_frame(&resp, max_frame_size)
                .map_err(|_| crate::channel::TransportError::Io(std::io::ErrorKind::InvalidData))?;
            send.write_all(&encoded).await?;
        }
        _ => {
            return Err(crate::channel::TransportError::Io(
                std::io::ErrorKind::InvalidInput,
            ));
        }
    }
    Ok(())
}

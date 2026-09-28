//! Converts between wire `browse.proto` messages and native Layer 0 types.

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;
use prost::Message;
use tradr_core::{
    Ack, BrowseCodec, BrowseDomainError, BrowseMessage, ContentHash, Delete, DirEntry, DirListing,
    EntryKind, ListDir, Mkdir, ReadFile, ReadFileBegin, RelPath, Rename, Stat, StatResult,
    UnixTime, WriteFile, WriteMode,
};

/// Errors arising during encoding or decoding framed Browse messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseFrameError {
    /// The frame's type byte did not match the expected message type.
    WrongMessageType {
        /// expected message type code
        expected: u8,
        /// received message type code
        got: u8,
    },
    /// Framing could not encode or decode the byte sequence.
    Framing(FrameError),
    /// Protobuf payload decoding failed.
    Decode(prost::DecodeError),
    /// Wire validation failed on decoded fields.
    Wire(BrowseDomainError),
}
impl std::fmt::Display for BrowseFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongMessageType { expected, got } => {
                write!(
                    f,
                    "expected frame type 0x{:02x}, got 0x{:02x}",
                    expected, got
                )
            }
            Self::Framing(e) => write!(f, "frame error: {}", e),
            Self::Decode(e) => write!(f, "protobuf decode error: {}", e),
            Self::Wire(e) => write!(f, "wire validation error: {}", e),
        }
    }
}
impl std::error::Error for BrowseFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongMessageType { .. } => None,
            Self::Framing(e) => Some(e),
            Self::Decode(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}
impl From<FrameError> for BrowseFrameError {
    fn from(err: FrameError) -> Self {
        Self::Framing(err)
    }
}
impl From<prost::DecodeError> for BrowseFrameError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Decode(err)
    }
}
impl From<BrowseDomainError> for BrowseFrameError {
    fn from(err: BrowseDomainError) -> Self {
        Self::Wire(err)
    }
}

pub fn list_dir_from_wire(msg: v1::ListDir) -> Result<ListDir, BrowseDomainError> {
    let path = if msg.path.is_empty() {
        RelPath::root()
    } else {
        RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?
    };
    Ok(ListDir {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path,
        cursor: msg.cursor,
        limit: msg.limit,
        with_hash: msg.with_hash,
    })
}
pub fn list_dir_to_wire(msg: &ListDir) -> v1::ListDir {
    v1::ListDir {
        share_id: msg.share_id.to_string(),
        path: msg.path.to_string(),
        cursor: msg.cursor.clone(),
        limit: msg.limit,
        with_hash: msg.with_hash,
    }
}
pub fn decode_list_dir_frame(frame: &Frame) -> Result<ListDir, BrowseFrameError> {
    let expected = MessageType::ListDir.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ListDir::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    list_dir_from_wire(wire).map_err(BrowseFrameError::Wire)
}
pub fn encode_list_dir_frame(msg: &ListDir, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = list_dir_to_wire(msg);
    encode_frame(MessageType::ListDir.code(), &wire.encode_to_vec(), max_size)
        .map_err(BrowseFrameError::Framing)
}

fn file_entry_from_wire(msg: v1::FileEntry) -> Result<DirEntry, BrowseDomainError> {
    let kind = match msg.kind {
        1 => EntryKind::File,
        2 => EntryKind::Directory,
        _ => EntryKind::File, // Ignore symlink/unspecified
    };
    Ok(DirEntry {
        name: msg.relative_path,
        kind,
        size_bytes: msg.size,
        modified: UnixTime::from_secs(msg.mtime),
    })
}
fn file_entry_to_wire(entry: &DirEntry) -> v1::FileEntry {
    v1::FileEntry {
        relative_path: entry.name.clone(),
        kind: match entry.kind {
            EntryKind::File => 1,
            EntryKind::Directory => 2,
        },
        size: entry.size_bytes,
        mtime: entry.modified.as_secs(),
        mode: 0,
        content_hash: vec![],
        mime: String::new(),
    }
}

pub fn dir_listing_from_wire(msg: v1::DirListing) -> Result<DirListing, BrowseDomainError> {
    let mut entries = Vec::new();
    for e in msg.entries {
        if let Ok(entry) = file_entry_from_wire(e) {
            entries.push(entry);
        }
    }
    Ok(DirListing {
        entries,
        next_cursor: msg.next_cursor,
        total_estimate: msg.total_estimate,
    })
}
pub fn dir_listing_to_wire(msg: &DirListing) -> v1::DirListing {
    v1::DirListing {
        entries: msg.entries.iter().map(file_entry_to_wire).collect(),
        next_cursor: msg.next_cursor.clone(),
        total_estimate: msg.total_estimate,
    }
}
pub fn decode_dir_listing_frame(frame: &Frame) -> Result<DirListing, BrowseFrameError> {
    let expected = MessageType::DirListing.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::DirListing::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    dir_listing_from_wire(wire).map_err(BrowseFrameError::Wire)
}
pub fn encode_dir_listing_frame(
    msg: &DirListing,
    max_size: u32,
) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = dir_listing_to_wire(msg);
    encode_frame(
        MessageType::DirListing.code(),
        &wire.encode_to_vec(),
        max_size,
    )
    .map_err(BrowseFrameError::Framing)
}

pub fn stat_from_wire(msg: v1::Stat) -> Result<Stat, BrowseDomainError> {
    Ok(Stat {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path: RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?,
    })
}
pub fn stat_to_wire(msg: &Stat) -> v1::Stat {
    v1::Stat {
        share_id: msg.share_id.to_string(),
        path: msg.path.to_string(),
    }
}
pub fn decode_stat_frame(frame: &Frame) -> Result<Stat, BrowseFrameError> {
    let expected = MessageType::Stat.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::Stat::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    stat_from_wire(wire).map_err(BrowseFrameError::Wire)
}
pub fn encode_stat_frame(msg: &Stat, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = stat_to_wire(msg);
    encode_frame(MessageType::Stat.code(), &wire.encode_to_vec(), max_size)
        .map_err(BrowseFrameError::Framing)
}

pub fn stat_result_from_wire(msg: v1::StatResult) -> Result<StatResult, BrowseDomainError> {
    Ok(StatResult {
        entry: msg
            .entry
            .map(file_entry_from_wire)
            .transpose()?
            .unwrap_or(DirEntry {
                name: String::new(),
                kind: EntryKind::File,
                size_bytes: 0,
                modified: UnixTime::from_secs(0),
            }),
    })
}
pub fn stat_result_to_wire(msg: &StatResult) -> v1::StatResult {
    v1::StatResult {
        entry: Some(file_entry_to_wire(&msg.entry)),
    }
}
pub fn decode_stat_result_frame(frame: &Frame) -> Result<StatResult, BrowseFrameError> {
    let expected = MessageType::StatResult.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::StatResult::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    stat_result_from_wire(wire).map_err(BrowseFrameError::Wire)
}
pub fn encode_stat_result_frame(
    msg: &StatResult,
    max_size: u32,
) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = stat_result_to_wire(msg);
    encode_frame(
        MessageType::StatResult.code(),
        &wire.encode_to_vec(),
        max_size,
    )
    .map_err(BrowseFrameError::Framing)
}

pub fn read_file_from_wire(msg: v1::ReadFile) -> Result<ReadFile, BrowseDomainError> {
    Ok(ReadFile {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path: RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?,
        offset: msg.offset,
        length: msg.length,
    })
}
pub fn read_file_to_wire(msg: &ReadFile) -> v1::ReadFile {
    v1::ReadFile {
        share_id: msg.share_id.to_string(),
        path: msg.path.to_string(),
        offset: msg.offset,
        length: msg.length,
    }
}
pub fn decode_read_file_frame(frame: &Frame) -> Result<ReadFile, BrowseFrameError> {
    let expected = MessageType::ReadFile.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ReadFile::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    read_file_from_wire(wire).map_err(BrowseFrameError::Wire)
}
pub fn encode_read_file_frame(msg: &ReadFile, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = read_file_to_wire(msg);
    encode_frame(
        MessageType::ReadFile.code(),
        &wire.encode_to_vec(),
        max_size,
    )
    .map_err(BrowseFrameError::Framing)
}

pub fn read_file_begin_from_wire(
    msg: v1::ReadFileBegin,
) -> Result<ReadFileBegin, BrowseDomainError> {
    let hash_bytes: [u8; 32] = if msg.content_hash.is_empty() {
        [0u8; 32]
    } else {
        msg.content_hash
            .try_into()
            .map_err(|bytes: Vec<u8>| BrowseDomainError::InvalidContentHash(bytes.len()))?
    };
    Ok(ReadFileBegin {
        total_size: msg.total_size,
        content_hash: ContentHash::from_bytes(hash_bytes),
        chunk_size: msg.chunk_size,
    })
}

pub fn read_file_begin_to_wire(msg: &ReadFileBegin) -> v1::ReadFileBegin {
    v1::ReadFileBegin {
        total_size: msg.total_size,
        content_hash: msg.content_hash.as_bytes().to_vec(),
        chunk_size: msg.chunk_size,
    }
}

pub fn decode_read_file_begin_frame(frame: &Frame) -> Result<ReadFileBegin, BrowseFrameError> {
    let expected = MessageType::ReadFileBegin.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::ReadFileBegin::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    read_file_begin_from_wire(wire).map_err(BrowseFrameError::Wire)
}

pub fn encode_read_file_begin_frame(
    msg: &ReadFileBegin,
    max_size: u32,
) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = read_file_begin_to_wire(msg);
    encode_frame(
        MessageType::ReadFileBegin.code(),
        &wire.encode_to_vec(),
        max_size,
    )
    .map_err(BrowseFrameError::Framing)
}

pub fn write_file_from_wire(msg: v1::WriteFile) -> Result<WriteFile, BrowseDomainError> {
    let mode = match v1::WriteMode::try_from(msg.mode) {
        Ok(v1::WriteMode::CreateNew) => WriteMode::CreateNew,
        Ok(v1::WriteMode::Overwrite) => WriteMode::Overwrite,
        Ok(v1::WriteMode::RenameIfExists) => WriteMode::RenameIfExists,
        Ok(v1::WriteMode::Unspecified) | Err(_) => return Err(BrowseDomainError::InvalidWriteMode),
    };
    let hash_bytes: [u8; 32] = if msg.content_hash.is_empty() {
        [0u8; 32]
    } else {
        msg.content_hash
            .try_into()
            .map_err(|bytes: Vec<u8>| BrowseDomainError::InvalidContentHash(bytes.len()))?
    };
    Ok(WriteFile {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path: RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?,
        size: msg.size,
        content_hash: ContentHash::from_bytes(hash_bytes),
        mode,
    })
}

pub fn write_file_to_wire(msg: &WriteFile) -> v1::WriteFile {
    let mode = match msg.mode {
        WriteMode::CreateNew => v1::WriteMode::CreateNew as i32,
        WriteMode::Overwrite => v1::WriteMode::Overwrite as i32,
        WriteMode::RenameIfExists => v1::WriteMode::RenameIfExists as i32,
    };
    v1::WriteFile {
        share_id: msg.share_id.to_string(),
        path: msg.path.to_string(),
        size: msg.size,
        content_hash: msg.content_hash.as_bytes().to_vec(),
        mode,
    }
}

pub fn decode_write_file_frame(frame: &Frame) -> Result<WriteFile, BrowseFrameError> {
    let expected = MessageType::WriteFile.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::WriteFile::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    write_file_from_wire(wire).map_err(BrowseFrameError::Wire)
}

pub fn encode_write_file_frame(
    msg: &WriteFile,
    max_size: u32,
) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = write_file_to_wire(msg);
    encode_frame(
        MessageType::WriteFile.code(),
        &wire.encode_to_vec(),
        max_size,
    )
    .map_err(BrowseFrameError::Framing)
}

pub fn mkdir_from_wire(msg: v1::Mkdir) -> Result<Mkdir, BrowseDomainError> {
    Ok(Mkdir {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path: RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?,
        parents: msg.parents,
    })
}

pub fn mkdir_to_wire(msg: &Mkdir) -> v1::Mkdir {
    v1::Mkdir {
        share_id: msg.share_id.to_string(),
        path: msg.path.to_string(),
        parents: msg.parents,
    }
}

pub fn decode_mkdir_frame(frame: &Frame) -> Result<Mkdir, BrowseFrameError> {
    let expected = MessageType::Mkdir.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::Mkdir::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    mkdir_from_wire(wire).map_err(BrowseFrameError::Wire)
}

pub fn encode_mkdir_frame(msg: &Mkdir, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = mkdir_to_wire(msg);
    encode_frame(MessageType::Mkdir.code(), &wire.encode_to_vec(), max_size)
        .map_err(BrowseFrameError::Framing)
}

pub fn delete_from_wire(msg: v1::Delete) -> Result<Delete, BrowseDomainError> {
    Ok(Delete {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path: RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?,
        recursive: msg.recursive,
    })
}

pub fn delete_to_wire(msg: &Delete) -> v1::Delete {
    v1::Delete {
        share_id: msg.share_id.to_string(),
        path: msg.path.to_string(),
        recursive: msg.recursive,
    }
}

pub fn decode_delete_frame(frame: &Frame) -> Result<Delete, BrowseFrameError> {
    let expected = MessageType::Delete.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::Delete::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    delete_from_wire(wire).map_err(BrowseFrameError::Wire)
}

pub fn encode_delete_frame(msg: &Delete, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = delete_to_wire(msg);
    encode_frame(MessageType::Delete.code(), &wire.encode_to_vec(), max_size)
        .map_err(BrowseFrameError::Framing)
}

pub fn rename_from_wire(msg: v1::Rename) -> Result<Rename, BrowseDomainError> {
    Ok(Rename {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        from: RelPath::new(&msg.from).map_err(BrowseDomainError::InvalidRelPath)?,
        to: RelPath::new(&msg.to).map_err(BrowseDomainError::InvalidRelPath)?,
    })
}

pub fn rename_to_wire(msg: &Rename) -> v1::Rename {
    v1::Rename {
        share_id: msg.share_id.to_string(),
        from: msg.from.to_string(),
        to: msg.to.to_string(),
    }
}

pub fn decode_rename_frame(frame: &Frame) -> Result<Rename, BrowseFrameError> {
    let expected = MessageType::Rename.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::Rename::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    rename_from_wire(wire).map_err(BrowseFrameError::Wire)
}

pub fn encode_rename_frame(msg: &Rename, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = rename_to_wire(msg);
    encode_frame(MessageType::Rename.code(), &wire.encode_to_vec(), max_size)
        .map_err(BrowseFrameError::Framing)
}

pub fn ack_from_wire(msg: v1::Ack) -> Result<Ack, BrowseDomainError> {
    Ok(Ack {
        request_id: msg.request_id,
    })
}

pub fn ack_to_wire(msg: &Ack) -> v1::Ack {
    v1::Ack {
        request_id: msg.request_id.clone(),
    }
}

pub fn decode_ack_frame(frame: &Frame) -> Result<Ack, BrowseFrameError> {
    let expected = MessageType::Ack.code();
    if frame.type_code() != expected {
        return Err(BrowseFrameError::WrongMessageType {
            expected,
            got: frame.type_code(),
        });
    }
    let wire = v1::Ack::decode(frame.payload()).map_err(BrowseFrameError::Decode)?;
    ack_from_wire(wire).map_err(BrowseFrameError::Wire)
}

pub fn encode_ack_frame(msg: &Ack, max_size: u32) -> Result<Vec<u8>, BrowseFrameError> {
    let wire = ack_to_wire(msg);
    encode_frame(MessageType::Ack.code(), &wire.encode_to_vec(), max_size)
        .map_err(BrowseFrameError::Framing)
}

fn frame_error_to_domain(err: BrowseFrameError) -> BrowseDomainError {
    match err {
        BrowseFrameError::Wire(e) => e,
        BrowseFrameError::Framing(e) => BrowseDomainError::CodecError(e.to_string()),
        BrowseFrameError::Decode(e) => BrowseDomainError::CodecError(e.to_string()),
        BrowseFrameError::WrongMessageType { expected, got } => BrowseDomainError::CodecError(
            format!("expected frame type 0x{:02x}, got 0x{:02x}", expected, got),
        ),
    }
}

pub struct ProtoBrowseCodec {
    max_frame_size: u32,
}

impl ProtoBrowseCodec {
    pub fn new(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }
}

impl BrowseCodec for ProtoBrowseCodec {
    fn decode_frame(
        &self,
        buf: &[u8],
        _max_frame_size: u32,
    ) -> Result<Option<(BrowseMessage, usize)>, BrowseDomainError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let announced = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        if announced == 0 {
            return Err(BrowseDomainError::CodecError(FrameError::Empty.to_string()));
        }
        if announced > self.max_frame_size as u64 {
            return Err(BrowseDomainError::CodecError(
                FrameError::Oversized {
                    announced,
                    limit: self.max_frame_size,
                }
                .to_string(),
            ));
        }
        let total_len = 4 + announced;
        if (buf.len() as u64) < total_len {
            return Ok(None);
        }
        let total_len = total_len as usize;

        let mut decoder = crate::framing::FrameDecoder::new(self.max_frame_size);
        decoder.feed(&buf[..total_len]);
        let frame = match decoder.next_frame() {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            Err(e) => return Err(BrowseDomainError::CodecError(e.to_string())),
        };

        let msg = match frame.type_code() {
            0x40 => BrowseMessage::ListDir(
                decode_list_dir_frame(&frame).map_err(frame_error_to_domain)?,
            ),
            0x41 => BrowseMessage::DirListing(
                decode_dir_listing_frame(&frame).map_err(frame_error_to_domain)?,
            ),
            0x42 => BrowseMessage::Stat(decode_stat_frame(&frame).map_err(frame_error_to_domain)?),
            0x43 => BrowseMessage::StatResult(
                decode_stat_result_frame(&frame).map_err(frame_error_to_domain)?,
            ),
            0x44 => BrowseMessage::ReadFile(
                decode_read_file_frame(&frame).map_err(frame_error_to_domain)?,
            ),
            0x45 => BrowseMessage::ReadFileBegin(
                decode_read_file_begin_frame(&frame).map_err(frame_error_to_domain)?,
            ),
            0x46 => BrowseMessage::WriteFile(
                decode_write_file_frame(&frame).map_err(frame_error_to_domain)?,
            ),
            0x47 => {
                BrowseMessage::Mkdir(decode_mkdir_frame(&frame).map_err(frame_error_to_domain)?)
            }
            0x48 => {
                BrowseMessage::Delete(decode_delete_frame(&frame).map_err(frame_error_to_domain)?)
            }
            0x49 => {
                BrowseMessage::Rename(decode_rename_frame(&frame).map_err(frame_error_to_domain)?)
            }
            0x4a => BrowseMessage::Ack(decode_ack_frame(&frame).map_err(frame_error_to_domain)?),
            _ => return Err(BrowseDomainError::UnsupportedMessage),
        };
        Ok(Some((msg, total_len)))
    }

    fn encode_frame(
        &self,
        msg: &BrowseMessage,
        max_frame_size: u32,
    ) -> Result<Vec<u8>, BrowseDomainError> {
        match msg {
            BrowseMessage::ListDir(m) => {
                encode_list_dir_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::DirListing(m) => {
                encode_dir_listing_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::Stat(m) => {
                encode_stat_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::StatResult(m) => {
                encode_stat_result_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::ReadFile(m) => {
                encode_read_file_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::ReadFileBegin(m) => {
                encode_read_file_begin_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::WriteFile(m) => {
                encode_write_file_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::Mkdir(m) => {
                encode_mkdir_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::Delete(m) => {
                encode_delete_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::Rename(m) => {
                encode_rename_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            BrowseMessage::Ack(m) => {
                encode_ack_frame(m, max_frame_size).map_err(frame_error_to_domain)
            }
            _ => Err(BrowseDomainError::UnsupportedMessage),
        }
    }
}

//! Converts between wire `browse.proto` messages and native Layer 0 types.

use crate::framing::{Frame, FrameError, encode_frame};
use crate::message_type::MessageType;
use crate::v1;
use prost::Message;
use tradr_core::{
    BrowseDomainError, DirEntry, DirListing, EntryKind, ListDir, ReadFile, RelPath, Stat,
    StatResult, UnixTime,
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
    Ok(ListDir {
        share_id: msg
            .share_id
            .parse()
            .map_err(BrowseDomainError::InvalidShareId)?,
        path: RelPath::new(&msg.path).map_err(BrowseDomainError::InvalidRelPath)?,
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

use tradr_core::{BrowseCodec, BrowseMessage};

pub struct ProtoBrowseCodec {
    decoder: std::sync::Mutex<crate::framing::FrameDecoder>,
}

impl ProtoBrowseCodec {
    pub fn new(max_frame_size: u32) -> Self {
        Self {
            decoder: std::sync::Mutex::new(crate::framing::FrameDecoder::new(max_frame_size)),
        }
    }
}

impl BrowseCodec for ProtoBrowseCodec {
    fn decode_frame(
        &self,
        buf: &[u8],
        _max_frame_size: u32,
    ) -> Result<Option<(BrowseMessage, usize)>, BrowseDomainError> {
        let mut decoder = self.decoder.lock().unwrap();
        decoder.feed(buf);
        let before_len = decoder.buffered_len();
        let frame = match decoder.next_frame() {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            Err(e) => return Err(BrowseDomainError::CodecError(e.to_string())),
        };
        let consumed = before_len - decoder.buffered_len();

        let msg = match frame.type_code() {
            0x40 => BrowseMessage::ListDir(
                decode_list_dir_frame(&frame)
                    .map_err(|e| BrowseDomainError::CodecError(e.to_string()))?,
            ),
            0x41 => BrowseMessage::DirListing(
                decode_dir_listing_frame(&frame)
                    .map_err(|e| BrowseDomainError::CodecError(e.to_string()))?,
            ),
            0x42 => BrowseMessage::Stat(
                decode_stat_frame(&frame)
                    .map_err(|e| BrowseDomainError::CodecError(e.to_string()))?,
            ),
            0x43 => BrowseMessage::StatResult(
                decode_stat_result_frame(&frame)
                    .map_err(|e| BrowseDomainError::CodecError(e.to_string()))?,
            ),
            0x44 => BrowseMessage::ReadFile(
                decode_read_file_frame(&frame)
                    .map_err(|e| BrowseDomainError::CodecError(e.to_string()))?,
            ),
            _ => return Err(BrowseDomainError::UnsupportedMessage),
        };
        Ok(Some((msg, consumed)))
    }

    fn encode_frame(
        &self,
        msg: &BrowseMessage,
        max_frame_size: u32,
    ) -> Result<Vec<u8>, BrowseDomainError> {
        match msg {
            BrowseMessage::ListDir(m) => encode_list_dir_frame(m, max_frame_size)
                .map_err(|e| BrowseDomainError::CodecError(e.to_string())),
            BrowseMessage::DirListing(m) => encode_dir_listing_frame(m, max_frame_size)
                .map_err(|e| BrowseDomainError::CodecError(e.to_string())),
            BrowseMessage::Stat(m) => encode_stat_frame(m, max_frame_size)
                .map_err(|e| BrowseDomainError::CodecError(e.to_string())),
            BrowseMessage::StatResult(m) => encode_stat_result_frame(m, max_frame_size)
                .map_err(|e| BrowseDomainError::CodecError(e.to_string())),
            BrowseMessage::ReadFile(m) => encode_read_file_frame(m, max_frame_size)
                .map_err(|e| BrowseDomainError::CodecError(e.to_string())),
            _ => Err(BrowseDomainError::UnsupportedMessage), // Unimplemented
        }
    }
}

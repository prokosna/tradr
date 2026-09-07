//! In-band multiplexing frames for single-stream links (docs/04-protocol.md,
//! "The in-band multiplexing frame"): `[len:u32 BE][type:u8][stream_id:u32 BE][payload]`.
//! This layer knows nothing about planes: it carries opaque bytes on numbered
//! streams and never reads a payload byte. Per docs/04, mux frames travel one
//! layer below the planes and are never valid on a plane's stream.

use core::fmt;

use crate::framing::{self, Frame, FrameError};

/// The fixed four-byte big-endian stream identifier on the wire.
pub const MUX_STREAM_ID_LEN: usize = 4;

/// Lowest type code reserved for the multiplexing layer.
pub const MUX_CODE_LOW: u8 = 0x60;

/// Highest type code reserved for the multiplexing layer.
pub const MUX_CODE_HIGH: u8 = 0x7f;

/// Which side opened a stream, encoded in stream identifier bit 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOpener {
    /// Bit 0 clear.
    Dialler,
    /// Bit 0 set.
    Listener,
}

/// A 32-bit stream identifier partitioned into four residue spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u32);

impl StreamId {
    /// Stream 0: dialler-opened bidirectional Control plane stream.
    pub const CONTROL: StreamId = Self(0);

    /// Refuses no value: every 32-bit value is a legal identifier because the two low bits classify one rather than constrain it.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The raw 32-bit integer identifier.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Owner is carried in the number so a receiver decides allocation rights without negotiation; a frame on its own space is a peer allocating where it may not.
    pub const fn opened_by(self) -> StreamOpener {
        if (self.0 & 0x01) == 0 {
            StreamOpener::Dialler
        } else {
            StreamOpener::Listener
        }
    }

    /// Directionality is in the number so a receiver settles whether an arriving stream is `accept_bi`'s or `accept_uni`'s with nothing on the wire to say so.
    pub const fn is_bidirectional(self) -> bool {
        (self.0 & 0x02) == 0
    }

    /// Yields `None` at the ceiling because a wrap would reopen an identifier that has already been finished.
    pub const fn next_in_space(self) -> Option<StreamId> {
        match self.0.checked_add(4) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// Allocates ascending stream identifiers in a single side's residue spaces.
#[derive(Debug, Clone)]
pub struct StreamAllocator {
    next_bidi: Option<StreamId>,
    next_uni: Option<StreamId>,
}

impl StreamAllocator {
    /// Builds a stream allocator starting at the lowest identifier for this opener.
    pub fn new(opener: StreamOpener) -> Self {
        match opener {
            StreamOpener::Dialler => Self {
                next_bidi: Some(StreamId::new(0)),
                next_uni: Some(StreamId::new(2)),
            },
            StreamOpener::Listener => Self {
                next_bidi: Some(StreamId::new(1)),
                next_uni: Some(StreamId::new(3)),
            },
        }
    }

    /// Yields the lowest unused bidirectional identifier in this side's space.
    pub fn next_bidirectional(&mut self) -> Result<StreamId, MuxError> {
        let current = self.next_bidi.ok_or(MuxError::StreamIdsExhausted)?;
        self.next_bidi = current.next_in_space();
        Ok(current)
    }

    /// Yields the lowest unused unidirectional identifier in this side's space.
    pub fn next_unidirectional(&mut self) -> Result<StreamId, MuxError> {
        let current = self.next_uni.ok_or(MuxError::StreamIdsExhausted)?;
        self.next_uni = current.next_in_space();
        Ok(current)
    }
}

/// Wire type codes assigned to in-band multiplexing frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxKind {
    /// Next slice of a stream byte sequence (`0x60`).
    Data,
    /// Half-close of a stream write direction (`0x61`).
    Fin,
}

impl MuxKind {
    /// The wire type code assigned to this kind.
    pub const fn code(self) -> u8 {
        match self {
            Self::Data => 0x60,
            Self::Fin => 0x61,
        }
    }

    /// An unassigned code is refused because a skipped mux frame is a hole in a stream's bytes rather than an ignored message.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x60 => Some(Self::Data),
            0x61 => Some(Self::Fin),
            _ => None,
        }
    }
}

/// A parsed multiplexing frame carrying a stream identifier and stream bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct MuxFrame {
    kind: MuxKind,
    stream_id: StreamId,
    payload: Vec<u8>,
}

impl MuxFrame {
    /// The multiplexing frame kind.
    pub fn kind(&self) -> MuxKind {
        self.kind
    }

    /// The stream this frame belongs to.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// The slice of stream bytes carried by this frame.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Failure to encode or parse an in-band multiplexing frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxError {
    /// Outer byte framing rejected the frame.
    Frame(FrameError),
    /// The type code falls outside the reserved multiplexing range.
    NotAMuxCode(u8),
    /// The type code is reserved for multiplexing but not assigned.
    UnassignedCode(u8),
    /// The payload has fewer than four bytes to carry a stream identifier.
    TruncatedHeader(usize),
    /// A Fin frame carried unexpected payload bytes beyond the stream identifier.
    FinCarriesPayload(usize),
    /// All identifiers in this residue space have been allocated.
    StreamIdsExhausted,
}

impl fmt::Display for MuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(err) => write!(f, "{err}"),
            Self::NotAMuxCode(code) => write!(f, "0x{code:02x} is outside multiplexing range"),
            Self::UnassignedCode(code) => write!(f, "0x{code:02x} is unassigned multiplexing code"),
            Self::TruncatedHeader(len) => {
                write!(
                    f,
                    "mux frame payload is too short for stream_id ({len} bytes)"
                )
            }
            Self::FinCarriesPayload(len) => {
                write!(
                    f,
                    "stream fin frame must have empty payload but carried {len} bytes"
                )
            }
            Self::StreamIdsExhausted => write!(f, "stream identifiers exhausted"),
        }
    }
}

impl std::error::Error for MuxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(err) => Some(err),
            Self::NotAMuxCode(_)
            | Self::UnassignedCode(_)
            | Self::TruncatedHeader(_)
            | Self::FinCarriesPayload(_)
            | Self::StreamIdsExhausted => None,
        }
    }
}

/// `limit` is the link's own record bound, not the `max_frame_size` a plane negotiates,
/// because that limit bounds the frames travelling inside a stream.
pub fn encode_mux_frame(
    kind: MuxKind,
    stream_id: StreamId,
    payload: &[u8],
    limit: u32,
) -> Result<Vec<u8>, MuxError> {
    if kind == MuxKind::Fin && !payload.is_empty() {
        return Err(MuxError::FinCarriesPayload(payload.len()));
    }
    let mut combined = Vec::with_capacity(MUX_STREAM_ID_LEN + payload.len());
    combined.extend_from_slice(&stream_id.value().to_be_bytes());
    combined.extend_from_slice(payload);
    framing::encode_frame(kind.code(), &combined, limit).map_err(MuxError::Frame)
}

/// Length bounds, zero length, and poisoning were already decided by the `FrameDecoder` that produced this `Frame`, so nothing here repeats them.
pub fn mux_frame_from_wire(frame: &Frame) -> Result<MuxFrame, MuxError> {
    let code = frame.type_code();
    if !(MUX_CODE_LOW..=MUX_CODE_HIGH).contains(&code) {
        return Err(MuxError::NotAMuxCode(code));
    }
    let kind = MuxKind::from_code(code).ok_or(MuxError::UnassignedCode(code))?;
    if frame.payload().len() < MUX_STREAM_ID_LEN {
        return Err(MuxError::TruncatedHeader(frame.payload().len()));
    }
    if kind == MuxKind::Fin && frame.payload().len() > MUX_STREAM_ID_LEN {
        return Err(MuxError::FinCarriesPayload(
            frame.payload().len() - MUX_STREAM_ID_LEN,
        ));
    }
    let stream_id = StreamId::new(u32::from_be_bytes([
        frame.payload()[0],
        frame.payload()[1],
        frame.payload()[2],
        frame.payload()[3],
    ]));
    let payload = frame.payload()[MUX_STREAM_ID_LEN..].to_vec();
    Ok(MuxFrame {
        kind,
        stream_id,
        payload,
    })
}

/// Where a writer chops a stream, not a limit a caller may exceed: a stream carries bytes, so what will not fit in one frame goes in the next.
pub const fn max_mux_payload(limit: u32) -> usize {
    const OVERHEAD: u32 = 1 + MUX_STREAM_ID_LEN as u32;
    limit.saturating_sub(OVERHEAD) as usize
}

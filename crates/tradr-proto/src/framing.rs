//! Byte framing for the wire (docs/04-protocol.md, "Framing"): `[len:u32
//! BE][type:u8][payload]`, where `len` counts `type` and `payload` together
//! and never itself. This module knows nothing about protobuf: it carries
//! `type_code` and `payload` verbatim, and does no I/O; the plane that
//! owns the stream feeds bytes in and pulls frames out.

use core::fmt;

/// Four length bytes plus the type byte.
pub const FRAME_HEADER_LEN: usize = 5;

/// The four-byte big-endian length prefix alone, without the type byte.
const LEN_PREFIX_LEN: usize = FRAME_HEADER_LEN - 1;

/// A frame that could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The announced length exceeds `limit`. `announced` is the value the
    /// `len` field carries (or would carry), `1 + payload.len()`, kept as
    /// `u64` because on encode it comes from `payload.len()`, which does
    /// not fit `u32` on a 64-bit target.
    Oversized { announced: u64, limit: u32 },
    /// The announced `len` was zero. A frame always carries at least its
    /// type byte, so `len == 0` cannot describe one.
    Empty,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Oversized { announced, limit } => {
                write!(
                    f,
                    "frame of {announced} bytes exceeds the {limit} byte limit"
                )
            }
            FrameError::Empty => write!(f, "frame announced a length of zero"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encodes `payload` under `type_code` as `[len:u32 BE][type_code][payload]`,
/// where `len == 1 + payload.len()`. `limit` is the **peer's** advertised
/// `max_frame_size` (docs/04's "Which `max_frame_size` bounds which
/// direction"), never this side's own: passing this side's own value here
/// is exactly the bug this parameter exists to make visible.
pub fn encode_frame(type_code: u8, payload: &[u8], limit: u32) -> Result<Vec<u8>, FrameError> {
    // u64 arithmetic: 1 + payload.len() does not fit u32 on a 64-bit
    // target, and a truncating cast would turn an oversized payload into a
    // small legal-looking frame.
    let announced: u64 = 1 + payload.len() as u64;
    if announced > limit as u64 {
        return Err(FrameError::Oversized { announced, limit });
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&(announced as u32).to_be_bytes());
    frame.push(type_code);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// A decoded frame: a type code carried verbatim and its payload bytes.
/// Holds no registry of what a type code means and never inspects one.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    type_code: u8,
    payload: Vec<u8>,
}

impl Frame {
    /// The frame's type byte, carried verbatim from the wire.
    pub fn type_code(&self) -> u8 {
        self.type_code
    }

    /// The frame's payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Assembles frames out of a byte stream fed to it in arbitrary chunks.
/// Never sizes an allocation from an announced length: the bound is
/// checked the moment the four header bytes are in hand, before a payload
/// byte is reserved. Once `next_frame` errors the decoder is poisoned and
/// returns that same error forever after (docs/04's "A bad length ends the connection").
pub struct FrameDecoder {
    limit: u32,
    buf: Vec<u8>,
    poison: Option<FrameError>,
}

impl FrameDecoder {
    /// Builds a decoder bounded by `limit`, this side's own advertised
    /// `max_frame_size` (docs/04), enforced against every frame received.
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            buf: Vec::new(),
            poison: None,
        }
    }

    /// Appends received bytes to the decoder's buffer. Never fails and
    /// never inspects the bytes; only `next_frame` interprets them.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// How many bytes are still buffered, unconsumed by a yielded frame.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Pulls the next complete frame out of the buffered bytes, if one is
    /// available. Returns `Ok(None)` when fewer than one whole frame has
    /// been fed so far.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if let Some(err) = self.poison {
            return Err(err);
        }
        if self.buf.len() < LEN_PREFIX_LEN {
            return Ok(None);
        }
        let announced =
            u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as u64;
        if announced == 0 {
            self.poison = Some(FrameError::Empty);
            self.buf.clear();
            return Err(FrameError::Empty);
        }
        if announced > self.limit as u64 {
            let err = FrameError::Oversized {
                announced,
                limit: self.limit,
            };
            self.poison = Some(err);
            self.buf.clear();
            return Err(err);
        }
        // total_len can exceed usize::MAX on a 32-bit target (announced is
        // bounded only by self.limit, up to u32::MAX), so the comparison
        // against the buffered length is done in u64 rather than cast down.
        let total_len = LEN_PREFIX_LEN as u64 + announced;
        if (self.buf.len() as u64) < total_len {
            return Ok(None);
        }
        let total_len = total_len as usize;
        let type_code = self.buf[LEN_PREFIX_LEN];
        let payload = self.buf[LEN_PREFIX_LEN + 1..total_len].to_vec();
        self.buf.drain(..total_len);
        Ok(Some(Frame { type_code, payload }))
    }
}

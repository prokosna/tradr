//! Owns connection multiplexing state while tradr-proto's mux module owns wire encoding.
//! Streams open implicitly on their first frame, so open_* emits nothing on the wire.
//! Any protocol refusal is permanent and fatal to the entire channel because there
//! is no in-band reset frame.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use tradr_proto::mux::{
    MuxError, MuxFrame, MuxKind, StreamAllocator, StreamId, StreamOpener, encode_mux_frame,
    max_mux_payload,
};

/// Multiplies frame size so plane progress requires a full frame and transports scale without a second table.
pub const RECEIVE_WINDOW_FRAMES: usize = 128;

/// Limits unaccepted streams so buffered receive windows cannot multiply memory usage without bound.
pub const MAX_PENDING_STREAMS: usize = 64;

/// Floor below which max_mux_payload is zero and chopping a write would never terminate.
pub const MIN_RECORD_LIMIT: u32 = 6;

/// Closes the entire channel because without reset frames an authenticated peer has broken the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRefusal {
    /// The peer sent a frame on an unallocated stream inside this side's residue space.
    PeerAllocatedInOurSpace(StreamId),
    /// The peer transmitted bytes on a stream this side opened unidirectionally.
    WroteToOurUnidirectionalStream(StreamId),
    /// A frame arrived for a stream whose remote finish was already received.
    FrameAfterFin(StreamId),
    /// Undelivered bytes for a stream would exceed the per-stream receive window bound.
    ReceiveWindowExceeded(StreamId),
    /// The number of unaccepted peer-opened streams exceeded the concurrency bound.
    TooManyPendingStreams,
}

impl fmt::Display for MuxRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerAllocatedInOurSpace(stream_id) => {
                write!(
                    f,
                    "peer allocated stream {} in local space",
                    stream_id.value()
                )
            }
            Self::WroteToOurUnidirectionalStream(stream_id) => {
                write!(
                    f,
                    "peer wrote to local unidirectional stream {}",
                    stream_id.value()
                )
            }
            Self::FrameAfterFin(stream_id) => {
                write!(
                    f,
                    "received frame after finish on stream {}",
                    stream_id.value()
                )
            }
            Self::ReceiveWindowExceeded(stream_id) => {
                write!(f, "receive window exceeded on stream {}", stream_id.value())
            }
            Self::TooManyPendingStreams => {
                write!(f, "exceeded maximum pending streams awaiting accept")
            }
        }
    }
}

impl std::error::Error for MuxRefusal {}

/// Operating errors encountered while reading, writing, or managing multiplexed streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxFault {
    /// The channel previously encountered a fatal protocol violation and remains closed.
    Refused(MuxRefusal),
    /// The requested stream identifier has not been opened locally or remotely.
    NoSuchStream(StreamId),
    /// Reading was attempted on a stream opened locally as unidirectional.
    NotReadable(StreamId),
    /// Writing was attempted on a stream opened by the peer as unidirectional.
    NotWritable(StreamId),
    /// Writing or finishing was attempted after this side already closed its send half.
    AlreadyFinished(StreamId),
    /// All available stream identifiers in this side's residue space were allocated.
    StreamIdsExhausted,
    /// The specified link record bound cannot accommodate minimal frame headers and payload.
    RecordLimitTooSmall(u32),
    /// Unreachable for writes and finishes because record limits below MIN_RECORD_LIMIT are rejected at construction.
    Encode(MuxError),
}

impl fmt::Display for MuxFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "multiplexer refused: {refusal}"),
            Self::NoSuchStream(stream_id) => {
                write!(f, "no such stream {}", stream_id.value())
            }
            Self::NotReadable(stream_id) => {
                write!(f, "stream {} is not readable", stream_id.value())
            }
            Self::NotWritable(stream_id) => {
                write!(f, "stream {} is not writable", stream_id.value())
            }
            Self::AlreadyFinished(stream_id) => {
                write!(f, "stream {} is already finished", stream_id.value())
            }
            Self::StreamIdsExhausted => write!(f, "stream identifiers exhausted"),
            Self::RecordLimitTooSmall(limit) => {
                write!(
                    f,
                    "record limit {limit} is smaller than minimum {MIN_RECORD_LIMIT}"
                )
            }
            Self::Encode(err) => write!(f, "mux frame encoding failed: {err}"),
        }
    }
}

impl std::error::Error for MuxFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            Self::Encode(err) => Some(err),
            Self::NoSuchStream(_) => None,
            Self::NotReadable(_) => None,
            Self::NotWritable(_) => None,
            Self::AlreadyFinished(_) => None,
            Self::StreamIdsExhausted => None,
            Self::RecordLimitTooSmall(_) => None,
        }
    }
}

/// Result of attempting to read available payload bytes from a stream buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// The count of bytes successfully drained into the destination slice.
    Read(usize),
    /// The peer's finish frame was received and all buffered bytes have been drained.
    Finished,
    /// No undelivered bytes are currently buffered and the peer has not sent finish.
    Pending,
}

#[derive(Debug)]
struct StreamState {
    recv_buf: VecDeque<u8>,
    local_finished: bool,
    peer_finished: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            recv_buf: VecDeque::new(),
            local_finished: false,
            peer_finished: false,
        }
    }
}

/// Performs no I/O, encryption, or waiting: frames are pushed in and pulled out while the caller owns the link.
#[derive(Debug)]
pub struct Multiplexer {
    opener: StreamOpener,
    allocator: StreamAllocator,
    record_limit: u32,
    receive_window: usize,
    streams: BTreeMap<StreamId, StreamState>,
    pending_bidi: VecDeque<StreamId>,
    pending_uni: VecDeque<StreamId>,
    refusal: Option<MuxRefusal>,
}

impl Multiplexer {
    /// Constructs a multiplexer where frame_size bounds plane frames and sizes receive windows while record_limit bounds wire records.
    pub fn new(opener: StreamOpener, frame_size: u32, record_limit: u32) -> Result<Self, MuxFault> {
        if record_limit < MIN_RECORD_LIMIT {
            return Err(MuxFault::RecordLimitTooSmall(record_limit));
        }
        let receive_window = RECEIVE_WINDOW_FRAMES.saturating_mul(frame_size as usize);
        Ok(Self {
            opener,
            allocator: StreamAllocator::new(opener),
            record_limit,
            receive_window,
            streams: BTreeMap::new(),
            pending_bidi: VecDeque::new(),
            pending_uni: VecDeque::new(),
            refusal: None,
        })
    }

    /// Allocates without emitting wire frames: the peer never hears of an opened stream until its first frame.
    pub fn open_bidirectional(&mut self) -> Result<StreamId, MuxFault> {
        if let Some(refusal) = self.refusal {
            return Err(MuxFault::Refused(refusal));
        }
        let stream_id = self
            .allocator
            .next_bidirectional()
            .map_err(|_| MuxFault::StreamIdsExhausted)?;
        self.streams.insert(stream_id, StreamState::new());
        Ok(stream_id)
    }

    /// Allocates without emitting wire frames: the peer never hears of an opened stream until its first frame.
    pub fn open_unidirectional(&mut self) -> Result<StreamId, MuxFault> {
        if let Some(refusal) = self.refusal {
            return Err(MuxFault::Refused(refusal));
        }
        let stream_id = self
            .allocator
            .next_unidirectional()
            .map_err(|_| MuxFault::StreamIdsExhausted)?;
        self.streams.insert(stream_id, StreamState::new());
        Ok(stream_id)
    }

    /// Returns link frames to send in order, emitting no frames at all when the input payload is empty.
    pub fn write(&mut self, stream: StreamId, bytes: &[u8]) -> Result<Vec<Vec<u8>>, MuxFault> {
        if let Some(refusal) = self.refusal {
            return Err(MuxFault::Refused(refusal));
        }
        let stream_state = self
            .streams
            .get(&stream)
            .ok_or(MuxFault::NoSuchStream(stream))?;
        if stream.opened_by() != self.opener && !stream.is_bidirectional() {
            return Err(MuxFault::NotWritable(stream));
        }
        if stream_state.local_finished {
            return Err(MuxFault::AlreadyFinished(stream));
        }
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let chunk_size = max_mux_payload(self.record_limit);
        let mut frames = Vec::new();
        for chunk in bytes.chunks(chunk_size) {
            let frame = encode_mux_frame(MuxKind::Data, stream, chunk, self.record_limit)
                .map_err(MuxFault::Encode)?;
            frames.push(frame);
        }
        Ok(frames)
    }

    /// Emits the terminal finish frame for a stream's local send half.
    pub fn finish(&mut self, stream: StreamId) -> Result<Vec<u8>, MuxFault> {
        if let Some(refusal) = self.refusal {
            return Err(MuxFault::Refused(refusal));
        }
        let stream_state = self
            .streams
            .get_mut(&stream)
            .ok_or(MuxFault::NoSuchStream(stream))?;
        if stream.opened_by() != self.opener && !stream.is_bidirectional() {
            return Err(MuxFault::NotWritable(stream));
        }
        if stream_state.local_finished {
            return Err(MuxFault::AlreadyFinished(stream));
        }
        stream_state.local_finished = true;
        encode_mux_frame(MuxKind::Fin, stream, &[], self.record_limit).map_err(MuxFault::Encode)
    }

    /// The only method a peer's bytes reach, making it where every refusal in docs/04 is decided.
    /// Valid frames advance stream state or enqueue payloads; any violation latches a fatal refusal.
    pub fn on_frame(&mut self, frame: &MuxFrame) -> Result<(), MuxRefusal> {
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }

        let stream_id = frame.stream_id();
        let stream_state = match self.streams.entry(stream_id) {
            Entry::Occupied(entry) => {
                if stream_id.opened_by() == self.opener && !stream_id.is_bidirectional() {
                    let refusal = MuxRefusal::WroteToOurUnidirectionalStream(stream_id);
                    self.refusal = Some(refusal);
                    return Err(refusal);
                }
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                if stream_id.opened_by() == self.opener {
                    let refusal = MuxRefusal::PeerAllocatedInOurSpace(stream_id);
                    self.refusal = Some(refusal);
                    return Err(refusal);
                }
                let pending_count = self
                    .pending_bidi
                    .len()
                    .saturating_add(self.pending_uni.len());
                if pending_count >= MAX_PENDING_STREAMS {
                    let refusal = MuxRefusal::TooManyPendingStreams;
                    self.refusal = Some(refusal);
                    return Err(refusal);
                }
                if stream_id.is_bidirectional() {
                    self.pending_bidi.push_back(stream_id);
                } else {
                    self.pending_uni.push_back(stream_id);
                }
                entry.insert(StreamState::new())
            }
        };

        if stream_state.peer_finished {
            let refusal = MuxRefusal::FrameAfterFin(stream_id);
            self.refusal = Some(refusal);
            return Err(refusal);
        }

        match frame.kind() {
            MuxKind::Data => {
                let new_len = stream_state
                    .recv_buf
                    .len()
                    .saturating_add(frame.payload().len());
                if new_len > self.receive_window {
                    let refusal = MuxRefusal::ReceiveWindowExceeded(stream_id);
                    self.refusal = Some(refusal);
                    return Err(refusal);
                }
                stream_state.recv_buf.extend(frame.payload());
            }
            MuxKind::Fin => {
                stream_state.peer_finished = true;
            }
        }

        Ok(())
    }

    /// Distinguishes awaiting peer bytes from end-of-stream on an empty buffer, which a byte count cannot distinguish.
    pub fn read(&mut self, stream: StreamId, buf: &mut [u8]) -> Result<ReadOutcome, MuxFault> {
        if let Some(refusal) = self.refusal {
            return Err(MuxFault::Refused(refusal));
        }
        let stream_state = self
            .streams
            .get_mut(&stream)
            .ok_or(MuxFault::NoSuchStream(stream))?;
        if stream.opened_by() == self.opener && !stream.is_bidirectional() {
            return Err(MuxFault::NotReadable(stream));
        }
        if !stream_state.recv_buf.is_empty() {
            let to_read = buf.len().min(stream_state.recv_buf.len());
            for (dest, byte) in buf[..to_read]
                .iter_mut()
                .zip(stream_state.recv_buf.drain(..to_read))
            {
                *dest = byte;
            }
            return Ok(ReadOutcome::Read(to_read));
        }
        if stream_state.peer_finished {
            Ok(ReadOutcome::Finished)
        } else {
            Ok(ReadOutcome::Pending)
        }
    }

    /// Returns None for both an empty queue and a closed channel; caller inspects refusal() to distinguish them.
    pub fn accept_bidirectional(&mut self) -> Option<StreamId> {
        if self.refusal.is_some() {
            return None;
        }
        self.pending_bidi.pop_front()
    }

    /// Returns None for both an empty queue and a closed channel; caller inspects refusal() to distinguish them.
    pub fn accept_unidirectional(&mut self) -> Option<StreamId> {
        if self.refusal.is_some() {
            return None;
        }
        self.pending_uni.pop_front()
    }

    /// Returns the recorded fatal refusal if the channel was closed by a protocol violation.
    pub fn refusal(&self) -> Option<MuxRefusal> {
        self.refusal
    }
}

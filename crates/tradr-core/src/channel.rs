//! Layer 1's secure-channel abstraction (docs/03, docs/04). No transport
//! implementation lives here: `direct-quic`, `relay`, `ble-gatt` and any
//! later transport belong to Layer 3. Encryption and multiplexing already
//! happened by the time a `SecureChannel` exists (QUIC's own TLS 1.3, or
//! Noise_IK around a raw stream), and nothing above this layer is told which.

use std::fmt;
use std::time::Duration;

use crate::device_id::DeviceId;
use crate::future::BoxFuture;

/// A transport's identity: an opaque compile-time token, not a closed set.
/// Change Drill D10 budgets one registration per new transport and no
/// drill may reach `tradr-core`; an enum here would make every addition a
/// core change. `&'static str`, not `String`, makes a wire value unable to
/// name one: the name is a constant its own implementation declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportId(&'static str);

impl TransportId {
    /// Builds a `TransportId` from a name owned by the implementation
    /// declaring it.
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Returns the underlying name.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An error from a `SecureChannel` or stream operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// No candidate address for the peer could be reached.
    Unreachable,
    /// The operation exceeded its deadline.
    TimedOut,
    /// The peer refused the connection.
    Rejected,
    /// The peer's key did not match the expected `DeviceId`. A security
    /// event rather than a reachability failure, so a caller must not
    /// retry it the way it would retry `Rejected`.
    AuthenticationFailed,
    /// The channel or stream is already closed.
    Closed,
    /// The underlying I/O failed.
    Io(std::io::ErrorKind),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable => write!(f, "no candidate address could be reached"),
            Self::TimedOut => write!(f, "the operation exceeded its deadline"),
            Self::Rejected => write!(f, "the peer refused the connection"),
            Self::AuthenticationFailed => {
                write!(f, "the peer's key did not match the expected device id")
            }
            Self::Closed => write!(f, "the channel or stream is already closed"),
            Self::Io(kind) => write!(f, "transport error: {kind}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// One direction of a multiplexed stream, opened for writing.
pub trait SendStream: Send {
    /// Writes `buf` in full; a short write is never reported as success.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>>;

    /// Closes the send half. No further write is valid once this succeeds.
    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>>;
}

/// One direction of a multiplexed stream, opened for reading.
pub trait RecvStream: Send {
    /// Reads into `buf`, returning the byte count read; `Ok(0)` means the
    /// peer has finished writing.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>>;
}

// Named so `open_bi`/`accept_bi`'s signature stays under clippy's
// complexity threshold; the type itself is unchanged from the Work Order.
type BiStreams = (Box<dyn SendStream>, Box<dyn RecvStream>);

/// A mutually authenticated, forward-secret, multiplexed channel to one
/// peer (docs/03's "A transport delivers an already-secure channel"). QUIC
/// paths get this from TLS 1.3 against the pinned Device Key; `relay` and
/// `ble-gatt` wrap a raw stream in Noise_IK, multiplexing in-band with a
/// `stream_id` frame. Layer 1 asks for a stream and gets one either way.
pub trait SecureChannel: Send + Sync {
    /// The device at the other end. Mutual authentication has already
    /// happened by the time a channel exists, so this cannot fail: it
    /// names the device, not the account, which is established separately
    /// by the Attestation exchange in `Hello`.
    fn peer(&self) -> DeviceId;

    /// Which transport produced this channel.
    fn transport(&self) -> TransportId;

    /// The current round-trip estimate. A method rather than a value fixed
    /// at connect time, since docs/03's Phase 5 re-evaluates a path
    /// mid-transfer and scores it against this.
    fn rtt(&self) -> Duration;

    /// The largest frame this side will **receive** on this channel: its
    /// own ceiling, advertised to the peer in `HelloAck` and enforced on
    /// decode (docs/04). Sending is bounded by the peer's advertised value
    /// instead. Reported by the channel rather than looked up from a
    /// per-transport table in the core, per docs/03's "What the core knows".
    fn max_frame_size(&self) -> u32;

    /// Opens a bidirectional stream, for the Browse plane's per-request
    /// exchange (docs/04).
    fn open_bi(&self) -> BoxFuture<'_, Result<BiStreams, TransportError>>;

    /// Opens a unidirectional stream, for the Data plane's per-Item stream
    /// that the receiver pulls chunks over (ADR-0007).
    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>>;

    /// Accepts a bidirectional stream the peer opened.
    fn accept_bi(&self) -> BoxFuture<'_, Result<BiStreams, TransportError>>;

    /// Accepts a unidirectional stream the peer opened.
    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>>;

    /// Closes the channel and every stream on it.
    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>>;
}

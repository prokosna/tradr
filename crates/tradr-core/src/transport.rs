//! Layer 1's transport abstraction (docs/03, "What the core knows about a
//! transport"). No implementation lives here: `direct-quic`, `relay` and
//! `ble-gatt` belong to Layer 3. Path selection races every candidate at
//! once (docs/03, "Path selection"), so `Transport` must be dyn compatible:
//! `tradr-transport` holds a heterogeneous `Vec<Box<dyn Transport>>`.

use std::fmt;

use crate::channel::{SecureChannel, TransportError, TransportId};
use crate::device_id::DeviceId;
use crate::future::BoxFuture;
use crate::key_store::PublicIdentity;

/// One address a peer might be reachable at, paired with the transport
/// that produced it. The address is opaque to the core: `192.168.1.42:51820`,
/// `relay://brokr.example/x` and `handle:0x0042` share no structure, so
/// carrying the `TransportId` alongside is how Phase 3 hands each
/// candidate to the transport that can use it, without parsing any of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Candidate {
    transport: TransportId,
    address: String,
}

/// An error constructing a `Candidate` from an address string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateError {
    /// The address was empty.
    Empty,
    /// The address contained a control character.
    ControlCharacter(char),
}

impl fmt::Display for CandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "candidate address is empty"),
            Self::ControlCharacter(c) => {
                write!(f, "candidate address contains control character {c:?}")
            }
        }
    }
}

impl std::error::Error for CandidateError {}

impl Candidate {
    /// Validates `address` against docs/03's "Opaque is not unchecked":
    /// reject empty, reject a control character, check nothing else. Pairs
    /// it with the transport that produced it; syntax beyond that is each
    /// transport's own concern, checked again at `connect`.
    pub fn new(transport: TransportId, address: &str) -> Result<Self, CandidateError> {
        if address.is_empty() {
            return Err(CandidateError::Empty);
        }
        if let Some(c) = address.chars().find(|c| c.is_control()) {
            return Err(CandidateError::ControlCharacter(c));
        }

        Ok(Self {
            transport,
            address: address.to_string(),
        })
    }

    /// The transport that produced this candidate and that alone knows
    /// how to dial it.
    pub fn transport(&self) -> TransportId {
        self.transport
    }

    /// The opaque address, exactly as given to `new`.
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// What the dialling side already knows about the device it is reaching
/// for, passed to `Transport::connect` (docs/03, "What a transport is
/// told about the peer it is dialling"): the three states of identity
/// knowledge this design has. `#[non_exhaustive]` keeps a later addition
/// inside Change Drill D10, a variant rather than a change to this trait.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerExpectation {
    /// No prior `DeviceId` to compare against: a Static Peer's first
    /// connection, whose entry is empty until that connection fills it in.
    /// The peer still proves possession of the key it presents; only the
    /// comparison against a prior expectation is absent.
    Unpinned,
    /// Refuse unless the key the peer proves possession of derives
    /// exactly this `DeviceId`.
    Device(DeviceId),
    /// As `Device`, keyed by the full identity, and additionally the
    /// agreement key `Noise_IK` needs before its first message.
    Identity(PublicIdentity),
}

impl PeerExpectation {
    /// The `DeviceId` this expectation names, or `None` when there is no
    /// prior expectation to compare against. `None` never means a peer
    /// may be accepted unauthenticated: the peer still proves possession
    /// of the key it presents in every case.
    pub fn device_id(&self) -> Option<DeviceId> {
        match self {
            Self::Unpinned => None,
            Self::Device(id) => Some(*id),
            Self::Identity(identity) => Some(identity.device_id()),
        }
    }
}

/// The listening side of a `Transport`, accepting channels a peer opens.
/// A device receives as well as sends (docs/03, "Android listening and
/// wake-up"), so this cannot wait for a later milestone.
pub trait Incoming: Send {
    /// Accepts the next incoming channel. Takes `&mut self` because
    /// accepting mutates a queue, unlike `SecureChannel`'s methods, which
    /// several tasks may share concurrently through `&self`.
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>>;
}

/// One way of reaching a peer: `direct-quic`, `relay`, `ble-gatt`, and any
/// later addition (Change Drill D10). Dyn compatible so path selection can
/// hold a heterogeneous set and race every candidate at once, rather than
/// picking one transport ahead of time (docs/03, "Path selection").
pub trait Transport: Send + Sync {
    /// This transport's identity, compared and displayed but never
    /// enumerated by the core (docs/03, "What the core knows about a
    /// transport").
    fn id(&self) -> TransportId;

    /// Dials `candidate`, checking its syntax beyond the core's non-empty,
    /// control-character-free pass, and returns an already-secure channel
    /// (docs/03). The peer must prove possession of the key it presents in
    /// every case; where `expect.device_id()` is `Some` and the proven key
    /// derives another, refuse with `TransportError::AuthenticationFailed`.
    fn connect<'a>(
        &'a self,
        candidate: &'a Candidate,
        expect: &'a PeerExpectation,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>>;

    /// Begins listening for incoming channels on this transport.
    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>>;
}

//! Layer 1's discovery abstraction (docs/03, "Discovery", "What a
//! Discovery Source reports", "The peer list", and "Capability flags").
//! No source implementation lives here: mDNS, BLE, Static Peer and the
//! Brokr presence registry belong to `tradr-discovery`. `PeerList` merging
//! is pure -- no clock, socket, or executor -- so it sits here, not there.

use std::collections::BTreeMap;
use std::fmt;

use crate::device_id::DeviceId;
use crate::future::BoxFuture;
use crate::transport::Candidate;

/// The most bytes an `ObservationKey` may occupy.
pub const OBSERVATION_KEY_MAX_LEN: usize = 128;

/// The most bytes a `DisplayName` may occupy: docs/03's mDNS TXT `n`,
/// 32 bytes maximum.
pub const DISPLAY_NAME_MAX_LEN: usize = 32;

/// The reasons a bounded, printable string is refused: shared by
/// `ObservationKey` and `DisplayName`, which check the same two rules
/// against different limits and hand back different public error types.
enum BoundedStringError {
    Empty,
    TooLong(usize),
    ControlCharacter(char),
}

// The one place `is_empty`, byte length, and `is_control` are checked, so
// `ObservationKey::new` and `DisplayName::new` cannot drift apart on what
// "the same rule and reasoning as Candidate::new" means in practice.
fn validate_bounded_string(s: &str, max_len: usize) -> Result<(), BoundedStringError> {
    if s.is_empty() {
        return Err(BoundedStringError::Empty);
    }
    if s.len() > max_len {
        return Err(BoundedStringError::TooLong(s.len()));
    }
    if let Some(c) = s.chars().find(|c| c.is_control()) {
        return Err(BoundedStringError::ControlCharacter(c));
    }
    Ok(())
}

/// A `DiscoverySource`'s identity: an opaque compile-time token, the same
/// construction and reasoning as `TransportId`. A wire value cannot name
/// one; the name is a constant its own implementation declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId(&'static str);

impl SourceId {
    /// Builds a `SourceId` from a name owned by the implementation
    /// declaring it.
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Returns the underlying name.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A key meaningful only to the source that produced it (docs/03, "What a
/// Discovery Source reports"). Two sources may use the same key and mean
/// different devices, which is why an `ObservationKey` alone never
/// identifies a peer -- only an `ObservationId`, paired with a `SourceId`,
/// does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObservationKey(String);

/// An error constructing an `ObservationKey` from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationKeyError {
    /// The input was empty.
    Empty,
    /// The input was longer than `OBSERVATION_KEY_MAX_LEN` bytes.
    TooLong(usize),
    /// The input contained a control character.
    ControlCharacter(char),
}

impl fmt::Display for ObservationKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "observation key is empty"),
            Self::TooLong(len) => write!(
                f,
                "observation key must be at most {OBSERVATION_KEY_MAX_LEN} bytes, got {len}"
            ),
            Self::ControlCharacter(c) => {
                write!(f, "observation key contains control character {c:?}")
            }
        }
    }
}

impl std::error::Error for ObservationKeyError {}

impl ObservationKey {
    /// Validates `s` against the same two rules as `Candidate::new`, plus
    /// the length bound `OBSERVATION_KEY_MAX_LEN`: reject empty, reject a
    /// control character, reject over-length. Checks nothing else.
    pub fn new(s: &str) -> Result<Self, ObservationKeyError> {
        validate_bounded_string(s, OBSERVATION_KEY_MAX_LEN).map_err(|e| match e {
            BoundedStringError::Empty => ObservationKeyError::Empty,
            BoundedStringError::TooLong(len) => ObservationKeyError::TooLong(len),
            BoundedStringError::ControlCharacter(c) => ObservationKeyError::ControlCharacter(c),
        })?;
        Ok(Self(s.to_string()))
    }

    /// The key exactly as given to `new`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObservationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What one `DiscoverySource` calls one peer: the source plus a key
/// meaningful only to it (docs/03, "What a Discovery Source reports").
/// Ordered by `(source, key)`, which is also the order `Peer::
/// observations` presents observations in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObservationId {
    source: SourceId,
    key: ObservationKey,
}

impl ObservationId {
    /// Builds an `ObservationId` from the source that produced it and the
    /// key that source uses for it.
    pub fn new(source: SourceId, key: ObservationKey) -> Self {
        Self { source, key }
    }

    /// The source that produced this observation.
    pub fn source(&self) -> SourceId {
        self.source
    }

    /// The key, meaningful only to `source`.
    pub fn key(&self) -> &ObservationKey {
        &self.key
    }
}

impl fmt::Display for ObservationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.source, self.key)
    }
}

/// The name a peer publishes about itself: docs/03's mDNS TXT `n`, at
/// most `DISPLAY_NAME_MAX_LEN` bytes. Validated the way a candidate
/// address is, never parsed (docs/03, "What a Discovery Source reports").
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DisplayName(String);

/// An error constructing a `DisplayName` from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayNameError {
    /// The input was empty.
    Empty,
    /// The input was longer than `DISPLAY_NAME_MAX_LEN` bytes.
    TooLong(usize),
    /// The input contained a control character.
    ControlCharacter(char),
}

impl fmt::Display for DisplayNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "display name is empty"),
            Self::TooLong(len) => write!(
                f,
                "display name must be at most {DISPLAY_NAME_MAX_LEN} bytes, got {len}"
            ),
            Self::ControlCharacter(c) => {
                write!(f, "display name contains control character {c:?}")
            }
        }
    }
}

impl std::error::Error for DisplayNameError {}

impl DisplayName {
    /// Validates `s` against the same two rules as `Candidate::new`, plus
    /// the length bound `DISPLAY_NAME_MAX_LEN`, measured in bytes since
    /// that is what the mDNS TXT record's own limit is measured in.
    pub fn new(s: &str) -> Result<Self, DisplayNameError> {
        validate_bounded_string(s, DISPLAY_NAME_MAX_LEN).map_err(|e| match e {
            BoundedStringError::Empty => DisplayNameError::Empty,
            BoundedStringError::TooLong(len) => DisplayNameError::TooLong(len),
            BoundedStringError::ControlCharacter(c) => DisplayNameError::ControlCharacter(c),
        })?;
        Ok(Self(s.to_string()))
    }

    /// The name exactly as given to `new`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// docs/03's capability bitmask, carried in advertisements and in `Hello`
/// so each side knows what the other can do. Bits 7-15 are reserved for a
/// later transport (Change Drill D10) and have no named constant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capabilities(u16);

impl Capabilities {
    /// Bit 0: supports `direct-quic`.
    pub const DIRECT_QUIC: Self = Self(1 << 0);
    /// Bit 1: supports `wifi-direct`.
    pub const WIFI_DIRECT: Self = Self(1 << 1);
    /// Bit 2: supports `ble-gatt` payloads.
    pub const BLE_GATT: Self = Self(1 << 2);
    /// Bit 3: supports `relay`, meaning a Brokr is registered.
    pub const RELAY: Self = Self(1 << 3);
    /// Bit 4: accepts Share browsing.
    pub const ACCEPTS_BROWSING: Self = Self(1 << 4);
    /// Bit 5: has a writable Share.
    pub const WRITABLE_SHARE: Self = Self(1 << 5);
    /// Bit 6: currently on a metered link.
    pub const METERED: Self = Self(1 << 6);

    /// Builds a `Capabilities` from a raw bitmask, e.g. as carried on the
    /// wire in an mDNS TXT `c` value or a `Hello`.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw bitmask.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// True if every bit set in `other` is also set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// No bit set.
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// What one `DiscoverySource` currently knows about one peer (docs/03,
/// "What a Discovery Source reports"). Built with `new` plus the `with_*`
/// builders, since most fields are unknown until the source learns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerObservation {
    id: ObservationId,
    device_id: Option<DeviceId>,
    candidates: Vec<Candidate>,
    display_name: Option<DisplayName>,
    capabilities: Capabilities,
}

impl PeerObservation {
    /// Builds a `PeerObservation` from its id and candidates, canonicalising
    /// `candidates` by sorting on `(transport, address)` and deduplicating
    /// so that two observations built from the same candidates in a
    /// different order are equal. An empty list is valid: a BLE scanner
    /// sees a peer before it has any address for it.
    pub fn new(id: ObservationId, mut candidates: Vec<Candidate>) -> Self {
        candidates.sort_by(|a, b| (a.transport(), a.address()).cmp(&(b.transport(), b.address())));
        candidates.dedup();
        Self {
            id,
            device_id: None,
            candidates,
            display_name: None,
            capabilities: Capabilities::empty(),
        }
    }

    /// Records the Device ID this source now knows for the peer.
    pub fn with_device_id(mut self, device_id: DeviceId) -> Self {
        self.device_id = Some(device_id);
        self
    }

    /// Records the name this peer publishes about itself.
    pub fn with_display_name(mut self, display_name: DisplayName) -> Self {
        self.display_name = Some(display_name);
        self
    }

    /// Records the capability bitmask this source read for the peer.
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// The id this observation is stored under.
    pub fn id(&self) -> &ObservationId {
        &self.id
    }

    /// The Device ID, once this source knows it.
    pub fn device_id(&self) -> Option<DeviceId> {
        self.device_id
    }

    /// Every address this source currently offers for the peer, sorted
    /// by `(transport, address)` and deduplicated.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// The name the peer publishes, if this source has read it.
    pub fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    /// The capability bitmask this source read for the peer.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
}

/// What a `DiscoverySource` reports about one observation (docs/03, "What
/// a Discovery Source reports"). Continuous rather than a snapshot: a
/// source is always reporting a change, never handing back a full list.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// This source can currently see this peer, and here is everything it
    /// knows. Replaces any earlier observation carrying the same
    /// `ObservationId` rather than adding a second one.
    Observed(PeerObservation),
    /// This source can no longer see that observation. Says nothing about
    /// the other three, which may still see the same device.
    Lost(ObservationId),
}

/// An error from a `DiscoverySource`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The source is closed and will produce no further events.
    Closed,
    /// The underlying I/O failed.
    Io(std::io::ErrorKind),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "the discovery source is closed"),
            Self::Io(kind) => write!(f, "discovery source error: {kind}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// One way peers are found: mDNS, BLE, Static Peer, or a Brokr's presence
/// registry (docs/03, "Discovery"). Four run at once and merge into one
/// `PeerList`, so this must be dyn compatible -- `next_event` returns
/// `BoxFuture` rather than being an `async fn` (ADR-0013).
pub trait DiscoverySource: Send {
    /// This source's identity, compared but never enumerated by the core.
    fn id(&self) -> SourceId;

    /// Waits for the next event this source has to report. Takes
    /// `&mut self` because a source tracks its own position in whatever
    /// stream of changes it is reading, unlike `SecureChannel`'s methods.
    fn next_event(&mut self) -> BoxFuture<'_, Result<DiscoveryEvent, DiscoveryError>>;
}

/// An error from `PeerList::apply`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerListError {
    /// The event's `ObservationId` named a source other than the one that
    /// produced it (docs/03, "The peer list"): a Brokr able to emit an
    /// observation labelled `mdns` could replace a LAN peer's candidates
    /// with addresses of its own choosing.
    SourceMismatch {
        /// The source the event's `ObservationId` claimed.
        claimed: SourceId,
        /// The source that actually produced the event.
        actual: SourceId,
    },
}

impl fmt::Display for PeerListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMismatch { claimed, actual } => write!(
                f,
                "event claimed source {claimed} but was produced by {actual}"
            ),
        }
    }
}

impl std::error::Error for PeerListError {}

/// Every `PeerObservation` from every source, merged (docs/03, "The peer
/// list"). Observations sharing a Device ID are one `Peer`; an observation
/// with none is a `Peer` on its own. Backed by a `BTreeMap` rather than a
/// `HashMap` so `peers()` never depends on hash iteration order.
#[derive(Debug, Clone, Default)]
pub struct PeerList {
    observations: BTreeMap<ObservationId, PeerObservation>,
}

impl PeerList {
    /// Builds an empty `PeerList`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one event from `source`, in three steps (docs/03, "The peer
    /// list"): refuse an event whose `ObservationId` names another source;
    /// otherwise store an `Observed` observation, replacing any earlier one
    /// under the same id; or remove the observation a `Lost` names, which
    /// is `Ok(())` even when nothing was stored under it.
    pub fn apply(&mut self, source: SourceId, event: DiscoveryEvent) -> Result<(), PeerListError> {
        let claimed = match &event {
            DiscoveryEvent::Observed(observation) => observation.id().source(),
            DiscoveryEvent::Lost(id) => id.source(),
        };
        if claimed != source {
            return Err(PeerListError::SourceMismatch {
                claimed,
                actual: source,
            });
        }

        match event {
            DiscoveryEvent::Observed(observation) => {
                self.observations
                    .insert(observation.id().clone(), observation);
            }
            DiscoveryEvent::Lost(id) => {
                self.observations.remove(&id);
            }
        }
        Ok(())
    }

    /// Every peer the list currently holds: every identified peer first,
    /// ascending by `DeviceId`, then every unidentified peer, ascending by
    /// the `ObservationId` of its single observation (docs/03, "The peer
    /// list"). Iterating `observations`, itself ordered by `ObservationId`,
    /// keeps both groups in that order without a further sort.
    pub fn peers(&self) -> Vec<Peer> {
        let mut identified: BTreeMap<DeviceId, Vec<PeerObservation>> = BTreeMap::new();
        let mut unidentified: Vec<Peer> = Vec::new();

        for observation in self.observations.values() {
            match observation.device_id() {
                Some(device_id) => identified
                    .entry(device_id)
                    .or_default()
                    .push(observation.clone()),
                None => unidentified.push(Peer {
                    device_id: None,
                    observations: vec![observation.clone()],
                }),
            }
        }

        let mut peers: Vec<Peer> = identified
            .into_iter()
            .map(|(device_id, observations)| Peer {
                device_id: Some(device_id),
                observations,
            })
            .collect();
        peers.extend(unidentified);
        peers
    }

    /// The identified peer for `device`, or `None`. Never returns an
    /// unidentified peer.
    pub fn peer(&self, device: DeviceId) -> Option<Peer> {
        let observations: Vec<PeerObservation> = self
            .observations
            .values()
            .filter(|observation| observation.device_id() == Some(device))
            .cloned()
            .collect();

        if observations.is_empty() {
            None
        } else {
            Some(Peer {
                device_id: Some(device),
                observations,
            })
        }
    }

    /// How many observations the list currently holds, across every peer.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

/// One peer as the merged view of every observation that named its
/// `DeviceId`, or the single observation of a peer nothing has identified
/// yet (docs/03, "The peer list"). Reports no merged name and no merged
/// capability set -- a caller reads `observations()` and owns that choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    device_id: Option<DeviceId>,
    observations: Vec<PeerObservation>,
}

impl Peer {
    /// The Device ID every observation here agrees on, or `None` when
    /// nothing has identified this peer yet.
    pub fn device_id(&self) -> Option<DeviceId> {
        self.device_id
    }

    /// The union of every observation's candidates, deduplicated and
    /// sorted by `(transport, address)`. The order is not a preference:
    /// path selection races every candidate at once, and a fixed order is
    /// here so the same inputs produce the same list twice.
    pub fn candidates(&self) -> Vec<Candidate> {
        let mut all: Vec<Candidate> = self
            .observations
            .iter()
            .flat_map(|observation| observation.candidates().iter().cloned())
            .collect();
        all.sort_by(|a, b| (a.transport(), a.address()).cmp(&(b.transport(), b.address())));
        all.dedup();
        all
    }

    /// Every observation this peer was built from, ordered by
    /// `ObservationId`: `(source, key)`, ascending.
    pub fn observations(&self) -> &[PeerObservation] {
        &self.observations
    }
}

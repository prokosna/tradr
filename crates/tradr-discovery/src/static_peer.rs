//! The Static Peer registry and its `DiscoverySource` (docs/03, "3. Static
//! Peer -- overlay networks and fixed IPs, Tier 1"). A Critical Module
//! (CLAUDE.md section 6): the registry alone decides what `PeerExpectation`
//! a Static Peer connection compares its proven key against, and handing
//! back `Unpinned` for a pinned entry authenticates a hijacked address.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tradr_core::{
    BoxFuture, Candidate, CandidateError, DeviceId, DiscoveryError, DiscoveryEvent,
    DiscoverySource, DisplayName, ObservationId, ObservationKey, PeerExpectation, PeerObservation,
    Rng, RngError, SourceId, TransportId,
};

/// This source's identity.
pub const STATIC_PEER_SOURCE_ID: SourceId = SourceId::new("static-peer");

/// docs/03's default port, used whenever an endpoint names none: below
/// Linux's ephemeral range so the kernel never hands it to another
/// process, and deliberately not WireGuard's 51820 (docs/03, "The default
/// port, and why it is not 51820").
pub const STATIC_PEER_DEFAULT_PORT: u16 = 21820;

/// The transport every candidate this source produces names. Declared
/// locally rather than imported from `tradr-transport`, which this crate
/// may not depend on -- `TransportId` is an opaque token precisely so both
/// sides can name the same string.
const DIRECT_QUIC: TransportId = TransportId::new("direct-quic");

/// How many hex characters a `StaticPeerId` occupies.
const STATIC_PEER_ID_HEX_LEN: usize = 32;

/// How many bytes `StaticPeerId::generate` draws from its `Rng`.
const STATIC_PEER_ID_BYTES: usize = 16;

/// An entry's own identity, and the `ObservationKey` its source reports it
/// under (docs/03, "What a Static Peer entry is keyed by"): 16 random
/// bytes rendered as 32 lowercase hex characters. Neither the label nor
/// the endpoint list can serve as this key, since both are editable and
/// neither names a single value to be keyed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPeerId(String);

impl StaticPeerId {
    /// Generates a fresh id from `STATIC_PEER_ID_BYTES` bytes drawn
    /// through `rng`.
    pub fn generate(rng: &dyn Rng) -> Result<Self, RngError> {
        let mut bytes = [0u8; STATIC_PEER_ID_BYTES];
        rng.fill_bytes(&mut bytes)?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }

    /// Validates `s` as exactly `STATIC_PEER_ID_HEX_LEN` lowercase hex
    /// characters, refusing anything else.
    pub fn new(s: &str) -> Result<Self, StaticPeerError> {
        let is_valid = s.len() == STATIC_PEER_ID_HEX_LEN
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if is_valid {
            Ok(Self(s.to_string()))
        } else {
            Err(StaticPeerError::Malformed(format!(
                "{s:?} is not {STATIC_PEER_ID_HEX_LEN} lowercase hex characters"
            )))
        }
    }

    /// The id exactly as generated or validated.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StaticPeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One entry the user registered by hand (docs/03, "3. Static Peer").
#[derive(Debug, Clone)]
pub struct StaticPeer {
    id: StaticPeerId,
    label: Option<String>,
    endpoints: Vec<String>,
    expect_device_id: Option<DeviceId>,
}

impl StaticPeer {
    /// This entry's own identity.
    pub fn id(&self) -> &StaticPeerId {
        &self.id
    }

    /// The user-supplied label, if any. Unlike `PeerObservation::
    /// display_name`, this is never dropped for being over-length -- it
    /// only decorates the observation it feeds, and only there does DCR-053
    /// apply.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Every endpoint this entry names, normalised and in the order given
    /// (docs/03, "A missing port is filled in with the default before the
    /// endpoint becomes a candidate").
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// The `DeviceId` the first connection pinned, or `None` before that
    /// has happened.
    pub fn expect_device_id(&self) -> Option<DeviceId> {
        self.expect_device_id
    }

    // Builds the record this entry serializes to on disk.
    fn to_record(&self) -> StaticPeerRecord {
        StaticPeerRecord {
            id: self.id.as_str().to_string(),
            label: self.label.clone(),
            endpoints: self.endpoints.clone(),
            expect_device_id: self.expect_device_id.map(|d| d.to_string()),
        }
    }

    // Rebuilds an entry from its on-disk record. Every field must already
    // be the shape this module ever writes -- `id`, `expect_device_id`,
    // and now each endpoint too -- or this is a malformed file, not a
    // silently-skipped record, per docs/03's "A discovery source must
    // emit an address its transport can parse".
    fn from_record(record: StaticPeerRecord) -> Result<Self, StaticPeerError> {
        let id = StaticPeerId::new(&record.id)?;
        let expect_device_id = match record.expect_device_id {
            Some(hex) => Some(
                hex.parse::<DeviceId>()
                    .map_err(|source| StaticPeerError::Malformed(source.to_string()))?,
            ),
            None => None,
        };

        let mut endpoints = Vec::with_capacity(record.endpoints.len());
        for raw in &record.endpoints {
            let address = normalize_endpoint(raw);
            Candidate::new(DIRECT_QUIC, &address)
                .map_err(|source| StaticPeerError::Malformed(source.to_string()))?;
            endpoints.push(address);
        }

        Ok(Self {
            id,
            label: record.label,
            endpoints,
            expect_device_id,
        })
    }
}

/// The on-disk shape of one `StaticPeer` (docs/03, "Where the set is
/// kept"). Kept distinct from `StaticPeer` itself so a field this module
/// has already validated -- an id, a Device ID -- is never assumed valid
/// again on the way back off disk.
#[derive(Debug, Serialize, Deserialize)]
struct StaticPeerRecord {
    id: String,
    label: Option<String>,
    endpoints: Vec<String>,
    expect_device_id: Option<String>,
}

/// The whole file `static-peers.json` holds.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StaticPeerFile {
    entries: Vec<StaticPeerRecord>,
}

/// An error from the Static Peer registry.
#[non_exhaustive]
#[derive(Debug)]
pub enum StaticPeerError {
    /// The registry file was present but was not valid JSON in the shape
    /// this module writes, or a field inside it -- an id, a Device ID --
    /// was not a shape this module ever produces. Replacing it with an
    /// empty registry would silently delete every pin the user holds
    /// (docs/03, "Where the set is kept").
    Malformed(String),
    /// `pin` was called on an entry that already holds a `DeviceId`
    /// naming a different device (docs/03, "The pin: what fills it in,
    /// and what may never overwrite it"). There is deliberately no
    /// re-pin operation: the interface cannot tell a rebuilt peer from an
    /// impostor, so the decision is left to the user.
    AlreadyPinned,
    /// `add` was called with no endpoints at all.
    NoEndpoints,
    /// One of the endpoints given to `add` failed `Candidate::new`.
    InvalidEndpoint(CandidateError),
    /// No entry in this registry carries the given id.
    UnknownEntry,
    /// The registry file could not be read or written.
    Io(std::io::Error),
    /// The underlying `Rng` failed while generating a fresh id.
    Rng(RngError),
}

impl fmt::Display for StaticPeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "static peer registry is malformed: {reason}"),
            Self::AlreadyPinned => {
                write!(f, "this entry already pins a different device")
            }
            Self::NoEndpoints => {
                write!(f, "a static peer entry must name at least one endpoint")
            }
            Self::InvalidEndpoint(source) => write!(f, "invalid static peer endpoint: {source}"),
            Self::UnknownEntry => write!(f, "no static peer entry has this id"),
            Self::Io(source) => write!(f, "static peer registry i/o error: {source}"),
            Self::Rng(source) => write!(f, "could not generate a static peer id: {source}"),
        }
    }
}

impl std::error::Error for StaticPeerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEndpoint(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::Rng(source) => Some(source),
            Self::Malformed(_) | Self::AlreadyPinned | Self::NoEndpoints | Self::UnknownEntry => {
                None
            }
        }
    }
}

// Fills in a missing port and nothing else, in docs/03's order: (1) a
// socket address is kept as-is; (2) a bare IP address gets the default
// port, bracketed first when it is IPv6; (3) an endpoint already ending
// in `:` plus digits is kept; (4) everything else gets the default port.
fn normalize_endpoint(raw: &str) -> String {
    if raw.parse::<SocketAddr>().is_ok() {
        return raw.to_string();
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(_) => format!("{raw}:{STATIC_PEER_DEFAULT_PORT}"),
            IpAddr::V6(_) => format!("[{raw}]:{STATIC_PEER_DEFAULT_PORT}"),
        };
    }
    if ends_with_port(raw) {
        return raw.to_string();
    }
    format!("{raw}:{STATIC_PEER_DEFAULT_PORT}")
}

// True when `raw` ends in a colon followed by one or more ASCII digits --
// a name or a bracketed literal that already names a port, which
// `normalize_endpoint`'s first two rules did not already recognise as a
// socket address or a bare IP.
fn ends_with_port(raw: &str) -> bool {
    match raw.rfind(':') {
        Some(index) => {
            let after = &raw[index + 1..];
            !after.is_empty() && after.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

// Builds the `Observed` event a source reports for one entry (docs/03,
// "The source never probes"). Both `add` and `from_record` already refuse
// an endpoint `Candidate::new` refuses, so this is unreachable by
// construction; `filter_map` stays the total shape rather than a fallible
// one for a value that is never actually absent.
fn observed_event(entry: &StaticPeer) -> DiscoveryEvent {
    let candidates: Vec<Candidate> = entry
        .endpoints
        .iter()
        .filter_map(|address| Candidate::new(DIRECT_QUIC, address).ok())
        .collect();

    let id = ObservationId::new(STATIC_PEER_SOURCE_ID, observation_key(&entry.id));
    let mut observation = PeerObservation::new(id, candidates);
    if let Some(device_id) = entry.expect_device_id {
        observation = observation.with_device_id(device_id);
    }
    // DCR-053: a label that only decorates never fails `add`, and a
    // label too long for `DisplayName` is dropped from the observation
    // rather than refusing the entry that carries it.
    if let Some(name) = entry
        .label
        .as_deref()
        .and_then(|label| DisplayName::new(label).ok())
    {
        observation = observation.with_display_name(name);
    }
    DiscoveryEvent::Observed(observation)
}

// Builds the `Lost` event a source reports when an entry is removed.
fn lost_event(id: &StaticPeerId) -> DiscoveryEvent {
    DiscoveryEvent::Lost(ObservationId::new(
        STATIC_PEER_SOURCE_ID,
        observation_key(id),
    ))
}

// A `StaticPeerId` is always `STATIC_PEER_ID_HEX_LEN` lowercase hex
// characters, well inside `OBSERVATION_KEY_MAX_LEN` and free of control
// characters, so it is always a valid `ObservationKey`.
fn observation_key(id: &StaticPeerId) -> ObservationKey {
    ObservationKey::new(id.as_str()).expect("a static peer id is always a valid observation key")
}

/// The Static Peer set: every entry the user registered by hand, backed
/// by `static-peers.json` in the application data directory (docs/03,
/// "Where the set is kept").
pub struct StaticPeerRegistry {
    path: PathBuf,
    entries: Vec<StaticPeer>,
    events: flume::Sender<DiscoveryEvent>,
}

impl StaticPeerRegistry {
    /// Loads the registry at `path`, alongside the `StaticPeerSource` it
    /// reports into. A missing file is an empty registry rather than an
    /// error, which is what a first run looks like; a malformed one is
    /// refused rather than silently replaced, since starting over deletes
    /// every pin the user holds.
    pub fn load(path: &Path) -> Result<(Self, StaticPeerSource), StaticPeerError> {
        let raw = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(StaticPeerError::Io(source)),
        };

        let file: StaticPeerFile = match raw {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|source| StaticPeerError::Malformed(source.to_string()))?,
            None => StaticPeerFile::default(),
        };

        let mut entries = Vec::with_capacity(file.entries.len());
        for record in file.entries {
            entries.push(StaticPeer::from_record(record)?);
        }

        let (events, receiver) = flume::unbounded();
        for entry in &entries {
            events
                .send(observed_event(entry))
                .expect("the receiver this function returns below is still alive");
        }

        let registry = Self {
            path: path.to_path_buf(),
            entries,
            events,
        };
        Ok((registry, StaticPeerSource::new(receiver)))
    }

    /// Every entry this registry currently holds.
    pub fn entries(&self) -> &[StaticPeer] {
        &self.entries
    }

    /// The entry carrying `id`, if this registry has one.
    pub fn entry(&self, id: &StaticPeerId) -> Option<&StaticPeer> {
        self.entries.iter().find(|entry| &entry.id == id)
    }

    /// Registers a new entry with the given label and endpoints,
    /// generating its id through `rng`. Refuses an empty endpoint list,
    /// and refuses any endpoint `Candidate::new` refuses once its port has
    /// been filled in.
    pub fn add(
        &mut self,
        label: Option<&str>,
        endpoints: &[String],
        rng: &dyn Rng,
    ) -> Result<StaticPeerId, StaticPeerError> {
        if endpoints.is_empty() {
            return Err(StaticPeerError::NoEndpoints);
        }

        let mut normalized = Vec::with_capacity(endpoints.len());
        for raw in endpoints {
            let address = normalize_endpoint(raw);
            Candidate::new(DIRECT_QUIC, &address).map_err(StaticPeerError::InvalidEndpoint)?;
            normalized.push(address);
        }

        let id = StaticPeerId::generate(rng).map_err(StaticPeerError::Rng)?;
        let entry = StaticPeer {
            id: id.clone(),
            label: label.map(str::to_string),
            endpoints: normalized,
            expect_device_id: None,
        };

        let mut prospective = self.entries.clone();
        prospective.push(entry.clone());
        self.persist(&prospective)?;

        self.entries = prospective;
        // No observer is not a failure of `add`: the mutation has already
        // been persisted to disk, which is the operation this method
        // promises.
        let _sent = self.events.send(observed_event(&entry));

        Ok(id)
    }

    /// Pins `device` as the `DeviceId` a connection to `id` must prove
    /// possession of. Only ever fills an empty pin (docs/03, "The pin"): a
    /// first pin is accepted, re-pinning the same device changes nothing,
    /// and a differing device is refused and changes nothing.
    pub fn pin(&mut self, id: &StaticPeerId, device: DeviceId) -> Result<(), StaticPeerError> {
        let index = self
            .entries
            .iter()
            .position(|entry| &entry.id == id)
            .ok_or(StaticPeerError::UnknownEntry)?;

        if let Some(existing) = self.entries[index].expect_device_id {
            return if existing == device {
                Ok(())
            } else {
                Err(StaticPeerError::AlreadyPinned)
            };
        }

        let mut prospective = self.entries.clone();
        prospective[index].expect_device_id = Some(device);
        self.persist(&prospective)?;

        self.entries = prospective;
        let _sent = self.events.send(observed_event(&self.entries[index]));

        Ok(())
    }

    /// Removes the entry carrying `id`, along with any pin it held.
    pub fn remove(&mut self, id: &StaticPeerId) -> Result<(), StaticPeerError> {
        let index = self
            .entries
            .iter()
            .position(|entry| &entry.id == id)
            .ok_or(StaticPeerError::UnknownEntry)?;

        let mut prospective = self.entries.clone();
        prospective.remove(index);
        self.persist(&prospective)?;

        self.entries = prospective;
        let _sent = self.events.send(lost_event(id));

        Ok(())
    }

    /// What a connection to `id` must prove possession of: `Unpinned`
    /// before any connection has pinned it, `Device` after one has, or
    /// `None` when this registry holds no such entry at all (docs/03,
    /// "The pin: what fills it in, and what may never overwrite it").
    pub fn expectation(&self, id: &StaticPeerId) -> Option<PeerExpectation> {
        self.entry(id).map(|entry| match entry.expect_device_id {
            Some(device) => PeerExpectation::Device(device),
            None => PeerExpectation::Unpinned,
        })
    }

    // Writes `entries` to `self.path` whole, via a fresh temporary file
    // renamed over the target, so a reader never observes a partial write
    // and a mutation is either fully on disk or not there at all.
    fn persist(&self, entries: &[StaticPeer]) -> Result<(), StaticPeerError> {
        let file = StaticPeerFile {
            entries: entries.iter().map(StaticPeer::to_record).collect(),
        };
        // Every field of `StaticPeerRecord` is already a validated String
        // or an Option of one, none of which serde_json can refuse to
        // serialize.
        let json = serde_json::to_vec_pretty(&file)
            .expect("a StaticPeerFile serializes to json without error");

        let dir = self.path.parent().filter(|dir| !dir.as_os_str().is_empty());
        if let Some(dir) = dir {
            fs::create_dir_all(dir).map_err(StaticPeerError::Io)?;
        }

        let temp_path = temp_path_for(&self.path);
        fs::write(&temp_path, &json).map_err(StaticPeerError::Io)?;
        fs::rename(&temp_path, &self.path).map_err(StaticPeerError::Io)
    }
}

// A temporary path in the same directory as `path`, so the rename that
// follows a successful write is same-filesystem and therefore atomic.
fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

/// A Static Peer `DiscoverySource` over a `flume::Receiver<DiscoveryEvent>`
/// the registry sends into directly -- the same shape `MdnsSource` uses,
/// except this source translates nothing, since the registry already
/// speaks `DiscoveryEvent` (docs/03, "The source never probes").
pub struct StaticPeerSource {
    events: flume::Receiver<DiscoveryEvent>,
}

impl StaticPeerSource {
    fn new(events: flume::Receiver<DiscoveryEvent>) -> Self {
        Self { events }
    }
}

impl DiscoverySource for StaticPeerSource {
    fn id(&self) -> SourceId {
        STATIC_PEER_SOURCE_ID
    }

    fn next_event(&mut self) -> BoxFuture<'_, Result<DiscoveryEvent, DiscoveryError>> {
        Box::pin(async move {
            self.events
                .recv_async()
                .await
                .map_err(|_| DiscoveryError::Closed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `normalize_endpoint` is exercised end-to-end through
    // `tests/static_peer.rs`; these cover the boundary between its rule 2
    // and rule 3 that the integration tests do not aim at directly, since
    // an IPv6 literal with a trailing digit could otherwise fall through
    // to the wrong rule.
    #[test]
    fn a_bare_ipv6_literal_ending_in_a_digit_is_still_recognised_as_an_ip_address() {
        let normalized = normalize_endpoint("fd7a:115c::1");

        assert_eq!(normalized, "[fd7a:115c::1]:21820");
    }

    #[test]
    fn ends_with_port_rejects_a_colon_with_no_digits_after_it() {
        assert!(!ends_with_port("desktop.example:"));
    }
}

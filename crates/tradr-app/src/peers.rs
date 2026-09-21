//! Turning a peer the discovery sources reported into a dial: which
//! candidate can carry the transfer, what the channel is authenticated
//! against, and the pin a Static Peer's first connection writes back
//! (docs/03, "The pin"). It decides nothing about what crosses the
//! channel afterwards.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use tradr_core::{
    Candidate, DeviceId, DiscoveryEvent, DiscoverySource, Peer, PeerExpectation, PeerList,
    SecureChannel,
};
use tradr_discovery::{
    MDNS_SOURCE_ID, MdnsSource, STATIC_PEER_SOURCE_ID, StaticPeerId, StaticPeerRegistry,
    StaticPeerSource,
};
use tradr_transport::selection::{TransferSize, prefilter};
use tradr_transport::set::TransportSet;

/// Discovered peer representation for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's 16-byte Device ID, rendered as hex. Empty when this
    /// peer has not yet been identified -- a Static Peer entry before its
    /// first connection.
    pub device_id: String,
    /// What `send_files`, `list_peer_directory` and `download_file` accept
    /// as `peer_id`: the Device ID hex for an identified peer, or the
    /// `ObservationId` (`<source>/<key>`) for one that is not. A Device ID
    /// hex string contains no `/`, so the two forms never collide.
    pub key: String,
    /// The peer's advertised display name, if present.
    pub display_name: Option<String>,
    /// Available candidate addresses for reaching the peer.
    pub addresses: Vec<String>,
    /// Advertised capability bitmask.
    pub capabilities: u16,
    /// Distinct discovery sources that reported this peer. Plural because
    /// one Device ID seen by two sources is one peer.
    pub sources: Vec<String>,
}

/// One Static Peer entry as exposed to the frontend (docs/03, "3. Static
/// Peer").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticPeerInfo {
    /// This entry's own id, 32 lowercase hex characters.
    pub id: String,
    /// The user-supplied label, if any.
    pub label: Option<String>,
    /// Every endpoint this entry names, normalised with a port.
    pub endpoints: Vec<String>,
    /// The Device ID the first connection pinned, hex, or absent before that.
    pub expect_device_id: Option<String>,
}

// Drains every event currently queued on both discovery sources into
// `list`, replacing the four copies of this loop that previously lived in
// each command below. A `SourceMismatch` is reported rather than
// discarded (rule F6): each source is applied under its own `SourceId`,
// so a mismatch can only mean a source produced an event it does not own.
pub async fn drain_peer_sources(
    mdns_source: &mut MdnsSource,
    static_peer_source: &mut StaticPeerSource,
    list: &mut PeerList,
    self_device_id: DeviceId,
) -> Result<(), String> {
    while let Ok(Ok(event)) =
        tokio::time::timeout(Duration::from_millis(5), mdns_source.next_event()).await
    {
        if let DiscoveryEvent::Observed(ref obs) = event
            && obs.device_id() == Some(self_device_id)
        {
            // Dropping self before insertion prevents self-resolution and dialing, not just frontend display.
            continue;
        }
        list.apply(MDNS_SOURCE_ID, event)
            .map_err(|e| format!("mdns peer list update rejected: {e}"))?;
    }
    while let Ok(Ok(event)) =
        tokio::time::timeout(Duration::from_millis(5), static_peer_source.next_event()).await
    {
        if let DiscoveryEvent::Observed(ref obs) = event
            && obs.device_id() == Some(self_device_id)
        {
            continue;
        }
        list.apply(STATIC_PEER_SOURCE_ID, event)
            .map_err(|e| format!("static peer list update rejected: {e}"))?;
    }
    Ok(())
}

/// The outcome of resolving a `peer_id` into a dial attempt: the candidate
/// to dial, the `PeerExpectation` to authenticate it against, and -- only
/// for a Static Peer's first connection -- the entry to pin once the
/// channel authenticates.
#[derive(Debug)]
pub struct ResolvedPeer {
    /// The candidate `connect_and_pin` dials.
    pub candidate: Candidate,
    /// The `PeerExpectation` the dial authenticates against.
    pub expectation: PeerExpectation,
    /// The Static Peer entry `connect_and_pin` writes back to once the
    /// channel authenticates, or `None` when there is nothing to pin --
    /// an already-identified peer, or an entry the registry already pins.
    pub pin_target: Option<StaticPeerId>,
}

// Paths unable to carry the transfer are dropped before scoring because dialling
// them cannot complete it. Phase 3's race is not built and one dial stands in for
// it; the score has no RTT term because nothing has been dialled yet (docs/03).
pub fn pick_candidate(
    peer: &Peer,
    peer_id: &str,
    transports: &TransportSet,
    size: TransferSize,
) -> Result<Candidate, String> {
    let candidates = peer.candidates();
    if candidates.is_empty() {
        return Err(format!("no candidate address found for peer {peer_id}"));
    }
    let filtered = prefilter(&candidates, size);
    if filtered.is_empty() {
        return Err(match size {
            TransferSize::Bytes(n) => {
                format!("no candidate for peer {peer_id} can carry a transfer of {n} bytes")
            }
            TransferSize::Unknown => {
                format!(
                    "no candidate for peer {peer_id} can carry a transfer whose size is not yet known"
                )
            }
        });
    }
    transports
        .best_candidate(&filtered)
        .ok_or_else(|| format!("no candidate for peer {peer_id} that this device can dial"))
}

/// Resolves `peer_id`, in either form `PeerInfo::key` may carry, into a
/// candidate and a `PeerExpectation`. An identified peer's expectation is
/// the Device ID the peer list merged it under -- for a Static Peer, the
/// pin its own source re-reports once written. The registry decides only
/// for an entry the list has not yet seen identified (docs/03, "The pin").
pub fn resolve_peer(
    peer_id: &str,
    list: &PeerList,
    registry: &StaticPeerRegistry,
    transports: &TransportSet,
    size: TransferSize,
) -> Result<ResolvedPeer, String> {
    for peer in list.peers() {
        if let Some(device_id) = peer.device_id() {
            if device_id.to_string() != peer_id {
                continue;
            }
            let candidate = pick_candidate(&peer, peer_id, transports, size)?;
            return Ok(ResolvedPeer {
                candidate,
                expectation: PeerExpectation::Device(device_id),
                pin_target: None,
            });
        }

        let observation = peer
            .observations()
            .first()
            .ok_or_else(|| format!("peer {peer_id} carries no observation"))?;
        if observation.id().to_string() != peer_id {
            continue;
        }

        let source = observation.id().source();
        if source == STATIC_PEER_SOURCE_ID {
            let static_id = StaticPeerId::new(observation.id().key().as_str())
                .map_err(|e| format!("malformed static peer observation key: {e}"))?;
            let expectation = registry
                .expectation(&static_id)
                .ok_or_else(|| format!("no static peer entry for {peer_id}"))?;
            let candidate = pick_candidate(&peer, peer_id, transports, size)?;
            let pin_target = matches!(expectation, PeerExpectation::Unpinned).then_some(static_id);
            return Ok(ResolvedPeer {
                candidate,
                expectation,
                pin_target,
            });
        } else if source == tradr_discovery::BLE_SOURCE_ID {
            let candidate = pick_candidate(&peer, peer_id, transports, size)?;
            return Ok(ResolvedPeer {
                candidate,
                expectation: PeerExpectation::Unpinned,
                pin_target: None,
            });
        } else {
            return Err(format!("peer {peer_id} has not yet been identified"));
        }
    }

    Err(format!("peer with id {peer_id} not found"))
}

/// Dials `resolved.candidate` under `resolved.expectation` and, when made
/// under `Unpinned`, writes the `DeviceId` the channel authenticated back
/// into the registry (docs/03, "The pin"). An `AlreadyPinned` refusal --
/// a second device answering where an earlier pin named another -- fails
/// the dial outright rather than being discarded (rule F6).
pub async fn connect_and_pin(
    transports: &TransportSet,
    registry: &tokio::sync::Mutex<StaticPeerRegistry>,
    resolved: ResolvedPeer,
) -> Result<Box<dyn SecureChannel>, String> {
    let dialler = transports.dialler(&resolved.candidate).ok_or_else(|| {
        format!(
            "no transport in set can dial candidate {} at {}",
            resolved.candidate.transport(),
            resolved.candidate.address()
        )
    })?;
    let channel = dialler
        .connect(&resolved.candidate, &resolved.expectation)
        .await
        .map_err(|e| {
            format!(
                "failed to connect to peer at {}: {e}",
                resolved.candidate.address()
            )
        })?;

    if let Some(static_id) = resolved.pin_target {
        registry
            .lock()
            .await
            .pin(&static_id, channel.peer())
            .map_err(|e| format!("failed to pin static peer {static_id}: {e}"))?;
    }

    Ok(channel)
}

/// Distinct discovery sources that reported `peer`, preserving observation
/// order so the frontend can attribute provenance deterministically.
pub fn peer_sources(peer: &Peer) -> Vec<String> {
    let mut sources: Vec<String> = peer
        .observations()
        .iter()
        .map(|o| o.id().source().as_str().to_string())
        .collect();
    sources.dedup();
    sources
}

/// Projects a discovered peer into the presentation view the frontend consumes.
pub fn peer_info(peer: &Peer) -> PeerInfo {
    let device_id = peer
        .device_id()
        .map(|id| id.to_string())
        .unwrap_or_default();
    let key = match peer.device_id() {
        Some(id) => id.to_string(),
        None => peer
            .observations()
            .first()
            .map(|o| o.id().to_string())
            .unwrap_or_default(),
    };
    let display_name = peer
        .observations()
        .iter()
        .find_map(|o| o.display_name().map(|n| n.as_str().to_string()));
    let addresses = peer
        .candidates()
        .iter()
        .map(|c| c.address().to_string())
        .collect();
    let capabilities = peer
        .observations()
        .first()
        .map(|o| o.capabilities().bits())
        .unwrap_or(0);
    let sources = peer_sources(peer);

    PeerInfo {
        device_id,
        key,
        display_name,
        addresses,
        capabilities,
        sources,
    }
}

//! The mDNS `DiscoverySource` and advertiser (docs/03, "1. mDNS / DNS-SD --
//! the same LAN, Tier 0", "What a Discovery Source reports", and "A
//! discovery source must emit an address its transport can parse"). Wraps
//! `mdns-sd`'s `ServiceEvent` stream; no daemon is started by this module's
//! own tests (STATE.md's mDNS block, and decision 22).

use std::net::Ipv6Addr;

use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use tradr_core::{
    BoxFuture, Candidate, DiscoveryError, DiscoveryEvent, DiscoverySource, ObservationId,
    ObservationKey, PeerObservation, Rng, RngError, SourceId, TransportId,
};

use crate::txt::TxtRecord;

/// This source's identity.
pub const MDNS_SOURCE_ID: SourceId = SourceId::new("mdns");

/// docs/03's service type.
pub const SERVICE_TYPE: &str = "_tradr._udp.local.";

/// The transport every candidate this source produces names. Declared
/// locally rather than imported from `tradr-transport`, which this crate
/// may not depend on -- `TransportId` is an opaque token precisely so both
/// sides can name the same string.
const DIRECT_QUIC: TransportId = TransportId::new("direct-quic");

/// An mDNS `DiscoverySource` over a `flume::Receiver<ServiceEvent>` (docs/03,
/// "1. mDNS / DNS-SD").
pub struct MdnsSource {
    events: flume::Receiver<ServiceEvent>,
}

impl MdnsSource {
    /// Wraps a stream of `ServiceEvent`s. The caller supplies the receiver,
    /// so a test drives this with no daemon and no network.
    pub fn new(events: flume::Receiver<ServiceEvent>) -> Self {
        Self { events }
    }

    /// Browses `SERVICE_TYPE` on a running daemon.
    pub fn browse(daemon: &ServiceDaemon) -> Result<Self, mdns_sd::Error> {
        let events = daemon.browse(SERVICE_TYPE)?;
        Ok(Self::new(events))
    }
}

impl DiscoverySource for MdnsSource {
    fn id(&self) -> SourceId {
        MDNS_SOURCE_ID
    }

    fn next_event(&mut self) -> BoxFuture<'_, Result<DiscoveryEvent, DiscoveryError>> {
        Box::pin(async move {
            loop {
                let event = self
                    .events
                    .recv_async()
                    .await
                    .map_err(|_| DiscoveryError::Closed)?;

                match event {
                    ServiceEvent::ServiceResolved(resolved) => {
                        if let Some(observation) = observation_from_resolved(&resolved) {
                            return Ok(DiscoveryEvent::Observed(observation));
                        }
                        // A record no meaning attaches to for this build:
                        // skip it and keep browsing (docs/03, "A malformed
                        // record is skipped").
                    }
                    ServiceEvent::ServiceRemoved(_ty_domain, fullname) => {
                        if let Ok(key) = ObservationKey::new(&fullname) {
                            return Ok(DiscoveryEvent::Lost(ObservationId::new(
                                MDNS_SOURCE_ID,
                                key,
                            )));
                        }
                    }
                    // `SearchStarted`, `ServiceFound`, `SearchStopped`, and
                    // whatever `#[non_exhaustive]` adds later have no
                    // `DiscoveryEvent` counterpart: keep browsing rather
                    // than fail a source that has only just started.
                    _ => {}
                }
            }
        })
    }
}

// Builds a `PeerObservation` from a resolved service, or `None` when its
// TXT record or `fullname` cannot be used (docs/03, "A malformed record is
// skipped, and the source keeps running").
fn observation_from_resolved(resolved: &ResolvedService) -> Option<PeerObservation> {
    let key = ObservationKey::new(&resolved.fullname).ok()?;

    let pairs: Vec<(String, String)> = resolved
        .txt_properties
        .iter()
        .map(|property| (property.key().to_string(), property.val_str().to_string()))
        .collect();
    let record = TxtRecord::parse(&pairs).ok()?;

    let candidates: Vec<Candidate> = resolved
        .addresses
        .iter()
        .filter_map(|address| format_address(address, resolved.port))
        .filter_map(|address| Candidate::new(DIRECT_QUIC, &address).ok())
        .collect();

    let id = ObservationId::new(MDNS_SOURCE_ID, key);
    let mut observation = PeerObservation::new(id, candidates)
        .with_device_id(record.device_id())
        .with_capabilities(record.capabilities());
    if let Some(name) = record.display_name() {
        observation = observation.with_display_name(name.clone());
    }
    Some(observation)
}

// Formats a `ScopedIp` into an address `direct-quic`'s parser accepts
// (docs/03, DCR-048): `ScopedIp`'s own `Display` renders a link-local scope
// as an interface name off Windows, which that parser refuses, so the
// numeric scope index is read instead. `None` for a variant this build
// does not know, since it cannot be formatted safely.
fn format_address(address: &ScopedIp, port: u16) -> Option<String> {
    match address {
        ScopedIp::V4(v4) => Some(format!("{}:{port}", v4.addr())),
        ScopedIp::V6(v6) => Some(format_v6(*v6.addr(), v6.scope_id().index, port)),
        _ => None,
    }
}

// The pure half of `format_address`'s V6 case, taking primitives rather
// than `mdns_sd::ScopedIpV6` -- whose fields are private, with no public
// constructor for a non-zero scope index, so this is what a test drives
// directly rather than going through `mdns_sd`'s own type.
fn format_v6(addr: Ipv6Addr, scope_index: u32, port: u16) -> String {
    if scope_index != 0 && is_link_local(&addr) {
        format!("[{addr}%{scope_index}]:{port}")
    } else {
        format!("[{addr}]:{port}")
    }
}

// `Ipv6Addr::is_unicast_link_local` is unstable on the pinned toolchain
// (STATE.md's mDNS block), so the fe80::/10 prefix is tested directly
// against the address's first 16-bit segment.
fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Builds the `ServiceInfo` this device advertises: `SERVICE_TYPE`, with
/// the given instance name and port, and the TXT properties `record`
/// carries. Its own address is left to `enable_addr_auto`, since a device
/// advertising itself has no address to hand `mdns-sd` up front.
pub fn advertisement(
    instance_name: &str,
    port: u16,
    record: &TxtRecord,
) -> Result<ServiceInfo, mdns_sd::Error> {
    let host_name = format!("{instance_name}.local.");
    let pairs = record.to_pairs();
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &host_name,
        "",
        port,
        &pairs[..],
    )?;
    Ok(info.enable_addr_auto())
}

/// Eight random hex characters, drawn through the `Rng` trait (rule B7).
/// docs/03: the Device ID never appears in the instance name.
pub fn instance_name(rng: &dyn Rng) -> Result<String, RngError> {
    let mut bytes = [0u8; 4];
    rng.fill_bytes(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    // `format_v6` is tested here, on primitives, rather than in
    // tests/mdns.rs: `mdns_sd::ScopedIpV6`'s fields are private and it has
    // no public constructor for a non-zero scope index, so the integration
    // test crate cannot build one (docs/03, DCR-048).
    #[test]
    fn a_link_local_address_with_a_scope_gets_the_numeric_index_and_parses() {
        let addr: Ipv6Addr = "fe80::1".parse().expect("valid ipv6 literal");

        let formatted = format_v6(addr, 2, 51820);

        assert_eq!(formatted, "[fe80::1%2]:51820");
        assert!(formatted.parse::<SocketAddr>().is_ok());
    }

    // Closes the gap the constant-true mutation of `is_link_local` would
    // open: a scope on a global address is wrong and unroutable, so a
    // non-zero index here must not appear in the string.
    #[test]
    fn a_global_address_with_a_scope_index_still_has_no_scope_in_the_string() {
        let addr: Ipv6Addr = "2001:db8::1".parse().expect("valid ipv6 literal");

        let formatted = format_v6(addr, 2, 51820);

        assert_eq!(formatted, "[2001:db8::1]:51820");
    }

    #[test]
    fn a_link_local_address_with_a_zero_scope_has_no_scope_in_the_string() {
        let addr: Ipv6Addr = "fe80::1".parse().expect("valid ipv6 literal");

        let formatted = format_v6(addr, 0, 51820);

        assert_eq!(formatted, "[fe80::1]:51820");
    }

    // Also closes the constant-true mutation's gap: fec0::/10 was once
    // "site-local" and is outside fe80::/10, so `& 0xffc0 == 0xfec0` must
    // not satisfy the fe80::/10 check.
    #[test]
    fn an_address_just_outside_the_link_local_prefix_has_no_scope_in_the_string() {
        let addr: Ipv6Addr = "fec0::1".parse().expect("valid ipv6 literal");

        let formatted = format_v6(addr, 2, 51820);

        assert_eq!(formatted, "[fec0::1]:51820");
    }

    // Closes the gap the widened-mask mutation actually opens: `fec0::1`
    // above is excluded by both the correct mask and `& 0xffff`, so it
    // cannot tell them apart. `fe90::1` is inside fe80::/10 but is not the
    // literal value `0xfe80`, which `& 0xffff` alone would reject.
    #[test]
    fn a_link_local_address_outside_the_exact_fe80_segment_still_gets_its_scope_index() {
        let addr: Ipv6Addr = "fe90::1".parse().expect("valid ipv6 literal");

        let formatted = format_v6(addr, 2, 51820);

        assert_eq!(formatted, "[fe90::1%2]:51820");
    }

    // `format_address`'s own wiring, untested by `format_v6`'s own tests,
    // is what DCR-048 exists to guard. `if_addrs::Interface` has all-public
    // fields and `ScopedIp`'s `From<&Interface>` is public, so this builds
    // a real scoped address through both crates' code, not a primitive.
    #[cfg(not(windows))]
    #[test]
    fn format_address_carries_a_link_local_scope_index_through_to_the_string() {
        use if_addrs::{IfAddr, IfOperStatus, Ifv6Addr, Interface};

        let interface = Interface {
            name: "eth0".to_string(),
            addr: IfAddr::V6(Ifv6Addr {
                ip: "fe80::1".parse().expect("valid ipv6 literal"),
                netmask: "ffff:ffff:ffff:ffff::".parse().expect("valid ipv6 literal"),
                prefixlen: 64,
                broadcast: None,
            }),
            index: Some(2),
            oper_status: IfOperStatus::Up,
            is_p2p: false,
        };
        let scoped = ScopedIp::from(&interface);

        let formatted = format_address(&scoped, 51820).expect("v4 and v6 always format");

        assert_eq!(formatted, "[fe80::1%2]:51820");
        assert!(formatted.parse::<SocketAddr>().is_ok());
    }
}

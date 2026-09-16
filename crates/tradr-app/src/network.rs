//! QUIC transport binding and mDNS advertisement shared across front ends (docs/03, DCR-126).
//! Provides the fallback QUIC bind on port 21820 and device advertisement
//! registration for mDNS discovery.

use std::net::SocketAddr;
use std::sync::Arc;

use mdns_sd::ServiceDaemon;
use tradr_core::{Capabilities, KeyStore, PublicIdentity, Rng};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, Platform, STATIC_PEER_DEFAULT_PORT, TxtRecord, advertisement,
    instance_name,
};
use tradr_transport::quic::QuicTransport;

/// Binds the QUIC transport, falling back to an ephemeral port if the default is taken.
pub fn bind_quic_transport(key_store: Arc<dyn KeyStore>) -> Result<Arc<QuicTransport>, String> {
    // docs/03, "The default port, and why it is not 51820": 21820 is the
    // fixed number a Static Peer's dialling side can rely on with no way
    // to be told otherwise. The bind falls back to an ephemeral port
    // whenever the default is already taken, which is every time two
    // instances run on the same machine.
    let default_addr: SocketAddr = format!("0.0.0.0:{STATIC_PEER_DEFAULT_PORT}")
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let ephemeral_addr: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let transport = Arc::new(match QuicTransport::new(key_store.clone(), default_addr) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "lifecycle: default quic port {STATIC_PEER_DEFAULT_PORT} unavailable ({e}), falling back to an ephemeral port"
            );
            QuicTransport::new(key_store.clone(), ephemeral_addr)
                .map_err(|e| format!("failed to start quic transport: {e}"))?
        }
    });
    Ok(transport)
}

/// Starts an mDNS daemon and disables virtual interfaces.
pub fn mdns_daemon() -> Result<ServiceDaemon, String> {
    let daemon = ServiceDaemon::new().map_err(|e| format!("failed to start mdns daemon: {e}"))?;

    let predicate = mdns_sd::IfPredicate::new(|i| {
        let n = &i.name;
        n.starts_with("veth")
            || n.starts_with("br-")
            || n.starts_with("docker")
            || n.starts_with("vnet")
            || n.starts_with("virbr")
    });
    daemon
        .disable_interface(mdns_sd::IfKind::Predicate(predicate))
        .map_err(|e| format!("failed to filter mdns interfaces: {e}"))?;
    Ok(daemon)
}

/// Returns the platform identifier string for the current host.
pub fn local_platform() -> &'static str {
    #[cfg(target_os = "linux")]
    let platform_str = "linux";
    #[cfg(target_os = "macos")]
    let platform_str = "mac";
    #[cfg(target_os = "windows")]
    let platform_str = "win";
    #[cfg(target_os = "android")]
    let platform_str = "android";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    )))]
    let platform_str = "other";
    platform_str
}

/// Builds the mDNS TXT record announcing this device's identity and capabilities.
pub fn device_txt_record(
    public_identity: &PublicIdentity,
    capabilities: Capabilities,
) -> Result<TxtRecord, String> {
    let agreement_hash = blake3::hash(public_identity.agreement_pub().as_bytes());
    let mut agreement_key_tag = [0u8; AGREEMENT_KEY_TAG_LEN];
    agreement_key_tag.copy_from_slice(&agreement_hash.as_bytes()[..AGREEMENT_KEY_TAG_LEN]);

    let platform = Platform::new(local_platform()).map_err(|e| e.to_string())?;
    let txt_record = TxtRecord::new(
        public_identity.device_id(),
        agreement_key_tag,
        None,
        capabilities,
        platform,
    );
    Ok(txt_record)
}

/// Registers the device's mDNS advertisement on the given daemon.
pub fn register_advertisement(
    daemon: &ServiceDaemon,
    port: u16,
    record: &TxtRecord,
    rng: &dyn Rng,
) -> Result<(), String> {
    let inst_name = instance_name(rng).map_err(|e| e.to_string())?;
    let service_info = advertisement(&inst_name, port, record)
        .map_err(|e| format!("failed to build advertisement: {e}"))?;
    daemon
        .register(service_info)
        .map_err(|e| format!("failed to register service info: {e}"))?;
    Ok(())
}

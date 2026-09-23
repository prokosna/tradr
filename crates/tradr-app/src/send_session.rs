//! Sending session and peer discovery compositions for desktop front ends (docs/02, DCR-139).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::ServiceDaemon;
use tradr_core::{Capabilities, DeviceId, PeerList, RootId, Transport};
use tradr_discovery::{MdnsSource, StaticPeerRegistry, StaticPeerSource};
use tradr_identity::{LinkRegistry, OsRng, SystemClock};
use tradr_transport::selection::TransferSize;
use tradr_transport::set::TransportSet;
use tradr_vfs::NativeVfs;

use crate::network::{self, bind_quic_dialler};
use crate::peer_trust::{HttpsJwksFetch, PeerTrust};
use crate::peers::{
    PeerInfo, ResolvedPeer, connect_and_pin, drain_peer_sources, peer_info, resolve_peer,
    select_peer_key,
};
pub use crate::send::TransferProgressPayload;
use crate::send::{execute_send_files_with_progress, resolve_send_items};
use crate::sign_in::{OAuthConfig, SignInState, peer_verifier, provider_profile, sign_in_keeping};
use crate::{identity, paths};

const DISCOVERY_WINDOW: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Coordinates mDNS and static peer discovery sources across polling windows.
pub struct PeerDiscovery {
    mdns: MdnsSource,
    static_source: StaticPeerSource,
    peer_list: PeerList,
    registry: tokio::sync::Mutex<StaticPeerRegistry>,
    device_id: DeviceId,
}

impl PeerDiscovery {
    /// Starts browsing mDNS and loads the static peer registry from disk.
    pub fn start(
        daemon: &ServiceDaemon,
        static_peers_path: &Path,
        device_id: DeviceId,
    ) -> Result<Self, String> {
        let mdns = MdnsSource::browse(daemon).map_err(|e| format!("failed to browse mdns: {e}"))?;
        let (registry, static_source) =
            StaticPeerRegistry::load(static_peers_path).map_err(|e| {
                format!(
                    "failed to load static peer registry at {}: {e}",
                    static_peers_path.display()
                )
            })?;
        Ok(Self::from_sources(mdns, static_source, registry, device_id))
    }

    /// Constructs discovery directly from existing sources without starting an mDNS daemon.
    pub fn from_sources(
        mdns: MdnsSource,
        static_source: StaticPeerSource,
        registry: StaticPeerRegistry,
        device_id: DeviceId,
    ) -> Self {
        Self {
            mdns,
            static_source,
            peer_list: PeerList::new(),
            registry: tokio::sync::Mutex::new(registry),
            device_id,
        }
    }

    /// Drains pending discovery events from both mDNS and static peer sources.
    pub async fn drain(&mut self) -> Result<(), String> {
        drain_peer_sources(
            &mut self.mdns,
            &mut self.static_source,
            &mut self.peer_list,
            self.device_id,
        )
        .await
    }

    /// Drains repeatedly until the window expires and answers all discovered peers.
    pub async fn collect(&mut self, window: Duration) -> Result<Vec<PeerInfo>, String> {
        let deadline = tokio::time::Instant::now() + window;
        loop {
            self.drain().await?;
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            tokio::time::sleep(remaining.min(POLL_INTERVAL)).await;
        }
        Ok(self.peer_list.peers().iter().map(peer_info).collect())
    }

    /// Awaits resolution of the named peer within the window, returning the last refusal on timeout.
    pub async fn await_peer(
        &mut self,
        peer_id: &str,
        transports: &TransportSet,
        size: TransferSize,
        window: Duration,
    ) -> Result<ResolvedPeer, String> {
        let deadline = tokio::time::Instant::now() + window;
        let mut last_refusal;
        loop {
            self.drain().await?;
            let selected_key = select_peer_key(peer_id, &self.peer_list)?;
            let target_peer_id = match &selected_key {
                Some(key) => key.as_str(),
                None => peer_id,
            };
            {
                let registry = self.registry.lock().await;
                match resolve_peer(target_peer_id, &self.peer_list, &registry, transports, size) {
                    Ok(resolved) => return Ok(resolved),
                    Err(e) => {
                        last_refusal = e;
                    }
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            tokio::time::sleep(remaining.min(POLL_INTERVAL)).await;
        }
        Err(last_refusal)
    }

    /// Returns a reference to the static peer registry mutex.
    pub fn registry(&self) -> &tokio::sync::Mutex<StaticPeerRegistry> {
        &self.registry
    }
}

/// Discovers peers reachable via LAN or static peer registration within the default window.
pub async fn discover_peers() -> Result<Vec<PeerInfo>, String> {
    let dir = paths::app_data_dir()?;
    let keys_dir = paths::device_keys_dir(&dir);
    let ladder = identity::platform_ladder(keys_dir);
    let identity = identity::open_device_identity(&ladder, &OsRng)?;
    let device_id = identity.public_identity().device_id();

    let static_peers_path = dir.join("static-peers.json");
    let daemon = network::mdns_daemon()?;
    let mut discovery = PeerDiscovery::start(&daemon, &static_peers_path, device_id)?;
    discovery.collect(DISCOVERY_WINDOW).await
}

/// Executes the sending composition, resolving files, signing in, and transmitting to a peer.
pub async fn run_send(
    peer_id: &str,
    files: &[String],
    oauth: &OAuthConfig,
    on_progress: Arc<dyn Fn(&TransferProgressPayload) + Send + Sync>,
) -> Result<Vec<String>, String> {
    let dir = paths::app_data_dir()?;
    let keys_dir = paths::device_keys_dir(&dir);
    let ladder = identity::platform_ladder(keys_dir);
    let identity = identity::open_device_identity(&ladder, &OsRng)?;
    let public_identity = identity.public_identity();

    let mut canonical_files = Vec::with_capacity(files.len());
    for file in files {
        let canonical =
            std::fs::canonicalize(file).map_err(|e| format!("cannot send '{file}': {e}"))?;
        canonical_files.push(canonical.to_string_lossy().into_owned());
    }

    let vfs = NativeVfs::new();
    // RootId is unused because every canonical path is absolute, triggering the absolute split.
    let dummy_root = RootId::new(0);
    let items = resolve_send_items(&vfs, dummy_root, &canonical_files).await?;
    let total: u64 = items.iter().map(|item| item.size_bytes).sum();

    let transport = bind_quic_dialler(identity.key_store())?;
    let transports = TransportSet::new(vec![transport as Arc<dyn Transport>]);

    let static_peers_path = dir.join("static-peers.json");
    let daemon = network::mdns_daemon()?;
    let mut discovery =
        PeerDiscovery::start(&daemon, &static_peers_path, public_identity.device_id())?;

    let profile = provider_profile(oauth)?;
    let peer_trust = Arc::new(PeerTrust::new(profile.clone(), Arc::new(HttpsJwksFetch)));
    let links_path = dir.join("links.json");
    let registry = LinkRegistry::load(&links_path)
        .map_err(|e| format!("link registry at {}: {e}", links_path.display()))?;
    let link_registry = Arc::new(std::sync::Mutex::new(registry));
    let sign_in_state = Arc::new(SignInState::empty());
    sign_in_keeping(
        "send",
        &profile,
        &public_identity,
        &peer_trust,
        &sign_in_state,
        &paths::attestation_path(&dir),
    )
    .await?;

    let resolved = discovery
        .await_peer(
            peer_id,
            &transports,
            TransferSize::Bytes(total),
            DISCOVERY_WINDOW,
        )
        .await?;

    let channel = connect_and_pin(&transports, discovery.registry(), resolved).await?;

    let attestation_token = sign_in_state
        .id_token()
        .ok_or_else(|| "missing id token after sign in".to_string())?;
    let verifier = peer_verifier(
        peer_trust,
        sign_in_state,
        link_registry,
        Arc::new(SystemClock),
    );
    execute_send_files_with_progress(
        channel.as_ref(),
        &vfs,
        &items,
        &public_identity,
        identity.key_store().as_ref(),
        attestation_token,
        Capabilities::DIRECT_QUIC,
        verifier,
        move |payload| on_progress(&payload),
    )
    .await
}

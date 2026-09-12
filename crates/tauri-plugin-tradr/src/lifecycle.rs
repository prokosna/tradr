//! Sets up the background runtime environment (WI-M1-025):
//! registers VFS roots, binds the QUIC transport, starts mDNS advertisement and browsing,
//! and runs the background transfer listener.

use std::net::SocketAddr;
use std::sync::Arc;

use mdns_sd::ServiceDaemon;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use tradr_core::{
    BoxFuture, Capabilities, Incoming, KeyBinding, KeyStore, PeerList, PublicIdentity, RootId,
    Transport, TrustTier,
};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, MdnsSource, Platform, STATIC_PEER_DEFAULT_PORT, StaticPeerRegistry,
    TxtRecord, advertisement, instance_name,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

use crate::ble_source::BleDiscovery;
use crate::broadcast_secrets::DeviceBroadcastSecrets;
use crate::capabilities::LocalCapabilities;
use crate::identity::IdentityState;
use crate::link_invite::{
    LinkInviteState, LinkProposalDto, LinkService, LinkServiceParts, ProposalSink,
};
use crate::link_registry::LinkRegistryState;
use crate::listener::{LinkStreamService, ListenerError, build_key_binding, run_listener};
use crate::peer_trust::{OwnAttestation, PeerTrustState};
use crate::sign_in::SignInState;

#[cfg(target_os = "android")]
use crate::ble_gatt_android::{AcceptorPeripheral, AndroidGattAcceptor};
#[cfg(target_os = "android")]
use tauri::plugin::PluginHandle;
#[cfg(target_os = "android")]
use tradr_identity::key_binding::ClockKeyBindingVerifier;
#[cfg(target_os = "android")]
use tradr_transport::ble::BleGattTransport;

/// Returns the root identifier for the local downloads directory.
pub fn downloads_root_id() -> RootId {
    RootId::new(1)
}

// Announces a `LinkProposal` as a Tauri event, the mechanism
// `android.rs`'s `share-intent` and `commands.rs`'s `transfer-progress`
// already use. `emit`'s `Result` is returned rather than discarded (rule
// F6): unlike those fire-and-forget sites, a caller of `announce` acts on
// a listener that has not attached yet.
struct EmitProposalSink<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> ProposalSink for EmitProposalSink<R> {
    fn announce(&self, proposal: &LinkProposalDto) -> Result<(), String> {
        self.app
            .emit("link-proposal", proposal)
            .map_err(|e| e.to_string())
    }
}

/// Everything a transfer listener needs, so each transport runs the same loop.
pub struct TransferListener {
    vfs: Arc<NativeVfs>,
    key_store: Arc<dyn KeyStore>,
    public_identity: PublicIdentity,
    our_attestation: Arc<dyn OwnAttestation>,
    root: RootId,
    capabilities: Arc<LocalCapabilities>,
    verify_attestation: Arc<
        dyn Fn(AttestationRequest) -> BoxFuture<'static, Result<TrustTier, String>> + Send + Sync,
    >,
    link_service: Option<Arc<dyn LinkStreamService>>,
}

impl TransferListener {
    /// The capability set this device declares, shared with every other declaration site.
    pub fn capabilities(&self) -> Arc<LocalCapabilities> {
        Arc::clone(&self.capabilities)
    }

    /// The key store used for signing key bindings and decrypting payloads.
    pub fn key_store(&self) -> Arc<dyn KeyStore> {
        Arc::clone(&self.key_store)
    }

    /// Builds the key binding for this node linking its agreement key to its identity key.
    pub fn key_binding(&self) -> Result<KeyBinding, String> {
        build_key_binding(self.key_store.as_ref(), &self.public_identity)
            .map_err(|e| format!("failed to build key binding: {e}"))
    }

    /// Runs the accept-handshake-serve loop over `incoming` until it ends.
    pub async fn run(&self, incoming: Box<dyn Incoming>) -> Result<(), ListenerError> {
        let verifier = Arc::clone(&self.verify_attestation);
        run_listener(
            incoming,
            Arc::clone(&self.vfs),
            Arc::clone(&self.key_store),
            self.public_identity.clone(),
            Arc::clone(&self.our_attestation),
            self.root,
            Arc::clone(&self.capabilities),
            move |req| verifier(req),
            self.link_service.clone(),
        )
        .await
    }
}

/// Handles to background lifecycle services started during initialization.
pub struct LifecycleHandles {
    /// The transfer listener running background protocols.
    pub listener: Arc<TransferListener>,
    /// The BLE discovery runner, if secrets and storage are available.
    pub ble: Option<BleDiscovery>,
}

/// Initializes the background network and storage services.
pub fn init_lifecycle<R: Runtime>(
    app: &AppHandle<R>,
    identity_state: &IdentityState,
    sign_in_state: Arc<SignInState>,
    peer_trust_state: &PeerTrustState,
    link_registry_state: &LinkRegistryState,
    link_invite_state: Arc<LinkInviteState>,
) -> Result<Option<LifecycleHandles>, String> {
    let key_store = match identity_state.key_store() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("lifecycle: key store not available: {e}");
            return Ok(None);
        }
    };
    let public_identity = match identity_state.public_identity() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("lifecycle: public identity not available: {e}");
            return Ok(None);
        }
    };

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the app data directory: {e}"))?;
    let static_peers_path = app_data_dir.join("static-peers.json");
    let abk_path = app_data_dir.join("account-broadcast-key.json");
    // A malformed file is refused rather than replaced with an empty
    // registry, which would delete every pin the user holds (docs/03,
    // "Where the set is kept"). Swallowing it here, unlike the key
    // store above, would leave a running app with no discovery and no
    // transfers at all, so setup fails loudly instead, naming the file.
    let (static_peer_registry, static_peer_source) =
        StaticPeerRegistry::load(&static_peers_path)
            .map_err(|e| format!("static peer registry not available: {e}"))?;

    let downloads_dir = app.path().download_dir().unwrap_or_else(|_| {
        app.path()
            .app_data_dir()
            .map(|p| p.join("downloads"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/tradr-downloads"))
    });
    std::fs::create_dir_all(&downloads_dir)
        .map_err(|e| format!("could not create downloads directory: {e}"))?;

    let vfs = Arc::new(NativeVfs::new());
    vfs.register_root(downloads_root_id(), downloads_dir, false)
        .map_err(|e| format!("could not register downloads root: {e}"))?;

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
    let transport = Arc::new(
        match tauri::async_runtime::block_on(async {
            QuicTransport::new(key_store.clone(), default_addr)
        }) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "lifecycle: default quic port {STATIC_PEER_DEFAULT_PORT} unavailable ({e}), falling back to an ephemeral port"
                );
                tauri::async_runtime::block_on(async {
                    QuicTransport::new(key_store.clone(), ephemeral_addr)
                })
                .map_err(|e| format!("failed to start quic transport: {e}"))?
            }
        },
    );
    let local_addr = transport
        .local_addr()
        .map_err(|e| format!("failed to get quic local address: {e}"))?;
    let bound_port = local_addr.port();

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

    let agreement_hash = blake3::hash(public_identity.agreement_pub().as_bytes());
    let mut agreement_key_tag = [0u8; AGREEMENT_KEY_TAG_LEN];
    agreement_key_tag.copy_from_slice(&agreement_hash.as_bytes()[..AGREEMENT_KEY_TAG_LEN]);

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

    let capabilities = Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC));

    let platform = Platform::new(platform_str).map_err(|e| e.to_string())?;
    let txt_record = TxtRecord::new(
        public_identity.device_id(),
        agreement_key_tag,
        None,
        capabilities.get(),
        platform,
    );

    let inst_name = instance_name(&OsRng).map_err(|e| e.to_string())?;
    let service_info = advertisement(&inst_name, bound_port, &txt_record)
        .map_err(|e| format!("failed to build advertisement: {e}"))?;
    daemon
        .register(service_info)
        .map_err(|e| format!("failed to register service info: {e}"))?;

    let mdns_source =
        MdnsSource::browse(&daemon).map_err(|e| format!("failed to browse mdns: {e}"))?;

    // `peer_trust` reports its build failure through every classification
    // rather than aborting the listener: a fresh clone with no configured
    // OAuth client ids still accepts channels, it just cannot yet promote
    // any of them past the handshake.
    let peer_trust = peer_trust_state.peer_trust();
    let sign_in_for_verify = sign_in_state.clone();
    // Reported the same way as `peer_trust` above, through `let links =
    // links?;` inside the closure, rather than substituting an empty list.
    let link_registry = link_registry_state.registry();

    let verify_attestation: Arc<
        dyn Fn(AttestationRequest) -> BoxFuture<'static, Result<TrustTier, String>> + Send + Sync,
    > = Arc::new(move |req: AttestationRequest| {
        let peer_trust = peer_trust.clone();
        let sign_in = sign_in_for_verify.clone();
        let links = link_registry.clone();
        Box::pin(async move {
            let trust = peer_trust?;
            let own_account = sign_in.own_account();
            // Read out and drop the guard before this block ends,
            // so no `std::sync::Mutex` guard is ever held across
            // the `.await` in `trust.classify` below.
            let linked_accounts = {
                let links = links?;
                let links = links
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                links.linked_accounts()
            };
            trust
                .classify(
                    req.token(),
                    req.identity_pub(),
                    req.agreement_pub(),
                    own_account.as_ref(),
                    &linked_accounts,
                    &SystemClock,
                )
                .await
        })
    });

    let link_service: Arc<dyn LinkStreamService> = Arc::new(LinkService::new(
        link_invite_state,
        LinkServiceParts {
            trust: peer_trust_state.peer_trust(),
            registry: link_registry_state.registry(),
            secrets: identity_state.secret_store(),
        },
        Arc::new(EmitProposalSink { app: app.clone() }),
        Arc::new(SystemClock),
    ));

    let listener = Arc::new(TransferListener {
        vfs: vfs.clone(),
        key_store: key_store.clone(),
        public_identity: public_identity.clone(),
        our_attestation: sign_in_state.clone(),
        root: downloads_root_id(),
        capabilities: capabilities.clone(),
        verify_attestation,
        link_service: Some(link_service),
    });

    let listener_for_quic = listener.clone();
    let transport_for_listener = transport.clone();
    tauri::async_runtime::spawn(async move {
        if let Ok(incoming) = transport_for_listener.listen().await
            && let Err(e) = listener_for_quic.run(incoming).await
        {
            eprintln!("listener loop exited with error: {e}");
        }
    });

    let peer_list = Arc::new(tokio::sync::Mutex::new(PeerList::new()));
    let ble = match identity_state.secret_store() {
        Ok(secret_store) => {
            let broadcast_secrets = DeviceBroadcastSecrets::new(
                sign_in_state.clone(),
                link_registry_state.registry(),
                secret_store,
                abk_path,
            );
            Some(BleDiscovery::new(
                Box::new(broadcast_secrets),
                Box::new(SystemClock),
                peer_list.clone(),
            ))
        }
        Err(e) => {
            eprintln!("lifecycle: secret store not available: {e}");
            None
        }
    };

    app.manage(capabilities);
    app.manage(vfs);
    app.manage(transport);
    app.manage(tokio::sync::Mutex::new(mdns_source));
    app.manage(tokio::sync::Mutex::new(static_peer_source));
    app.manage(tokio::sync::Mutex::new(static_peer_registry));
    app.manage(peer_list);

    Ok(Some(LifecycleHandles { listener, ble }))
}

/// Spawns the background BLE GATT listener on Android (docs/03, DCR-104).
#[cfg(target_os = "android")]
pub fn spawn_ble_gatt_listener<R: Runtime>(
    handle: PluginHandle<R>,
    listener: Arc<TransferListener>,
) {
    tauri::async_runtime::spawn(async move {
        let binding = match listener.key_binding() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("failed to create key binding for ble-gatt listener: {e}");
                return;
            }
        };

        let acceptor = match AndroidGattAcceptor::new(
            handle,
            listener.key_store(),
            Arc::new(OsRng),
            Arc::new(ClockKeyBindingVerifier::new(Arc::new(SystemClock))),
            binding,
            Arc::new(SystemClock),
        )
        .await
        {
            Ok(a) => Arc::new(a),
            Err(e) => {
                eprintln!("failed to start android gatt acceptor: {e}");
                return;
            }
        };

        let peripheral = Arc::new(AcceptorPeripheral::new(acceptor));
        let transport = BleGattTransport::new(None, Some(peripheral));
        let incoming = match transport.listen().await {
            Ok(inc) => inc,
            Err(e) => {
                eprintln!("failed to listen on ble-gatt transport: {e}");
                return;
            }
        };

        listener.capabilities().declare(Capabilities::BLE_GATT);

        if let Err(e) = listener.run(incoming).await {
            eprintln!("ble-gatt listener loop exited with error: {e}");
        }

        listener.capabilities().withdraw(Capabilities::BLE_GATT);
    });
}

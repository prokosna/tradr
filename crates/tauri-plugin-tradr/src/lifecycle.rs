//! Sets up the background runtime environment (WI-M1-025):
//! registers VFS roots, binds the QUIC transport, starts mDNS advertisement and browsing,
//! and runs the background transfer listener.

use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use tradr_core::{
    BoxFuture, Capabilities, Clock, DeviceId, DisplayName, Incoming, KeyBinding, KeyStore,
    PeerList, PublicIdentity, RelPath, RootId, Transport, TrustTier, VersionRange,
};
use tradr_discovery::{DeclaredCapabilities, MdnsSource, StaticPeerRegistry};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_integrity::BaoVerifier;
use tradr_transport::set::TransportSet;
use tradr_vfs::NativeVfs;

use crate::ble_advertising::{BleAdvertising, local_platform_code};
use crate::ble_source::BleDiscovery;
use crate::brokr_commands::{BrokrDeps, BrokrState};
use crate::identity::IdentityState;
use crate::link_registry::LinkRegistryState;
use crate::peer_trust::PeerTrustState;
use tradr_app::broadcast_secrets::DeviceBroadcastSecrets;
use tradr_app::brokr::LinkView;
use tradr_app::browse_access::BrowseAccess;
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::known_store::{KnownDeviceRecorder, KnownDevicesStore};
use tradr_app::link_invite::{
    LinkInviteState, LinkProposalDto, LinkService, LinkServiceParts, ProposalSink,
};
use tradr_app::listener::{
    LinkStreamService, ListenerError, ListenerParams, build_key_binding, listen_for_transfers,
};
use tradr_app::network::{
    bind_quic_transport, device_txt_record, mdns_daemon, register_advertisement,
};
use tradr_app::partial_sweep::sweep_stale_partials;
use tradr_app::peer_trust::OwnAttestation;
use tradr_app::sign_in::{SignInState, listener_peer_verifier};

#[cfg(target_os = "android")]
use crate::ble_gatt_android::{AcceptorPeripheral, AndroidGattAcceptor};
#[cfg(target_os = "android")]
use tauri::plugin::PluginHandle;
#[cfg(any(target_os = "android", target_os = "linux"))]
use tradr_identity::key_binding::ClockKeyBindingVerifier;
#[cfg(any(target_os = "android", target_os = "linux"))]
use tradr_transport::ble::BleGattTransport;
#[cfg(target_os = "linux")]
use tradr_transport::ble::BluerCentral;

/// Returns the root identifier for the local downloads directory.
pub fn downloads_root_id() -> RootId {
    RootId::new(1)
}

/// Payload for the `files-received` event.
#[derive(Serialize, Clone)]
pub struct FilesReceivedPayload {
    pub device_id: String,
    pub files: Vec<String>,
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

type ArrivalHook = Arc<dyn Fn(DeviceId, &[RelPath]) + Send + Sync>;

/// Everything a transfer listener needs, so each transport runs the same loop.
pub struct TransferListener {
    vfs: Arc<NativeVfs>,
    key_store: Arc<dyn KeyStore>,
    public_identity: PublicIdentity,
    our_attestation: Arc<dyn OwnAttestation>,
    root: RootId,
    capabilities: Arc<LocalCapabilities>,
    browse_access: Arc<BrowseAccess>,
    verify_attestation: Arc<
        dyn Fn(AttestationRequest) -> BoxFuture<'static, Result<TrustTier, String>> + Send + Sync,
    >,
    link_service: Option<Arc<dyn LinkStreamService>>,
    on_arrival: ArrivalHook,
    known_devices: Arc<KnownDevicesStore>,
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
        build_key_binding(self.key_store.as_ref(), &self.public_identity, &SystemClock)
            .map_err(|e| format!("failed to build key binding: {e}"))
    }

    /// Runs the accept-handshake-serve loop over `incoming` until it ends.
    pub async fn run(&self, mut incoming: Box<dyn Incoming>) -> Result<(), ListenerError> {
        let verifier = Arc::clone(&self.verify_attestation);
        let key_binding = self
            .key_binding()
            .map_err(ListenerError::ProtocolViolation)?;

        match self.vfs.list_partial_root(self.root).await {
            Ok(entries) => {
                if let Err(e) =
                    sweep_stale_partials(self.vfs.as_ref(), self.root, SystemClock.now(), &entries)
                        .await
                {
                    eprintln!("listener: sweeping stale partial files failed: {e}");
                }
            }
            Err(e) => {
                eprintln!("listener: sweeping stale partial files failed: {e}");
            }
        }

        let versions = VersionRange::new(1, 1)
            .map_err(|_| ListenerError::ProtocolViolation("invalid version range".to_string()))?;

        let known_rec: &dyn KnownDeviceRecorder = self.known_devices.as_ref();
        let params = ListenerParams {
            root: self.root,
            our_identity: &self.public_identity,
            our_attestation_token: self.our_attestation.clone(),
            our_key_binding: key_binding,
            our_versions: versions,
            our_capabilities: self.capabilities.clone(),
            browse_access: self.browse_access.clone(),
            known_devices: Some(known_rec),
        };

        listen_for_transfers(
            incoming.as_mut(),
            self.vfs.as_ref(),
            params,
            self.key_store.as_ref(),
            &OsRng,
            &SystemClock,
            &BaoVerifier,
            move |req| verifier(req),
            None,
            self.link_service.as_deref(),
            Some(self.on_arrival.as_ref()),
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
    /// The BLE advertising runner, if secrets and storage are available.
    pub ble_advertising: Option<BleAdvertising>,
}

/// Initializes the background network and storage services.
pub fn init_lifecycle<R: Runtime>(
    app: &AppHandle<R>,
    identity_state: &IdentityState,
    sign_in_state: Arc<SignInState>,
    peer_trust_state: &PeerTrustState,
    link_registry_state: &LinkRegistryState,
    link_invite_state: Arc<LinkInviteState>,
    own_display_name: Option<DisplayName>,
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

    let app_data_dir = crate::paths::app_data_dir(app)?;
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
        crate::paths::app_data_dir(app)
            .map(|p| p.join("downloads"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/tradr-downloads"))
    });
    std::fs::create_dir_all(&downloads_dir)
        .map_err(|e| format!("could not create downloads directory: {e}"))?;

    #[cfg(target_os = "android")]
    let vfs = {
        let app_cache_dir = app
            .path()
            .app_cache_dir()
            .map_err(|e| format!("could not resolve app cache directory: {e}"))?;
        Arc::new(NativeVfs::new().with_scratch_dir(app_cache_dir))
    };
    #[cfg(not(target_os = "android"))]
    let vfs = Arc::new(NativeVfs::new());
    vfs.register_root(downloads_root_id(), downloads_dir, false)
        .map_err(|e| format!("could not register downloads root: {e}"))?;

    let transport =
        tauri::async_runtime::block_on(async { bind_quic_transport(key_store.clone()) })?;
    let local_addr = transport
        .local_addr()
        .map_err(|e| format!("failed to get quic local address: {e}"))?;
    let bound_port = local_addr.port();

    let daemon = mdns_daemon()?;

    let capabilities = Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC));

    let txt_record = device_txt_record(&public_identity, capabilities.get(), own_display_name)?;

    register_advertisement(&daemon, bound_port, &txt_record, &OsRng)?;

    let mdns_source =
        MdnsSource::browse(&daemon).map_err(|e| format!("failed to browse mdns: {e}"))?;

    // `peer_trust` reports its build failure through every classification
    // rather than aborting the listener: a fresh clone with no configured
    // OAuth client ids still accepts channels, it just cannot yet promote
    // any of them past the handshake.
    let browse_access = Arc::new(BrowseAccess::new());

    let peer_trust = peer_trust_state.peer_trust();
    let sign_in_for_verify = sign_in_state.clone();
    // Reported the same way as `peer_trust` above, through `let links =
    // links?;` inside the closure, rather than substituting an empty list.
    let link_registry = link_registry_state.registry();

    let access_for_verify = Arc::clone(&browse_access);
    let verify_attestation: Arc<
        dyn Fn(AttestationRequest) -> BoxFuture<'static, Result<TrustTier, String>> + Send + Sync,
    > = Arc::new(move |req: AttestationRequest| {
        let peer_trust = peer_trust.clone();
        let sign_in = sign_in_for_verify.clone();
        let links = link_registry.clone();
        let access = Arc::clone(&access_for_verify);
        Box::pin(async move {
            let trust = peer_trust?;
            let links = links?;
            let clock = Arc::new(SystemClock);
            listener_peer_verifier(trust, sign_in, links, clock, access)(req).await
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

    let app_handle = app.clone();
    let on_arrival: ArrivalHook = Arc::new(move |peer: DeviceId, paths: &[RelPath]| {
        let payload = FilesReceivedPayload {
            device_id: peer.to_string(),
            files: paths.iter().map(|p| p.to_string()).collect(),
        };
        if let Err(e) = app_handle.emit("files-received", payload) {
            eprintln!("failed to emit files-received event: {e}");
        }
    });

    let known_devices_path = app_data_dir.join("known_devices.json");
    let known_devices = match KnownDevicesStore::open(&known_devices_path) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            return Err(format!(
                "could not open known devices store at {}: {e}",
                known_devices_path.display()
            ));
        }
    };

    let listener = Arc::new(TransferListener {
        vfs: vfs.clone(),
        key_store: key_store.clone(),
        public_identity: public_identity.clone(),
        our_attestation: sign_in_state.clone(),
        root: downloads_root_id(),
        capabilities: capabilities.clone(),
        browse_access,
        verify_attestation,
        link_service: Some(link_service),
        on_arrival: on_arrival.clone(),
        known_devices: known_devices.clone(),
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
    let (ble, ble_advertising) = match identity_state.secret_store() {
        Ok(secret_store) => {
            let broadcast_secrets = DeviceBroadcastSecrets::new(
                sign_in_state.clone(),
                link_registry_state.registry(),
                secret_store.clone(),
                abk_path.clone(),
            );
            let discovery = BleDiscovery::new(
                Box::new(broadcast_secrets),
                Box::new(SystemClock),
                peer_list.clone(),
            );
            let adv_secrets = DeviceBroadcastSecrets::new(
                sign_in_state.clone(),
                link_registry_state.registry(),
                secret_store,
                abk_path,
            );
            let advertising = BleAdvertising::new(
                Box::new(adv_secrets),
                Box::new(SystemClock),
                capabilities.clone() as Arc<dyn DeclaredCapabilities>,
                local_platform_code(),
            );
            (Some(discovery), Some(advertising))
        }
        Err(e) => {
            eprintln!("lifecycle: secret store not available: {e}");
            (None, None)
        }
    };

    let mut transports: Vec<Arc<dyn Transport>> = vec![transport.clone() as Arc<dyn Transport>];
    transports.extend(ble_central_transport(&listener, &key_store));

    let transport_set = Arc::new(TransportSet::new(transports));

    let secret_store = match identity_state.secret_store() {
        Ok(s) => s,
        Err(e) => return Err(format!("secret store not available: {e}")),
    };

    let peer_trust = peer_trust_state.peer_trust();
    let peer_trust_fn = Arc::new(move || peer_trust.clone());
    let sign_in_state_for_brokr = sign_in_state.clone();
    let own_account_fn = Arc::new(move || sign_in_state_for_brokr.own_account());
    let link_registry_for_brokr = link_registry_state.registry();
    let secrets_for_links = secret_store.clone();
    let links_fn = Arc::new(move || {
        let registry = link_registry_for_brokr.clone()?;
        let guard = registry.lock().unwrap_or_else(|p| p.into_inner());
        let mut accounts = Vec::new();
        let mut link_secrets = Vec::new();
        for link in guard.links() {
            accounts.push(link.peer_account().clone());
            if let Some(sec) = guard
                .link_secret(&link.link_id(), secrets_for_links.as_ref())
                .map_err(|e| e.to_string())?
            {
                link_secrets.push(sec);
            }
        }
        Ok(LinkView {
            accounts,
            secrets: link_secrets,
        })
    });

    let brokr_state = Arc::new(BrokrState::new(BrokrDeps {
        app_data_dir,
        secrets: secret_store,
        key_store: key_store.clone(),
        identity: public_identity.clone(),
        vfs: vfs.clone(),
        clock: Arc::new(SystemClock),
        peer_trust_fn,
        own_account_fn,
        links_fn,
        on_arrival,
    }));

    app.manage(capabilities);
    app.manage(vfs);
    app.manage(transport_set);
    app.manage(tokio::sync::Mutex::new(mdns_source));
    app.manage(tokio::sync::Mutex::new(static_peer_source));
    app.manage(tokio::sync::Mutex::new(static_peer_registry));
    app.manage(peer_list);
    app.manage(known_devices);
    app.manage(brokr_state);

    Ok(Some(LifecycleHandles {
        listener,
        ble,
        ble_advertising,
    }))
}

#[cfg(target_os = "linux")]
fn ble_central_transport(
    listener: &TransferListener,
    key_store: &Arc<dyn KeyStore>,
) -> Option<Arc<dyn Transport>> {
    match listener.key_binding() {
        Ok(binding) => {
            let central_result = tauri::async_runtime::block_on(async {
                BluerCentral::open(
                    key_store.clone(),
                    Arc::new(OsRng),
                    Arc::new(ClockKeyBindingVerifier::new(Arc::new(SystemClock))),
                    binding,
                    Arc::new(SystemClock),
                )
                .await
            });
            match central_result {
                Ok(central) => {
                    let ble_transport = BleGattTransport::new(
                        Some(Arc::new(central) as Arc<dyn tradr_transport::ble::GattCentral>),
                        None,
                    );
                    Some(Arc::new(ble_transport) as Arc<dyn Transport>)
                }
                Err(e) => {
                    eprintln!("lifecycle: failed to open ble central: {e}");
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("lifecycle: failed to create key binding for ble central: {e}");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn ble_central_transport(
    _listener: &TransferListener,
    _key_store: &Arc<dyn KeyStore>,
) -> Option<Arc<dyn Transport>> {
    None
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

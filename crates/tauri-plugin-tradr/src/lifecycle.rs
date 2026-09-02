//! Sets up the background runtime environment (WI-M1-025):
//! registers VFS roots, binds the QUIC transport, starts mDNS advertisement and browsing,
//! and runs the background transfer listener.

use std::net::SocketAddr;
use std::sync::Arc;

use mdns_sd::ServiceDaemon;
use tauri::{AppHandle, Manager, Runtime};

use tradr_core::{Capabilities, PeerList, RootId, Transport};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, MdnsSource, Platform, STATIC_PEER_DEFAULT_PORT, StaticPeerRegistry,
    TxtRecord, advertisement, instance_name,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_transport::quic::QuicTransport;
use tradr_vfs::NativeVfs;

use crate::identity::IdentityState;
use crate::listener::run_listener;
use crate::peer_trust::PeerTrustState;
use crate::sign_in::SignInState;

/// Returns the root identifier for the local downloads directory.
pub fn downloads_root_id() -> RootId {
    RootId::new(1)
}

/// Initializes the background network and storage services.
pub fn init_lifecycle<R: Runtime>(
    app: &AppHandle<R>,
    identity_state: &IdentityState,
    sign_in_state: Arc<SignInState>,
    peer_trust_state: &PeerTrustState,
) -> Result<(), String> {
    let key_store = match identity_state.key_store() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("lifecycle: key store not available: {e}");
            return Ok(());
        }
    };
    let public_identity = match identity_state.public_identity() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("lifecycle: public identity not available: {e}");
            return Ok(());
        }
    };

    let static_peers_path = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the app data directory: {e}"))?
        .join("static-peers.json");
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

    let platform = Platform::new(platform_str).map_err(|e| e.to_string())?;
    let txt_record = TxtRecord::new(
        public_identity.device_id(),
        agreement_key_tag,
        None,
        Capabilities::DIRECT_QUIC,
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

    let transport_for_listener = transport.clone();
    let vfs_for_listener = vfs.clone();
    let key_store_for_listener = key_store.clone();
    let public_identity_for_listener = public_identity.clone();
    let our_attestation = sign_in_state.clone();
    // `peer_trust` reports its build failure through every classification
    // rather than aborting the listener: a fresh clone with no configured
    // OAuth client ids still accepts channels, it just cannot yet promote
    // any of them past the handshake.
    let peer_trust = peer_trust_state.peer_trust();
    let sign_in_for_verify = sign_in_state;

    tauri::async_runtime::spawn(async move {
        if let Ok(incoming) = transport_for_listener.listen().await {
            let res = run_listener(
                incoming,
                vfs_for_listener,
                key_store_for_listener,
                public_identity_for_listener,
                our_attestation,
                downloads_root_id(),
                move |req: AttestationRequest| {
                    let peer_trust = peer_trust.clone();
                    let sign_in = sign_in_for_verify.clone();
                    async move {
                        let trust = peer_trust?;
                        let own_account = sign_in.own_account();
                        trust
                            .classify(
                                req.token(),
                                req.identity_pub(),
                                req.agreement_pub(),
                                own_account.as_ref(),
                                &[],
                                &SystemClock,
                            )
                            .await
                    }
                },
                None,
            )
            .await;
            if let Err(e) = res {
                eprintln!("listener loop exited with error: {e}");
            }
        }
    });

    app.manage(vfs);
    app.manage(transport);
    app.manage(tokio::sync::Mutex::new(mdns_source));
    app.manage(tokio::sync::Mutex::new(static_peer_source));
    app.manage(tokio::sync::Mutex::new(static_peer_registry));
    app.manage(tokio::sync::Mutex::new(PeerList::new()));

    Ok(())
}

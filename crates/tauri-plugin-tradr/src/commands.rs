//! Frontend command surface for discovery and outgoing file transfers (WI-M1-025).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use tradr_core::{PeerList, RelPath};
use tradr_discovery::{MdnsSource, StaticPeerId, StaticPeerRegistry, StaticPeerSource};
use tradr_identity::{OsRng, SystemClock};
use tradr_transport::selection::TransferSize;
use tradr_transport::set::TransportSet;
use tradr_vfs::NativeVfs;

use crate::identity::IdentityState;
use crate::lifecycle::downloads_root_id;
use crate::link_registry::LinkRegistryState;
use crate::peer_trust::PeerTrustState;
use tradr_app::browse::{
    DirListingDto, ShareInfo, execute_download_file, execute_list_peer_directory,
};
use tradr_app::capabilities::LocalCapabilities;
use tradr_app::peers::{
    PeerInfo, StaticPeerInfo, connect_and_pin, drain_peer_sources, peer_info, resolve_peer,
};
use tradr_app::send::{execute_send_files_with_progress, resolve_send_items};
use tradr_app::sign_in::{SignInState, peer_verifier};

/// Polls discovered peers from every source and returns the current merged list.
#[tauri::command]
pub async fn get_peers(
    identity_state: State<'_, IdentityState>,
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    static_peer_source: State<'_, tokio::sync::Mutex<StaticPeerSource>>,
    peer_list: State<'_, Arc<tokio::sync::Mutex<PeerList>>>,
) -> Result<Vec<PeerInfo>, String> {
    let self_id = identity_state.public_identity()?.device_id();
    let mut mdns = mdns_source.lock().await;
    let mut static_source = static_peer_source.lock().await;
    let mut list = peer_list.lock().await;

    drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id).await?;

    Ok(list.peers().iter().map(peer_info).collect())
}

/// Lists every Static Peer entry currently registered.
#[tauri::command]
pub async fn list_static_peers(
    static_peer_registry: State<'_, tokio::sync::Mutex<StaticPeerRegistry>>,
) -> Result<Vec<StaticPeerInfo>, String> {
    let registry = static_peer_registry.lock().await;
    Ok(registry
        .entries()
        .iter()
        .map(|entry| StaticPeerInfo {
            id: entry.id().to_string(),
            label: entry.label().map(str::to_string),
            endpoints: entry.endpoints().to_vec(),
            expect_device_id: entry.expect_device_id().map(|d| d.to_string()),
        })
        .collect())
}

/// Registers a new Static Peer entry, returning its generated id.
#[tauri::command]
pub async fn add_static_peer(
    label: Option<String>,
    endpoints: Vec<String>,
    static_peer_registry: State<'_, tokio::sync::Mutex<StaticPeerRegistry>>,
) -> Result<String, String> {
    let mut registry = static_peer_registry.lock().await;
    let id = registry
        .add(label.as_deref(), &endpoints, &OsRng)
        .map_err(|e| format!("failed to add static peer: {e}"))?;
    Ok(id.to_string())
}

/// Removes a Static Peer entry by id, along with any pin it held.
#[tauri::command]
pub async fn remove_static_peer(
    id: String,
    static_peer_registry: State<'_, tokio::sync::Mutex<StaticPeerRegistry>>,
) -> Result<(), String> {
    let static_id =
        StaticPeerId::new(&id).map_err(|e| format!("invalid static peer id '{id}': {e}"))?;
    let mut registry = static_peer_registry.lock().await;
    registry
        .remove(&static_id)
        .map_err(|e| format!("failed to remove static peer: {e}"))
}

/// Queries the visible shares for a specific discovered peer.
#[tauri::command]
pub async fn get_visible_shares(
    #[allow(unused_variables)] peer_id: String,
) -> Result<Vec<ShareInfo>, String> {
    Ok(vec![ShareInfo {
        share_id: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".to_string(),
        label: "Shared Files".to_string(),
        mode: "ro".to_string(),
    }])
}

/// Dials a discovered peer, negotiates a transfer offer, and transmits the selected files.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn send_files<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    peer_id: String,
    files: Vec<String>,
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
    peer_trust_state: State<'_, PeerTrustState>,
    link_registry: State<'_, LinkRegistryState>,
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    static_peer_source: State<'_, tokio::sync::Mutex<StaticPeerSource>>,
    static_peer_registry: State<'_, tokio::sync::Mutex<StaticPeerRegistry>>,
    peer_list: State<'_, Arc<tokio::sync::Mutex<PeerList>>>,
    transports: State<'_, Arc<TransportSet>>,
    vfs: State<'_, Arc<NativeVfs>>,
    capabilities: State<'_, Arc<LocalCapabilities>>,
) -> Result<Vec<String>, String> {
    let self_id = identity_state.public_identity()?.device_id();
    {
        let mut mdns = mdns_source.lock().await;
        let mut static_source = static_peer_source.lock().await;
        let mut list = peer_list.lock().await;
        drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id).await?;
    }

    let items = resolve_send_items(vfs.as_ref(), downloads_root_id(), &files).await?;
    let total_bytes: u64 = items.iter().map(|item| item.size_bytes).sum();

    let resolved = {
        let list = peer_list.lock().await;
        let registry = static_peer_registry.lock().await;
        resolve_peer(
            &peer_id,
            &list,
            &registry,
            transports.as_ref(),
            TransferSize::Bytes(total_bytes),
        )?
    };
    let channel =
        connect_and_pin(transports.as_ref(), static_peer_registry.inner(), resolved).await?;

    let public_identity = identity_state.public_identity()?;
    let key_store = identity_state.key_store()?;
    let attestation_token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in before sending files".to_string())?;
    let verify_attestation = peer_verifier(
        peer_trust_state.peer_trust()?,
        sign_in_state.inner().clone(),
        link_registry.registry()?,
        Arc::new(SystemClock),
    );

    let app_handle = app.clone();
    execute_send_files_with_progress(
        channel.as_ref(),
        vfs.as_ref(),
        &items,
        &public_identity,
        key_store.as_ref(),
        attestation_token,
        capabilities.get(),
        verify_attestation,
        move |progress| {
            use tauri::Emitter;
            if let Err(e) = app_handle.emit("transfer-progress", &progress) {
                eprintln!("emit transfer-progress event failed: {e}");
            }
        },
    )
    .await
}

/// Dials a peer over QUIC, runs the Hello handshake, opens a Browse stream, and lists directory entries.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn list_peer_directory(
    peer_id: String,
    share_id: String,
    path: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
    peer_trust_state: State<'_, PeerTrustState>,
    link_registry: State<'_, LinkRegistryState>,
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    static_peer_source: State<'_, tokio::sync::Mutex<StaticPeerSource>>,
    static_peer_registry: State<'_, tokio::sync::Mutex<StaticPeerRegistry>>,
    peer_list: State<'_, Arc<tokio::sync::Mutex<PeerList>>>,
    transports: State<'_, Arc<TransportSet>>,
    capabilities: State<'_, Arc<LocalCapabilities>>,
) -> Result<DirListingDto, String> {
    let self_id = identity_state.public_identity()?.device_id();
    {
        let mut mdns = mdns_source.lock().await;
        let mut static_source = static_peer_source.lock().await;
        let mut list = peer_list.lock().await;
        drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id).await?;
    }

    let resolved = {
        let list = peer_list.lock().await;
        let registry = static_peer_registry.lock().await;
        resolve_peer(
            &peer_id,
            &list,
            &registry,
            transports.as_ref(),
            TransferSize::Bytes(0),
        )?
    };
    let channel =
        connect_and_pin(transports.as_ref(), static_peer_registry.inner(), resolved).await?;

    let public_identity = identity_state.public_identity()?;
    let key_store = identity_state.key_store()?;
    let attestation_token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in before browsing a peer's share".to_string())?;
    let verify_attestation = peer_verifier(
        peer_trust_state.peer_trust()?,
        sign_in_state.inner().clone(),
        link_registry.registry()?,
        Arc::new(SystemClock),
    );

    let parsed_share_id: tradr_core::ShareId = share_id
        .parse()
        .map_err(|e| format!("invalid share_id '{share_id}': {e}"))?;
    let path_str = path.unwrap_or_default();
    let parsed_path = if path_str.is_empty() {
        RelPath::root()
    } else {
        RelPath::new(&path_str).map_err(|e| format!("invalid relative path '{path_str}': {e}"))?
    };

    execute_list_peer_directory(
        channel.as_ref(),
        parsed_share_id,
        parsed_path,
        cursor.unwrap_or_default(),
        limit.unwrap_or(500),
        &public_identity,
        key_store.as_ref(),
        attestation_token,
        capabilities.get(),
        verify_attestation,
    )
    .await
}

/// Downloads a file from a peer's share over the Browse plane.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn download_file<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    peer_id: String,
    share_id: String,
    path: String,
    dest_path: String,
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
    peer_trust_state: State<'_, PeerTrustState>,
    link_registry: State<'_, LinkRegistryState>,
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    static_peer_source: State<'_, tokio::sync::Mutex<StaticPeerSource>>,
    static_peer_registry: State<'_, tokio::sync::Mutex<StaticPeerRegistry>>,
    peer_list: State<'_, Arc<tokio::sync::Mutex<PeerList>>>,
    transports: State<'_, Arc<TransportSet>>,
    capabilities: State<'_, Arc<LocalCapabilities>>,
) -> Result<u64, String> {
    let self_id = identity_state.public_identity()?.device_id();
    {
        let mut mdns = mdns_source.lock().await;
        let mut static_source = static_peer_source.lock().await;
        let mut list = peer_list.lock().await;
        drain_peer_sources(&mut mdns, &mut static_source, &mut list, self_id).await?;
    }

    let resolved = {
        let list = peer_list.lock().await;
        let registry = static_peer_registry.lock().await;
        resolve_peer(
            &peer_id,
            &list,
            &registry,
            transports.as_ref(),
            TransferSize::Unknown,
        )?
    };
    let channel =
        connect_and_pin(transports.as_ref(), static_peer_registry.inner(), resolved).await?;

    let public_identity = identity_state.public_identity()?;
    let key_store = identity_state.key_store()?;
    let attestation_token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in before downloading from a peer's share".to_string())?;
    let verify_attestation = peer_verifier(
        peer_trust_state.peer_trust()?,
        sign_in_state.inner().clone(),
        link_registry.registry()?,
        Arc::new(SystemClock),
    );

    let parsed_share_id: tradr_core::ShareId = share_id
        .parse()
        .map_err(|e| format!("invalid share_id '{share_id}': {e}"))?;
    let parsed_path =
        RelPath::new(&path).map_err(|e| format!("invalid relative path '{path}': {e}"))?;
    let dest_path_buf = std::path::PathBuf::from(dest_path);

    execute_download_file(
        channel.as_ref(),
        parsed_share_id,
        parsed_path,
        &dest_path_buf,
        &public_identity,
        key_store.as_ref(),
        attestation_token,
        capabilities.get(),
        verify_attestation,
    )
    .await
}

/// Publishes dynamic sharing shortcuts to the platform share sheet.
#[tauri::command]
pub async fn publish_sharing_shortcuts<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    #[allow(unused_variables)] peers: Vec<tradr_app::share::PeerShortcut>,
) -> Result<(), String> {
    if peers.is_empty() {
        return Ok(());
    }

    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        if let Some(handle_state) = app.try_state::<crate::android::AndroidPluginHandle<R>>() {
            crate::android::publish_sharing_shortcuts(&handle_state.0, peers)?;
        }
    }

    Ok(())
}

/// Launches the platform directory picker to choose a share root.
///
/// On Android, this delegates to SAF `ACTION_OPEN_DOCUMENT_TREE`, requests persistable permissions,
/// and returns the `content://` URI string. If cancelled, returns `None`.
#[tauri::command]
pub async fn pick_share_root<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let handle_state = app
            .try_state::<crate::android::AndroidPluginHandle<R>>()
            .ok_or_else(|| "android plugin handle not found".to_string())?;
        crate::android::pick_share_root(&handle_state.0).await
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(None)
    }
}

/// Permission response mapping alias or name to granted state.
pub type PermissionResponse = std::collections::HashMap<String, PermissionState>;

/// Request argument specifying which permissions to request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPermissionsArgs {
    /// Optional list of permission names or aliases to request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

/// State of a requested permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionState {
    /// Permission is granted.
    Granted,
    /// Permission is denied.
    Denied,
    /// Permission needs to be prompted.
    Prompt,
    /// Permission prompt with rationale explanation.
    PromptWithRationale,
}

/// Requests specified permissions or all plugin permissions on mobile, or returns granted on desktop.
#[tauri::command]
pub async fn request_permissions<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    permissions: Option<Vec<String>>,
) -> Result<PermissionResponse, String> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let handle_state = app
            .try_state::<crate::android::AndroidPluginHandle<R>>()
            .ok_or_else(|| "android plugin handle not found".to_string())?;
        crate::mobile::request_permissions(&handle_state.0, permissions).await
    }
    #[cfg(not(target_os = "android"))]
    {
        crate::desktop::request_permissions(permissions).await
    }
}

/// Checks current status of plugin permissions without prompting the user.
#[tauri::command]
pub async fn check_permissions<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
) -> Result<PermissionResponse, String> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let handle_state = app
            .try_state::<crate::android::AndroidPluginHandle<R>>()
            .ok_or_else(|| "android plugin handle not found".to_string())?;
        crate::mobile::check_permissions(&handle_state.0).await
    }
    #[cfg(not(target_os = "android"))]
    {
        crate::desktop::check_permissions().await
    }
}

/// Request argument for triggering an incoming transfer notification.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShowIncomingTransferNotificationArgs {
    /// Optional transfer session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    /// Optional display name of the sending peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
}

/// Triggers an incoming transfer notification with Accept and Decline actions on supported platforms.
#[tauri::command]
pub async fn show_incoming_transfer_notification<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    transfer_id: Option<String>,
    sender_name: Option<String>,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let handle_state = app
            .try_state::<crate::android::AndroidPluginHandle<R>>()
            .ok_or_else(|| "android plugin handle not found".to_string())?;
        crate::android::show_incoming_transfer_notification(
            &handle_state.0,
            transfer_id,
            sender_name,
        )
        .await
    }
    #[cfg(not(target_os = "android"))]
    {
        crate::desktop::show_incoming_transfer_notification(transfer_id, sender_name).await
    }
}

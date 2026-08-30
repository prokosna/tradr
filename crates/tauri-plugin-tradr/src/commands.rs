//! Frontend command surface for discovery and outgoing file transfers (WI-M1-025).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tauri::State;

use tradr_core::{
    Capabilities, Clock, DeviceId, DiscoverySource, DomainTag, ItemId, KeyBinding, KeyStore,
    OfferItem, PeerExpectation, PeerList, PublicIdentity, RecvStream, RelPath, Rng, RootId,
    SecureChannel, TransferId, TransferOffer, Transport, TransportId, TrustTier, UnixTime,
    VersionRange, Vfs,
};
use tradr_discovery::{MDNS_SOURCE_ID, MdnsSource};
use tradr_identity::{OsRng, SystemClock};
use tradr_integrity::outboard;
use tradr_proto::control::{decode_transfer_accept_frame, encode_transfer_offer_frame};
use tradr_proto::framing::{Frame, FrameDecoder, encode_frame};
use tradr_transport::quic::QuicTransport;
use tradr_vfs::PosixVfs;

use crate::handshake::{HandshakeParams, perform_handshake};
use crate::identity::IdentityState;
use crate::lifecycle::downloads_root_id;
use crate::sign_in::SignInState;
use crate::transfer::{SendRequest, SessionStreams, send_file_with_progress};

/// Discovered peer representation for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's 16-byte Device ID, rendered as hex.
    pub device_id: String,
    /// The peer's advertised display name, if present.
    pub display_name: Option<String>,
    /// Available candidate addresses for reaching the peer.
    pub addresses: Vec<String>,
    /// Advertised capability bitmask.
    pub capabilities: u16,
}

/// Progress payload emitted during file transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProgressPayload {
    /// The UUID of the transfer session.
    pub transfer_id: String,
    /// The item identifier.
    pub item_id: String,
    /// The filename or relative path.
    pub rel_path: String,
    /// Number of bytes transferred so far for this item.
    pub bytes_transferred: u64,
    /// Total bytes of this item.
    pub total_bytes: u64,
    /// Current transfer status: "starting", "transferring", "completed", "failed".
    pub status: String,
}

// Bounded length and payload check protects against malicious frame allocations.
async fn read_exact(
    recv: &mut (impl RecvStream + ?Sized),
    mut buf: &mut [u8],
) -> Result<(), String> {
    while !buf.is_empty() {
        let n = recv
            .read(buf)
            .await
            .map_err(|e| format!("transport error: {e}"))?;
        if n == 0 {
            return Err("stream closed unexpectedly".to_string());
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

async fn read_frame(
    recv: &mut (impl RecvStream + ?Sized),
    max_frame_size: u32,
) -> Result<Frame, String> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    if announced == 0 {
        return Err("empty frame announced".to_string());
    }
    if announced > max_frame_size {
        return Err(format!("frame oversized: {announced} > {max_frame_size}"));
    }

    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    read_exact(recv, &mut raw[4..]).await?;

    let mut decoder = FrameDecoder::new(max_frame_size);
    decoder.feed(&raw);
    decoder
        .next_frame()
        .map_err(|e| format!("frame decoder error: {e}"))?
        .ok_or_else(|| "incomplete frame in buffer".to_string())
}

// Generates an RFC 9562 compliant UUIDv7 transfer identifier.
pub(crate) fn generate_transfer_id(rng: &dyn Rng) -> Result<TransferId, String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let mut random_bytes = [0u8; 10];
    rng.fill_bytes(&mut random_bytes)
        .map_err(|e| e.to_string())?;

    let time_bytes = now_ms.to_be_bytes();
    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&time_bytes[2..8]);
    b[6] = 0x70 | (random_bytes[0] & 0x0F);
    b[7] = random_bytes[1];
    b[8] = 0x80 | (random_bytes[2] & 0x3F);
    b[9..16].copy_from_slice(&random_bytes[3..10]);

    let s = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    );
    s.parse::<TransferId>().map_err(|e| e.to_string())
}

/// Executes the sending side of a file transfer session over an open secure channel with progress callbacks.
#[allow(clippy::too_many_arguments)]
pub async fn execute_send_files_with_progress<F>(
    channel: &dyn SecureChannel,
    vfs: &PosixVfs,
    root: RootId,
    file_names: &[String],
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
    mut on_progress: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(TransferProgressPayload) + Send,
{
    if file_names.is_empty() {
        return Err("no files provided for transfer".to_string());
    }

    let (mut control_send, mut control_recv) = channel
        .open_bi()
        .await
        .map_err(|e| format!("failed to open control stream: {e}"))?;

    let clock = SystemClock;
    let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
    let keybind_sig = key_store
        .sign(DomainTag::KeyBind, identity.agreement_pub().as_bytes())
        .map_err(|e| format!("failed to sign key binding: {e}"))?;
    let our_key_binding = KeyBinding::new(identity.agreement_pub().clone(), keybind_sig, not_after);

    let handshake_params = HandshakeParams {
        authenticated_peer: channel.peer(),
        our_channel_max_frame_size: channel.max_frame_size(),
        our_identity: identity,
        our_attestation_token: attestation_token,
        our_key_binding,
        our_versions: VersionRange::new(1, 1).map_err(|e| e.to_string())?,
        our_capabilities: Capabilities::DIRECT_QUIC,
    };

    let session = perform_handshake(
        control_send.as_mut(),
        control_recv.as_mut(),
        handshake_params,
        key_store,
        &OsRng,
        &SystemClock,
        |_| async { Ok(TrustTier::SameAccount) },
    )
    .await
    .map_err(|e| format!("handshake failed: {e}"))?;

    let transfer_id = generate_transfer_id(&OsRng)?;
    let mut offer_items = Vec::with_capacity(file_names.len());

    let mut actual_roots = std::collections::HashMap::new();
    let mut preloaded_content = std::collections::HashMap::new();
    for (idx, name) in file_names.iter().enumerate() {
        let item_id = ItemId::new(&format!("item_{}", idx + 1))
            .map_err(|e| format!("invalid item id: {e}"))?;

        if name.starts_with('/') {
            let content = tokio::fs::read(name)
                .await
                .map_err(|e| format!("failed to read '{name}': {e}"))?;

            let file_name = std::path::Path::new(name)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let rel_path = RelPath::new(&file_name)
                .map_err(|e| format!("invalid filename '{file_name}': {e}"))?;

            let (_, hash) = outboard(&content);
            let content_len = content.len() as u64;
            preloaded_content.insert(item_id, content);
            actual_roots.insert(item_id, root);
            let offer_item = OfferItem::new(item_id, rel_path, content_len, hash)
                .map_err(|e| format!("invalid offer item: {e}"))?;
            offer_items.push(offer_item);
        } else {
            let rel_path =
                RelPath::new(name).map_err(|e| format!("invalid relative path '{name}': {e}"))?;
            let meta = vfs
                .stat(root, &rel_path)
                .await
                .map_err(|e| format!("failed to stat '{name}': {e}"))?;
            let read_handle = vfs
                .open_read(root, &rel_path)
                .await
                .map_err(|e| format!("failed to open '{name}': {e}"))?;

            let mut content = vec![0u8; meta.size_bytes as usize];
            let mut total_read = 0;
            while total_read < content.len() {
                let n = read_handle
                    .read_at(total_read as u64, &mut content[total_read..])
                    .await
                    .map_err(|e| format!("read error on '{name}': {e}"))?;
                if n == 0 {
                    break;
                }
                total_read += n;
            }

            let (_, hash) = outboard(&content);
            actual_roots.insert(item_id, root);
            let offer_item = OfferItem::new(item_id, rel_path, meta.size_bytes, hash)
                .map_err(|e| format!("invalid offer item: {e}"))?;
            offer_items.push(offer_item);
        }
    }

    let total_bytes: u64 = offer_items.iter().map(|i| i.size()).sum();
    let offer = TransferOffer::new(transfer_id, offer_items.clone(), total_bytes, None, None)
        .map_err(|e| format!("invalid offer: {e}"))?;

    let offer_bytes = encode_transfer_offer_frame(&offer, session.peer_max_frame_size())
        .map_err(|e| format!("failed to encode offer: {e}"))?;
    control_send
        .write_all(&offer_bytes)
        .await
        .map_err(|e| format!("failed to send offer: {e}"))?;

    let accept_frame = read_frame(control_recv.as_mut(), channel.max_frame_size())
        .await
        .map_err(|e| format!("failed to read accept frame: {e}"))?;
    let transfer_accept = decode_transfer_accept_frame(&accept_frame)
        .map_err(|e| format!("failed to decode accept frame: {e}"))?;
    transfer_accept
        .for_offer(&offer)
        .map_err(|e| format!("accept validation failed: {e}"))?;

    let mut sent = Vec::new();
    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());

    for item_acc in transfer_accept.items() {
        if !item_acc.accepted() {
            continue;
        }
        let offer_item = offer_items
            .iter()
            .find(|i| i.item_id() == item_acc.item_id())
            .ok_or_else(|| format!("accepted item {} not found in offer", item_acc.item_id()))?;

        on_progress(TransferProgressPayload {
            transfer_id: transfer_id.to_string(),
            item_id: offer_item.item_id().to_string(),
            rel_path: offer_item.rel_path().to_string(),
            bytes_transferred: 0,
            total_bytes: offer_item.size(),
            status: "starting".to_string(),
        });

        let (mut data_send, mut data_recv) = channel
            .open_bi()
            .await
            .map_err(|e| format!("failed to open data stream: {e}"))?;

        let init_frame = encode_frame(0x24, &[], negotiated_frame_bound)
            .map_err(|e| format!("failed to encode init frame: {e}"))?;
        data_send
            .write_all(&init_frame)
            .await
            .map_err(|e| format!("failed to initialize data stream: {e}"))?;

        let actual_root = actual_roots
            .get(offer_item.item_id())
            .copied()
            .unwrap_or(root);
        let send_req = SendRequest {
            root: actual_root,
            rel_path: offer_item.rel_path(),
            transfer_id,
            item_id: *offer_item.item_id(),
            max_frame_size: negotiated_frame_bound,
        };

        let mut streams = SessionStreams {
            control_send: control_send.as_mut(),
            control_recv: control_recv.as_mut(),
            data_send: data_send.as_mut(),
            data_recv: data_recv.as_mut(),
        };

        let t_id_str = transfer_id.to_string();
        let i_id_str = offer_item.item_id().to_string();
        let r_path_str = offer_item.rel_path().to_string();

        let preloaded = preloaded_content
            .get(offer_item.item_id())
            .map(|v| v.as_slice());
        let ok = send_file_with_progress(
            vfs,
            &send_req,
            preloaded,
            &mut streams,
            |bytes_done, total_b| {
                on_progress(TransferProgressPayload {
                    transfer_id: t_id_str.clone(),
                    item_id: i_id_str.clone(),
                    rel_path: r_path_str.clone(),
                    bytes_transferred: bytes_done,
                    total_bytes: total_b,
                    status: "transferring".to_string(),
                });
            },
        )
        .await
        .map_err(|e| {
            on_progress(TransferProgressPayload {
                transfer_id: t_id_str.clone(),
                item_id: i_id_str.clone(),
                rel_path: r_path_str.clone(),
                bytes_transferred: 0,
                total_bytes: offer_item.size(),
                status: "failed".to_string(),
            });
            format!("failed sending {}: {e}", offer_item.rel_path())
        })?;

        if ok {
            on_progress(TransferProgressPayload {
                transfer_id: t_id_str,
                item_id: i_id_str,
                rel_path: r_path_str,
                bytes_transferred: offer_item.size(),
                total_bytes: offer_item.size(),
                status: "completed".to_string(),
            });
            sent.push(offer_item.rel_path().to_string());
        }
    }

    control_send
        .finish()
        .await
        .map_err(|e| format!("failed to finish control stream: {e}"))?;

    Ok(sent)
}

/// Executes the sending side of a file transfer session over an open secure channel.
pub async fn execute_send_files(
    channel: &dyn SecureChannel,
    vfs: &PosixVfs,
    root: RootId,
    file_names: &[String],
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
) -> Result<Vec<String>, String> {
    execute_send_files_with_progress(
        channel,
        vfs,
        root,
        file_names,
        identity,
        key_store,
        attestation_token,
        |_| {},
    )
    .await
}

/// Polls discovered peers from mDNS and returns the current active list.
#[tauri::command]
pub async fn get_peers(
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    peer_list: State<'_, tokio::sync::Mutex<PeerList>>,
) -> Result<Vec<PeerInfo>, String> {
    let mut source = mdns_source.lock().await;
    let mut list = peer_list.lock().await;

    while let Ok(Ok(event)) =
        tokio::time::timeout(Duration::from_millis(5), source.next_event()).await
    {
        let _ = list.apply(MDNS_SOURCE_ID, event);
    }

    let peers = list
        .peers()
        .into_iter()
        .map(|peer| {
            let device_id = peer
                .device_id()
                .map(|id| id.to_string())
                .unwrap_or_default();
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

            PeerInfo {
                device_id,
                display_name,
                addresses,
                capabilities,
            }
        })
        .collect();

    Ok(peers)
}

/// Dials a discovered peer, negotiates a transfer offer, and transmits the selected files.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn send_files<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    peer_id: String,
    files: Vec<String>,
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, SignInState>,
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    peer_list: State<'_, tokio::sync::Mutex<PeerList>>,
    transport: State<'_, Arc<QuicTransport>>,
    vfs: State<'_, Arc<PosixVfs>>,
) -> Result<Vec<String>, String> {
    let target_device_id: DeviceId = peer_id
        .parse::<DeviceId>()
        .or_else(|_| {
            let decoded = URL_SAFE_NO_PAD
                .decode(&peer_id)
                .map_err(|e| format!("invalid peer_id: {e}"))?;
            DeviceId::from_bytes(&decoded).map_err(|e| format!("invalid peer_id: {e}"))
        })
        .map_err(|e| format!("failed to parse peer_id '{peer_id}': {e}"))?;

    {
        let mut source = mdns_source.lock().await;
        let mut list = peer_list.lock().await;
        while let Ok(Ok(event)) =
            tokio::time::timeout(Duration::from_millis(5), source.next_event()).await
        {
            let _ = list.apply(MDNS_SOURCE_ID, event);
        }
    }

    let list = peer_list.lock().await;
    let peer = list
        .peer(target_device_id)
        .ok_or_else(|| format!("peer with device id {peer_id} not found"))?;

    let candidate = peer
        .candidates()
        .into_iter()
        .find(|c| c.transport() == TransportId::new("direct-quic"))
        .or_else(|| peer.candidates().first().cloned())
        .ok_or_else(|| format!("no candidate address found for peer {peer_id}"))?;
    drop(list);

    let channel = transport
        .connect(&candidate, &PeerExpectation::Device(target_device_id))
        .await
        .map_err(|e| format!("failed to connect to peer at {}: {e}", candidate.address()))?;

    let public_identity = identity_state.public_identity()?;
    let key_store = identity_state.key_store()?;
    let attestation_token = sign_in_state.id_token().unwrap_or_default();

    let app_handle = app.clone();
    execute_send_files_with_progress(
        channel.as_ref(),
        vfs.as_ref(),
        downloads_root_id(),
        &files,
        &public_identity,
        key_store.as_ref(),
        attestation_token,
        move |progress| {
            use tauri::Emitter;
            let _ = app_handle.emit("transfer-progress", &progress);
        },
    )
    .await
}

/// Publishes dynamic sharing shortcuts to the platform share sheet.
#[tauri::command]
pub async fn publish_sharing_shortcuts<R: tauri::Runtime>(
    #[allow(unused_variables)] app: tauri::AppHandle<R>,
    #[allow(unused_variables)] peers: Vec<crate::share::PeerShortcut>,
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

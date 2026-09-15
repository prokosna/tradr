//! Sending side of the file transfer pipeline (docs/04-protocol.md).

use std::future::Future;

use serde::{Deserialize, Serialize};

use tradr_core::{
    Capabilities, Clock, DomainTag, ItemId, KeyBinding, KeyStore, OfferItem, PublicIdentity,
    RecvStream, RelPath, Rng, RootId, SecureChannel, TransferId, TransferOffer, TrustTier,
    UnixTime, VersionRange, Vfs,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_integrity::outboard;
use tradr_proto::control::{decode_transfer_accept_frame, encode_transfer_offer_frame};
use tradr_proto::framing::{Frame, FrameDecoder, encode_frame};
use tradr_vfs::NativeVfs;

use crate::handshake::{HandshakeParams, perform_handshake};
use crate::transfer::{SendRequest, SessionStreams, send_file_with_progress};

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
fn generate_transfer_id(rng: &dyn Rng) -> Result<TransferId, String> {
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

// `starts_with('/')` only recognises a Unix absolute path; drag-and-drop on
// Windows hands the frontend `C:\...`, UNC or `\\?\...` paths, none of which
// start with `/`, so they fell into the relative branch and were rejected by
// `RelPath::new` (WI-M5-008). `Path::is_absolute` is the platform-correct test.
fn split_absolute_path(name: &str) -> Option<(std::path::PathBuf, String)> {
    let path = std::path::Path::new(name);
    if !path.is_absolute() {
        return None;
    }
    let parent = path.parent().unwrap_or(path).to_path_buf();
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    Some((parent, file_name))
}

/// One file resolved for a transfer offer.
#[derive(Debug)]
pub struct SendItem {
    /// The VFS root holding this file.
    pub root: RootId,
    /// Path relative to `root`.
    pub rel_path: RelPath,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// Resolves candidate file paths to VFS roots and sizes ahead of transfer offer negotiation.
pub async fn resolve_send_items(
    vfs: &NativeVfs,
    root: RootId,
    file_names: &[String],
) -> Result<Vec<SendItem>, String> {
    let mut items = Vec::with_capacity(file_names.len());
    for name in file_names {
        let (actual_root, rel_path) = if let Some((parent, file_name)) = split_absolute_path(name) {
            let r = RelPath::new(&file_name)
                .map_err(|e| format!("invalid filename '{file_name}': {e}"))?;

            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            name.hash(&mut hasher);
            let temp_root = tradr_core::RootId::new(hasher.finish());

            vfs.register_root(temp_root, parent, true)
                .map_err(|e| format!("failed to register temp root for '{name}': {e}"))?;
            (temp_root, r)
        } else {
            let r =
                RelPath::new(name).map_err(|e| format!("invalid relative path '{name}': {e}"))?;
            (root, r)
        };
        let meta = vfs
            .stat(actual_root, &rel_path)
            .await
            .map_err(|e| format!("failed to stat '{name}': {e}"))?;
        items.push(SendItem {
            root: actual_root,
            rel_path,
            size_bytes: meta.size_bytes,
        });
    }
    Ok(items)
}

/// Executes the sending side of a file transfer session over an open secure channel with progress callbacks.
#[allow(clippy::too_many_arguments)]
pub async fn execute_send_files_with_progress<F, Fut, G>(
    channel: &dyn SecureChannel,
    vfs: &NativeVfs,
    items: &[SendItem],
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
    capabilities: Capabilities,
    verify_attestation: F,
    mut on_progress: G,
) -> Result<Vec<String>, String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
    G: FnMut(TransferProgressPayload) + Send,
{
    if items.is_empty() {
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
        our_capabilities: capabilities,
    };

    let session = perform_handshake(
        control_send.as_mut(),
        control_recv.as_mut(),
        handshake_params,
        key_store,
        &OsRng,
        &SystemClock,
        verify_attestation,
    )
    .await
    .map_err(|e| format!("handshake failed: {e}"))?;

    let transfer_id = generate_transfer_id(&OsRng)?;
    let mut offer_items = Vec::with_capacity(items.len());

    let mut actual_roots = std::collections::HashMap::new();
    for (idx, item) in items.iter().enumerate() {
        let actual_root = item.root;
        let rel_path = item.rel_path.clone();

        let read_handle = vfs
            .open_read(actual_root, &rel_path)
            .await
            .map_err(|e| format!("failed to open '{rel_path}': {e}"))?;

        let mut content = vec![0u8; item.size_bytes as usize];
        let mut total_read = 0;
        while total_read < content.len() {
            let n = read_handle
                .read_at(total_read as u64, &mut content[total_read..])
                .await
                .map_err(|e| format!("read error on '{rel_path}': {e}"))?;
            if n == 0 {
                break;
            }
            total_read += n;
        }

        let (_, hash) = outboard(&content);
        let item_id = ItemId::new(&format!("item_{}", idx + 1))
            .map_err(|e| format!("invalid item id: {e}"))?;
        actual_roots.insert(item_id, actual_root);
        let offer_item = OfferItem::new(item_id, rel_path, item.size_bytes, hash)
            .map_err(|e| format!("invalid offer item: {e}"))?;
        offer_items.push(offer_item);
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
            .ok_or_else(|| format!("missing root for item {}", offer_item.item_id()))?;
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

        let ok = send_file_with_progress(vfs, &send_req, &mut streams, |bytes_done, total_b| {
            on_progress(TransferProgressPayload {
                transfer_id: t_id_str.clone(),
                item_id: i_id_str.clone(),
                rel_path: r_path_str.clone(),
                bytes_transferred: bytes_done,
                total_bytes: total_b,
                status: "transferring".to_string(),
            });
        })
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
#[allow(clippy::too_many_arguments)]
pub async fn execute_send_files<F, Fut>(
    channel: &dyn SecureChannel,
    vfs: &NativeVfs,
    root: RootId,
    file_names: &[String],
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
    capabilities: Capabilities,
    verify_attestation: F,
) -> Result<Vec<String>, String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let items = resolve_send_items(vfs, root, file_names).await?;
    execute_send_files_with_progress(
        channel,
        vfs,
        &items,
        identity,
        key_store,
        attestation_token,
        capabilities,
        verify_attestation,
        |_| {},
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::split_absolute_path;

    #[test]
    fn a_plain_relative_name_is_not_absolute() {
        assert!(split_absolute_path("report.pdf").is_none());
    }

    #[test]
    fn a_relative_name_with_a_subdirectory_is_not_absolute() {
        assert!(split_absolute_path("sub/report.pdf").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_drive_path_is_absolute() {
        let (parent, file_name) = split_absolute_path(r"C:\Users\me\report.pdf")
            .expect("a drive-letter path must be recognised as absolute");
        assert_eq!(parent, std::path::PathBuf::from(r"C:\Users\me"));
        assert_eq!(file_name, "report.pdf");
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_path_is_absolute() {
        let (parent, file_name) = split_absolute_path("/home/me/report.pdf")
            .expect("a leading-slash path must be recognised as absolute");
        assert_eq!(parent, std::path::PathBuf::from("/home/me"));
        assert_eq!(file_name, "report.pdf");
    }

    #[cfg(unix)]
    #[test]
    fn a_non_ascii_file_name_survives_the_split_unchanged() {
        let (_, file_name) = split_absolute_path("/home/me/20260830_配置図.pdf")
            .expect("a leading-slash path must be recognised as absolute");
        assert_eq!(file_name, "20260830_配置図.pdf");
    }

    #[cfg(windows)]
    #[test]
    fn a_non_ascii_file_name_survives_the_split_unchanged() {
        let (_, file_name) = split_absolute_path(r"C:\Users\me\20260830_配置図.pdf")
            .expect("a drive-letter path must be recognised as absolute");
        assert_eq!(file_name, "20260830_配置図.pdf");
    }

    #[tokio::test]
    async fn read_frame_refuses_oversized_announcement_before_payload() {
        let max = 64u32;
        let announced = max + 1;
        let mut stream =
            crate::test_recv::CountingRecvStream::new(announced.to_be_bytes().to_vec());
        let result = super::read_frame(&mut stream, max).await;
        let msg = result.expect_err("expected oversized frame refusal");
        assert!(msg.contains(&format!("frame oversized: {announced} > {max}")));
        // Distinguishes prefix refusal from decoder-side refusal after payload read.
        assert_eq!(stream.read_count(), 1);
    }
}

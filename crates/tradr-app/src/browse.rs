//! Browse plane operations for peer directory listing and file download (docs/04-protocol.md).

use std::future::Future;

use serde::{Deserialize, Serialize};

use tradr_core::{
    Capabilities, Clock, DomainTag, KeyBinding, KeyStore, PublicIdentity, RecvStream, RelPath,
    RootId, SecureChannel, SendStream, TrustTier, UnixTime, VersionRange, Vfs,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_proto::framing::{Frame, FrameDecoder};
use tradr_vfs::NativeVfs;

use crate::handshake::{HandshakeParams, perform_handshake};
use crate::send::SendItem;

/// Information about a share visible on a peer device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareInfo {
    /// The UUIDv7 share identifier.
    pub share_id: String,
    /// Human-readable label of the share.
    pub label: String,
    /// Access mode ("ro" for read-only, "rw" for read-write).
    pub mode: String,
}

/// Directory entry description returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntryDto {
    /// Relative filename.
    pub name: String,
    /// Type of entry: "file" or "directory".
    pub kind: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Modification timestamp in seconds since UNIX epoch.
    pub modified: i64,
}

/// Paginated directory listing response for frontend browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirListingDto {
    /// List of file and directory entries.
    pub entries: Vec<FileEntryDto>,
    /// Cursor for requesting the next page.
    pub next_cursor: String,
    /// Total estimated number of entries in the directory.
    pub total_estimate: u64,
}

/// Authentication parameters for Browse plane operations.
pub struct BrowseAuth<'a> {
    /// Public identity of this device.
    pub identity: &'a PublicIdentity,
    /// Key store holding the device's private keys.
    pub key_store: &'a (dyn KeyStore + Sync),
    /// Current OIDC attestation token.
    pub attestation_token: String,
    /// Advertised local capabilities.
    pub capabilities: Capabilities,
}

struct BrowseSession {
    control_send: Box<dyn SendStream>,
    browse_send: Box<dyn SendStream>,
    browse_recv: Box<dyn RecvStream>,
    negotiated_frame_bound: u32,
}

async fn open_browse_session<F, Fut>(
    channel: &dyn SecureChannel,
    auth: &BrowseAuth<'_>,
    verify_attestation: F,
) -> Result<BrowseSession, String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let (mut control_send, mut control_recv) = channel
        .open_bi()
        .await
        .map_err(|e| format!("failed to open control stream: {e}"))?;

    let clock = SystemClock;
    let not_after = UnixTime::from_secs(clock.now().as_secs() + 30 * 24 * 3600);
    let keybind_sig = auth
        .key_store
        .sign(DomainTag::KeyBind, auth.identity.agreement_pub().as_bytes())
        .map_err(|e| format!("failed to sign key binding: {e}"))?;
    let our_key_binding = KeyBinding::new(
        auth.identity.agreement_pub().clone(),
        keybind_sig,
        not_after,
    );

    let handshake_params = HandshakeParams {
        authenticated_peer: channel.peer(),
        our_channel_max_frame_size: channel.max_frame_size(),
        our_identity: auth.identity,
        our_attestation_token: auth.attestation_token.clone(),
        our_key_binding,
        our_versions: VersionRange::new(1, 1).map_err(|e| e.to_string())?,
        our_capabilities: auth.capabilities,
    };

    let session = perform_handshake(
        control_send.as_mut(),
        control_recv.as_mut(),
        handshake_params,
        auth.key_store,
        &OsRng,
        &SystemClock,
        verify_attestation,
    )
    .await
    .map_err(|e| format!("handshake failed: {e}"))?;

    let (browse_send, browse_recv) = channel
        .open_bi()
        .await
        .map_err(|e| format!("failed to open browse stream: {e}"))?;

    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());

    Ok(BrowseSession {
        control_send,
        browse_send,
        browse_recv,
        negotiated_frame_bound,
    })
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

async fn wait_for_ack(
    recv: &mut (impl RecvStream + ?Sized),
    max_frame_size: u32,
) -> Result<tradr_core::Ack, String> {
    let frame = read_frame(recv, max_frame_size).await?;
    tradr_proto::browse::decode_ack_frame(&frame)
        .map_err(|e| format!("failed to decode Ack frame: {e}"))
}

/// Executes the browse plane listing operation over an open secure channel.
#[allow(clippy::too_many_arguments)]
pub async fn execute_list_peer_directory<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    path: RelPath,
    cursor: String,
    limit: u32,
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
    capabilities: Capabilities,
    verify_attestation: F,
) -> Result<DirListingDto, String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let auth = BrowseAuth {
        identity,
        key_store,
        attestation_token,
        capabilities,
    };
    let mut session = open_browse_session(channel, &auth, verify_attestation).await?;

    let list_dir_msg = tradr_core::ListDir {
        share_id,
        path,
        cursor,
        limit,
        with_hash: false,
    };

    let frame_bytes =
        tradr_proto::browse::encode_list_dir_frame(&list_dir_msg, session.negotiated_frame_bound)
            .map_err(|e| format!("failed to encode ListDir frame: {e}"))?;
    session
        .browse_send
        .write_all(&frame_bytes)
        .await
        .map_err(|e| format!("failed to send ListDir frame: {e}"))?;

    let resp_frame = read_frame(session.browse_recv.as_mut(), channel.max_frame_size())
        .await
        .map_err(|e| format!("failed to read DirListing response: {e}"))?;

    let dir_listing = tradr_proto::browse::decode_dir_listing_frame(&resp_frame)
        .map_err(|e| format!("failed to decode DirListing frame: {e}"))?;

    let entries = dir_listing
        .entries
        .into_iter()
        .map(|entry| FileEntryDto {
            name: entry.name,
            kind: match entry.kind {
                tradr_core::EntryKind::File => "file".to_string(),
                tradr_core::EntryKind::Directory => "directory".to_string(),
            },
            size_bytes: entry.size_bytes,
            modified: entry.modified.as_secs(),
        })
        .collect();

    if let Err(e) = session.control_send.finish().await {
        eprintln!("browse directory: closing the control stream failed: {e}");
    }

    Ok(DirListingDto {
        entries,
        next_cursor: dir_listing.next_cursor,
        total_estimate: dir_listing.total_estimate,
    })
}

/// Uploads a sequence of items to a peer directory over a single browse stream.
pub async fn execute_upload_items<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    destination: RelPath,
    items: &[SendItem],
    vfs: &NativeVfs,
    auth: &BrowseAuth<'_>,
    verify_attestation: F,
) -> Result<Vec<String>, String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let mut session = open_browse_session(channel, auth, verify_attestation).await?;
    let mut uploaded_names = Vec::with_capacity(items.len());

    for (idx, item) in items.iter().enumerate() {
        let file_name = item
            .rel_path
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or(item.rel_path.as_str());

        let target_path_str = if destination.as_str().is_empty() {
            file_name.to_string()
        } else {
            format!("{}/{file_name}", destination.as_str())
        };
        let target_path = RelPath::new(&target_path_str)
            .map_err(|e| format!("invalid target path '{target_path_str}': {e}"))?;

        let write_msg = tradr_core::WriteFile {
            share_id,
            path: target_path,
            size: item.size_bytes,
            content_hash: tradr_core::ContentHash::from_bytes([0u8; 32]),
            mode: tradr_core::WriteMode::RenameIfExists,
        };

        let frame_bytes = tradr_proto::browse::encode_write_file_frame(
            &write_msg,
            session.negotiated_frame_bound,
        )
        .map_err(|e| format!("failed to encode WriteFile frame: {e}"))?;

        if let Err(e) = session.browse_send.write_all(&frame_bytes).await {
            if idx == 0 {
                return Err(format!("peer refused '{file_name}': no access ({e})"));
            }
            return Err(format!("peer refused '{file_name}': {e}"));
        }

        let reader = vfs
            .open_read(item.root, &item.rel_path)
            .await
            .map_err(|e| format!("failed to open '{}' for reading: {e}", item.rel_path))?;

        let mut offset = 0u64;
        let chunk_size = 1024 * 1024;
        let mut buf = vec![0u8; chunk_size];

        while offset < item.size_bytes {
            let to_read = ((item.size_bytes - offset).min(buf.len() as u64)) as usize;
            let n = reader
                .read_at(offset, &mut buf[..to_read])
                .await
                .map_err(|e| format!("failed reading '{}': {e}", item.rel_path))?;
            if n == 0 {
                return Err(format!("unexpected EOF reading '{}'", item.rel_path));
            }
            if let Err(e) = session.browse_send.write_all(&buf[..n]).await {
                if idx == 0 {
                    return Err(format!("peer refused '{file_name}': no access ({e})"));
                }
                return Err(format!("peer refused '{file_name}': {e}"));
            }
            offset += n as u64;
        }

        match wait_for_ack(session.browse_recv.as_mut(), channel.max_frame_size()).await {
            Ok(_) => {
                uploaded_names.push(file_name.to_string());
            }
            Err(_) => {
                if idx == 0 {
                    return Err(format!("peer refused '{file_name}': no access"));
                }
                return Err(format!("peer refused '{file_name}'"));
            }
        }
    }

    if let Err(e) = session.browse_send.finish().await {
        eprintln!("upload items: closing browse send stream failed: {e}");
    }
    if let Err(e) = session.control_send.finish().await {
        eprintln!("upload items: closing control stream failed: {e}");
    }

    Ok(uploaded_names)
}

/// Creates a directory on the peer device with parent directories enabled.
pub async fn execute_make_directory<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    path: RelPath,
    auth: &BrowseAuth<'_>,
    verify_attestation: F,
) -> Result<(), String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let mut session = open_browse_session(channel, auth, verify_attestation).await?;

    let mkdir_msg = tradr_core::Mkdir {
        share_id,
        path: path.clone(),
        parents: true,
    };

    let frame_bytes =
        tradr_proto::browse::encode_mkdir_frame(&mkdir_msg, session.negotiated_frame_bound)
            .map_err(|e| format!("failed to encode Mkdir frame: {e}"))?;

    if let Err(e) = session.browse_send.write_all(&frame_bytes).await {
        return Err(format!("peer refused '{path}': no access ({e})"));
    }

    match wait_for_ack(session.browse_recv.as_mut(), channel.max_frame_size()).await {
        Ok(_) => {}
        Err(_) => {
            return Err(format!("peer refused '{path}': no access"));
        }
    }

    if let Err(e) = session.browse_send.finish().await {
        eprintln!("make directory: closing browse send stream failed: {e}");
    }
    if let Err(e) = session.control_send.finish().await {
        eprintln!("make directory: closing control stream failed: {e}");
    }

    Ok(())
}

/// Deletes a file or directory entry on the peer device.
pub async fn execute_delete_entry<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    path: RelPath,
    recursive: bool,
    auth: &BrowseAuth<'_>,
    verify_attestation: F,
) -> Result<(), String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let mut session = open_browse_session(channel, auth, verify_attestation).await?;

    let delete_msg = tradr_core::Delete {
        share_id,
        path: path.clone(),
        recursive,
    };

    let frame_bytes =
        tradr_proto::browse::encode_delete_frame(&delete_msg, session.negotiated_frame_bound)
            .map_err(|e| format!("failed to encode Delete frame: {e}"))?;

    if let Err(e) = session.browse_send.write_all(&frame_bytes).await {
        return Err(format!("peer refused '{path}': no access ({e})"));
    }

    match wait_for_ack(session.browse_recv.as_mut(), channel.max_frame_size()).await {
        Ok(_) => {}
        Err(_) => {
            return Err(format!("peer refused '{path}': no access"));
        }
    }

    if let Err(e) = session.browse_send.finish().await {
        eprintln!("delete entry: closing browse send stream failed: {e}");
    }
    if let Err(e) = session.control_send.finish().await {
        eprintln!("delete entry: closing control stream failed: {e}");
    }

    Ok(())
}

/// Renames a file or directory entry on the peer device.
pub async fn execute_rename_entry<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    from: RelPath,
    to: RelPath,
    auth: &BrowseAuth<'_>,
    verify_attestation: F,
) -> Result<(), String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let mut session = open_browse_session(channel, auth, verify_attestation).await?;

    let rename_msg = tradr_core::Rename {
        share_id,
        from: from.clone(),
        to,
    };

    let frame_bytes =
        tradr_proto::browse::encode_rename_frame(&rename_msg, session.negotiated_frame_bound)
            .map_err(|e| format!("failed to encode Rename frame: {e}"))?;

    if let Err(e) = session.browse_send.write_all(&frame_bytes).await {
        return Err(format!("peer refused '{from}': no access ({e})"));
    }

    match wait_for_ack(session.browse_recv.as_mut(), channel.max_frame_size()).await {
        Ok(_) => {}
        Err(_) => {
            return Err(format!("peer refused '{from}': no access"));
        }
    }

    if let Err(e) = session.browse_send.finish().await {
        eprintln!("rename entry: closing browse send stream failed: {e}");
    }
    if let Err(e) = session.control_send.finish().await {
        eprintln!("rename entry: closing control stream failed: {e}");
    }

    Ok(())
}

/// Executes the browse plane file download operation over an open secure channel.
#[allow(clippy::too_many_arguments)]
pub async fn execute_download_file<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    path: RelPath,
    vfs: &NativeVfs,
    root: RootId,
    dest: RelPath,
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
    capabilities: Capabilities,
    verify_attestation: F,
) -> Result<(u64, RelPath), String>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let auth = BrowseAuth {
        identity,
        key_store,
        attestation_token,
        capabilities,
    };
    let mut session = open_browse_session(channel, &auth, verify_attestation).await?;

    let read_file_msg = tradr_core::ReadFile {
        share_id,
        path,
        offset: 0,
        length: 0,
    };

    let frame_bytes =
        tradr_proto::browse::encode_read_file_frame(&read_file_msg, session.negotiated_frame_bound)
            .map_err(|e| format!("failed to encode ReadFile frame: {e}"))?;
    session
        .browse_send
        .write_all(&frame_bytes)
        .await
        .map_err(|e| format!("failed to send ReadFile frame: {e}"))?;

    if let Err(e) = session.browse_send.finish().await {
        eprintln!("download file: closing the browse send stream failed: {e}");
    }

    let resp_frame = read_frame(session.browse_recv.as_mut(), channel.max_frame_size())
        .await
        .map_err(|e| format!("failed to read ReadFileBegin response: {e}"))?;

    let _read_file_begin = tradr_proto::browse::decode_read_file_begin_frame(&resp_frame)
        .map_err(|e| format!("failed to decode ReadFileBegin frame: {e}"))?;

    let target_path = tradr_vfs::resolve_collision(vfs, root, &dest)
        .await
        .map_err(|e| format!("failed to resolve destination: {e}"))?;

    if let Some(idx) = target_path.as_str().rfind('/') {
        let parent_str = &target_path.as_str()[..idx];
        if !parent_str.is_empty() {
            let parent_rel = RelPath::new(parent_str)
                .map_err(|e| format!("invalid parent directory '{parent_str}': {e}"))?;
            vfs.create_dir(root, &parent_rel)
                .await
                .map_err(|e| format!("failed to create destination directory: {e}"))?;
        }
    }

    let mut writer = vfs
        .open_write(root, &target_path)
        .await
        .map_err(|e| format!("failed to open destination file for write: {e}"))?;

    let mut total_bytes_written = 0u64;
    let mut read_buf = vec![0u8; 64 * 1024];

    loop {
        let n = session
            .browse_recv
            .read(&mut read_buf)
            .await
            .map_err(|e| format!("error reading file stream: {e}"))?;
        if n == 0 {
            break;
        }
        writer
            .write_at(total_bytes_written, &read_buf[..n])
            .await
            .map_err(|e| format!("error writing to destination file: {e}"))?;
        total_bytes_written += n as u64;
    }

    writer
        .sync()
        .await
        .map_err(|e| format!("failed to sync destination file: {e}"))?;

    if let Err(e) = session.control_send.finish().await {
        eprintln!("download file: closing the control stream failed: {e}");
    }

    Ok((total_bytes_written, target_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_recv::CountingRecvStream;

    #[tokio::test]
    async fn read_frame_refuses_oversized_announcement_before_payload() {
        let max = 64u32;
        let announced = max + 1;
        let mut stream = CountingRecvStream::new(announced.to_be_bytes().to_vec());
        let result = read_frame(&mut stream, max).await;
        let msg = result.expect_err("expected oversized frame refusal");
        assert!(msg.contains(&format!("frame oversized: {announced} > {max}")));
        // Distinguishes prefix refusal from decoder-side refusal after payload read.
        assert_eq!(stream.read_count(), 1);
    }
}

//! Browse plane operations for peer directory listing and file download (docs/04-protocol.md).

use std::future::Future;

use serde::{Deserialize, Serialize};

use tradr_core::{
    Capabilities, Clock, DomainTag, KeyBinding, KeyStore, PublicIdentity, RecvStream, RelPath,
    SecureChannel, TrustTier, UnixTime, VersionRange,
};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{OsRng, SystemClock};
use tradr_proto::framing::{Frame, FrameDecoder};

use crate::handshake::{HandshakeParams, perform_handshake};

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

    let (mut browse_send, mut browse_recv) = channel
        .open_bi()
        .await
        .map_err(|e| format!("failed to open browse stream: {e}"))?;

    let list_dir_msg = tradr_core::ListDir {
        share_id,
        path,
        cursor,
        limit,
        with_hash: false,
    };

    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());
    let frame_bytes =
        tradr_proto::browse::encode_list_dir_frame(&list_dir_msg, negotiated_frame_bound)
            .map_err(|e| format!("failed to encode ListDir frame: {e}"))?;
    browse_send
        .write_all(&frame_bytes)
        .await
        .map_err(|e| format!("failed to send ListDir frame: {e}"))?;

    let resp_frame = read_frame(browse_recv.as_mut(), channel.max_frame_size())
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

    if let Err(e) = control_send.finish().await {
        eprintln!("browse directory: closing the control stream failed: {e}");
    }

    Ok(DirListingDto {
        entries,
        next_cursor: dir_listing.next_cursor,
        total_estimate: dir_listing.total_estimate,
    })
}

/// Executes the browse plane file download operation over an open secure channel.
#[allow(clippy::too_many_arguments)]
pub async fn execute_download_file<F, Fut>(
    channel: &dyn SecureChannel,
    share_id: tradr_core::ShareId,
    path: RelPath,
    dest_path: &std::path::Path,
    identity: &PublicIdentity,
    key_store: &(dyn KeyStore + Sync),
    attestation_token: String,
    capabilities: Capabilities,
    verify_attestation: F,
) -> Result<u64, String>
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

    let (mut browse_send, mut browse_recv) = channel
        .open_bi()
        .await
        .map_err(|e| format!("failed to open browse stream: {e}"))?;

    let read_file_msg = tradr_core::ReadFile {
        share_id,
        path,
        offset: 0,
        length: 0,
    };

    let negotiated_frame_bound = session.peer_max_frame_size().min(channel.max_frame_size());
    let frame_bytes =
        tradr_proto::browse::encode_read_file_frame(&read_file_msg, negotiated_frame_bound)
            .map_err(|e| format!("failed to encode ReadFile frame: {e}"))?;
    browse_send
        .write_all(&frame_bytes)
        .await
        .map_err(|e| format!("failed to send ReadFile frame: {e}"))?;

    if let Err(e) = browse_send.finish().await {
        eprintln!("download file: closing the browse send stream failed: {e}");
    }

    let resp_frame = read_frame(browse_recv.as_mut(), channel.max_frame_size())
        .await
        .map_err(|e| format!("failed to read ReadFileBegin response: {e}"))?;

    let _read_file_begin = tradr_proto::browse::decode_read_file_begin_frame(&resp_frame)
        .map_err(|e| format!("failed to decode ReadFileBegin frame: {e}"))?;

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create destination directories: {e}"))?;
    }

    use std::io::Write;
    let mut out_file = std::fs::File::create(dest_path)
        .map_err(|e| format!("failed to create destination file: {e}"))?;

    let mut total_bytes_written = 0u64;
    let mut read_buf = vec![0u8; 64 * 1024];

    loop {
        let n = browse_recv
            .read(&mut read_buf)
            .await
            .map_err(|e| format!("error reading file stream: {e}"))?;
        if n == 0 {
            break;
        }
        out_file
            .write_all(&read_buf[..n])
            .map_err(|e| format!("error writing to destination file: {e}"))?;
        total_bytes_written += n as u64;
    }

    out_file
        .flush()
        .map_err(|e| format!("failed to flush destination file: {e}"))?;

    if let Err(e) = control_send.finish().await {
        eprintln!("download file: closing the control stream failed: {e}");
    }

    Ok(total_bytes_written)
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

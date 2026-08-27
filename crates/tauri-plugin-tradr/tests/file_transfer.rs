//! Supervisor-authored integration tests for end-to-end file transfers.
//! Drives sender and receiver transfer engines over connected stream pairs,
//! verifying partial-file chunk writes, fsync syncs, and atomic collision renames.
//! See docs/04-protocol.md and AGENTS.md.

use tauri_plugin_tradr::transfer::{TransferSessionError, receive_file, send_file};
use tradr_core::{
    BoxFuture, ItemId, RecvStream, RelPath, RootId, SendStream, TransferId, TransportError,
};
use tradr_vfs::PosixVfs;

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn sample_transfer() -> TransferId {
    VALID_V7.parse().expect("valid transfer id")
}

fn sample_item() -> ItemId {
    ItemId::new("photo_1").expect("valid item id")
}

struct MemorySendStream {
    sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl SendStream for MemorySendStream {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let sender = self.sender.as_ref().ok_or(TransportError::Closed)?;
            sender
                .send(buf.to_vec())
                .await
                .map_err(|_| TransportError::Closed)?;
            Ok(())
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.sender = None;
            Ok(())
        })
    }
}

struct MemoryRecvStream {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buffered: Vec<u8>,
}

impl RecvStream for MemoryRecvStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            if self.buffered.is_empty() {
                match self.receiver.recv().await {
                    Some(chunk) => self.buffered = chunk,
                    None => return Ok(0),
                }
            }
            let to_read = self.buffered.len().min(buf.len());
            buf[..to_read].copy_from_slice(&self.buffered[..to_read]);
            self.buffered.drain(..to_read);
            Ok(to_read)
        })
    }
}

fn memory_stream_pair() -> (
    (MemorySendStream, MemoryRecvStream),
    (MemorySendStream, MemoryRecvStream),
) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(64);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(64);
    let peer_a = (
        MemorySendStream {
            sender: Some(tx_a_to_b),
        },
        MemoryRecvStream {
            receiver: rx_b_to_a,
            buffered: Vec::new(),
        },
    );
    let peer_b = (
        MemorySendStream {
            sender: Some(tx_b_to_a),
        },
        MemoryRecvStream {
            receiver: rx_a_to_b,
            buffered: Vec::new(),
        },
    );
    (peer_a, peer_b)
}

#[tokio::test]
async fn single_chunk_file_transfer_succeeds_end_to_end() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_vfs = PosixVfs::new();
    let receiver_vfs = PosixVfs::new();

    let root_sender = RootId::new(1);
    let root_receiver = RootId::new(2);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    // Create a 42 KiB test file on the sender
    let src_rel = RelPath::new("document.pdf").unwrap();
    let file_content = vec![0x42u8; 42 * 1024];
    std::fs::write(sender_dir.path().join("document.pdf"), &file_content).unwrap();

    let (mut sender_streams, mut receiver_streams) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let dest_rel = RelPath::new("document.pdf").unwrap();

    let sender_task = send_file(
        &sender_vfs,
        root_sender,
        &src_rel,
        &mut sender_streams.0,
        &mut sender_streams.1,
        transfer_id,
        item_id,
        65536,
    );

    let receiver_task = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest_rel,
        file_content.len() as u64,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        transfer_id,
        item_id,
        65536,
    );

    let (sender_res, receiver_res) = tokio::try_join!(sender_task, receiver_task).unwrap();
    assert!(sender_res);
    assert_eq!(receiver_res.as_str(), "document.pdf");

    let received_bytes = std::fs::read(receiver_dir.path().join("document.pdf")).unwrap();
    assert_eq!(received_bytes, file_content);
}

#[tokio::test]
async fn multi_mebibyte_file_transfer_succeeds_across_multiple_chunks() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_vfs = PosixVfs::new();
    let receiver_vfs = PosixVfs::new();

    let root_sender = RootId::new(10);
    let root_receiver = RootId::new(20);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    // 2.5 MiB file (3 chunks)
    let total_bytes = (2.5 * 1024.0 * 1024.0) as usize;
    let mut file_content = Vec::with_capacity(total_bytes);
    for i in 0..total_bytes {
        file_content.push((i % 251) as u8);
    }
    std::fs::write(sender_dir.path().join("large_video.mp4"), &file_content).unwrap();

    let src_rel = RelPath::new("large_video.mp4").unwrap();
    let dest_rel = RelPath::new("large_video.mp4").unwrap();

    let (mut sender_streams, mut receiver_streams) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let sender_task = send_file(
        &sender_vfs,
        root_sender,
        &src_rel,
        &mut sender_streams.0,
        &mut sender_streams.1,
        transfer_id,
        item_id,
        1048576 + 4096,
    );

    let receiver_task = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest_rel,
        file_content.len() as u64,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        transfer_id,
        item_id,
        1048576 + 4096,
    );

    let (sender_res, receiver_res) = tokio::try_join!(sender_task, receiver_task).unwrap();
    assert!(sender_res);
    assert_eq!(receiver_res.as_str(), "large_video.mp4");

    let received_bytes = std::fs::read(receiver_dir.path().join("large_video.mp4")).unwrap();
    assert_eq!(received_bytes, file_content);
}

#[tokio::test]
async fn collision_resolution_safely_renames_existing_file() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_vfs = PosixVfs::new();
    let receiver_vfs = PosixVfs::new();

    let root_sender = RootId::new(100);
    let root_receiver = RootId::new(200);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    // Receiver already has photo.jpg
    std::fs::write(receiver_dir.path().join("photo.jpg"), b"existing-photo").unwrap();

    // Sender sends photo.jpg with new content
    let new_content = b"newly-transferred-photo";
    std::fs::write(sender_dir.path().join("photo.jpg"), new_content).unwrap();

    let src_rel = RelPath::new("photo.jpg").unwrap();
    let dest_rel = RelPath::new("photo.jpg").unwrap();

    let (mut sender_streams, mut receiver_streams) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let sender_task = send_file(
        &sender_vfs,
        root_sender,
        &src_rel,
        &mut sender_streams.0,
        &mut sender_streams.1,
        transfer_id,
        item_id,
        65536,
    );

    let receiver_task = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest_rel,
        new_content.len() as u64,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        transfer_id,
        item_id,
        65536,
    );

    let (sender_res, receiver_res) = tokio::try_join!(sender_task, receiver_task).unwrap();
    assert!(sender_res);
    assert_eq!(receiver_res.as_str(), "photo (2).jpg");

    // Existing photo.jpg preserved untouched
    assert_eq!(
        std::fs::read(receiver_dir.path().join("photo.jpg")).unwrap(),
        b"existing-photo"
    );
    // Newly transferred photo saved under photo (2).jpg
    assert_eq!(
        std::fs::read(receiver_dir.path().join("photo (2).jpg")).unwrap(),
        new_content
    );
}

#[tokio::test]
async fn transfer_handles_unexpected_eof_cleanly() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_vfs = PosixVfs::new();
    let receiver_vfs = PosixVfs::new();

    let root_sender = RootId::new(300);
    let root_receiver = RootId::new(400);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let (mut sender_streams, receiver_streams) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    // Close receiver stream immediately
    drop(receiver_streams.0);
    drop(receiver_streams.1);

    let src_rel = RelPath::new("test.txt").unwrap();
    std::fs::write(sender_dir.path().join("test.txt"), b"some data").unwrap();

    let sender_err = send_file(
        &sender_vfs,
        root_sender,
        &src_rel,
        &mut sender_streams.0,
        &mut sender_streams.1,
        transfer_id,
        item_id,
        65536,
    )
    .await
    .unwrap_err();

    assert!(matches!(sender_err, TransferSessionError::StreamClosed));
}

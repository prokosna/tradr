//! Supervisor-authored integration tests for end-to-end file transfers.
//! Drives sender and receiver transfer engines over connected stream pairs,
//! verifying partial-file chunk writes, fsync syncs, and atomic collision renames.
//! See docs/04-protocol.md and AGENTS.md.

use tradr_app::transfer::{
    ReceiveRequest, SendRequest, SessionStreams, TransferSessionError, prepare_item, receive_file,
    send_file,
};
use tradr_core::{
    BoxFuture, ChunkIndex, ChunkRequest, DirEntry, ItemId, Metadata, ReadAt, RecvStream, RelPath,
    RootId, SendStream, TransferId, TransportError, Vfs, VfsError, WriteAt,
};
use tradr_integrity::{BaoVerifier, outboard};
use tradr_proto::encode_chunk_request_frame;
use tradr_vfs::NativeVfs;

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

    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();

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

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let (_, hash) = outboard(&file_content);
    let (mut ctrl_sender, mut ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, mut data_receiver) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let dest_rel = RelPath::new("document.pdf").unwrap();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };
    let mut receiver_streams = SessionStreams {
        control_send: &mut ctrl_receiver.0,
        control_recv: &mut ctrl_receiver.1,
        data_send: &mut data_receiver.0,
        data_recv: &mut data_receiver.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 65536,
        item: &prepared,
    };

    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest_rel,
        total_bytes: file_content.len() as u64,
        content_hash: &hash,
        transfer_id,
        item_id,
        max_frame_size: 65536,
    };

    let sender_task = send_file(&sender_vfs, &send_req, &mut sender_streams);
    let receiver_task = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
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

    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();

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

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let (_, hash) = outboard(&file_content);
    let (mut ctrl_sender, mut ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, mut data_receiver) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };
    let mut receiver_streams = SessionStreams {
        control_send: &mut ctrl_receiver.0,
        control_recv: &mut ctrl_receiver.1,
        data_send: &mut data_receiver.0,
        data_recv: &mut data_receiver.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 1048576 + 4096,
        item: &prepared,
    };

    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest_rel,
        total_bytes: file_content.len() as u64,
        content_hash: &hash,
        transfer_id,
        item_id,
        max_frame_size: 2 * 1024 * 1024,
    };

    let sender_task = send_file(&sender_vfs, &send_req, &mut sender_streams);
    let receiver_task = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
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

    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();

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

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let (_, hash) = outboard(new_content);
    let (mut ctrl_sender, mut ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, mut data_receiver) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };
    let mut receiver_streams = SessionStreams {
        control_send: &mut ctrl_receiver.0,
        control_recv: &mut ctrl_receiver.1,
        data_send: &mut data_receiver.0,
        data_recv: &mut data_receiver.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 65536,
        item: &prepared,
    };

    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest_rel,
        total_bytes: new_content.len() as u64,
        content_hash: &hash,
        transfer_id,
        item_id,
        max_frame_size: 65536,
    };

    let sender_task = send_file(&sender_vfs, &send_req, &mut sender_streams);
    let receiver_task = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
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

    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();

    let root_sender = RootId::new(300);
    let root_receiver = RootId::new(400);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let (mut ctrl_sender, ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, data_receiver) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    // Close receiver stream immediately
    drop(ctrl_receiver);
    drop(data_receiver);

    let src_rel = RelPath::new("test.txt").unwrap();
    std::fs::write(sender_dir.path().join("test.txt"), b"some data").unwrap();

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 65536,
        item: &prepared,
    };

    let sender_err = send_file(&sender_vfs, &send_req, &mut sender_streams)
        .await
        .unwrap_err();

    assert!(matches!(sender_err, TransferSessionError::StreamClosed));
}

#[tokio::test]
async fn streaming_file_transfer_succeeds_across_non_aligned_boundaries() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let sender_vfs = NativeVfs::new();
    let receiver_vfs = NativeVfs::new();

    let root_sender = RootId::new(500);
    let root_receiver = RootId::new(600);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .unwrap();

    let total_bytes = 3 * 1024 * 1024 + 17;
    let mut file_content = Vec::with_capacity(total_bytes);
    let mut state: u32 = 0x9e37_79b9;
    while file_content.len() < total_bytes {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        file_content.extend_from_slice(&state.to_le_bytes());
    }
    file_content.truncate(total_bytes);

    let src_rel = RelPath::new("streamed_data.bin").unwrap();
    let dest_rel = RelPath::new("streamed_data.bin").unwrap();
    std::fs::write(sender_dir.path().join("streamed_data.bin"), &file_content).unwrap();

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(*prepared.hash(), tradr_integrity::outboard(&file_content).1);

    let (mut ctrl_sender, mut ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, mut data_receiver) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };
    let mut receiver_streams = SessionStreams {
        control_send: &mut ctrl_receiver.0,
        control_recv: &mut ctrl_receiver.1,
        data_send: &mut data_receiver.0,
        data_recv: &mut data_receiver.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 1048576 + 4096,
        item: &prepared,
    };

    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest_rel,
        total_bytes: file_content.len() as u64,
        content_hash: prepared.hash(),
        transfer_id,
        item_id,
        max_frame_size: 2 * 1024 * 1024,
    };

    let sender_task = send_file(&sender_vfs, &send_req, &mut sender_streams);
    let receiver_task = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
    );

    let (sender_res, receiver_res) = tokio::try_join!(sender_task, receiver_task).unwrap();
    assert!(sender_res);
    assert_eq!(receiver_res.as_str(), "streamed_data.bin");

    let received_bytes = std::fs::read(receiver_dir.path().join("streamed_data.bin")).unwrap();
    assert_eq!(received_bytes, file_content);
}

#[tokio::test]
async fn file_size_change_between_preparation_and_send_fails_with_source_changed() {
    use std::io::Write;

    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(700);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();

    let file_content = vec![0x5au8; 64 * 1024];
    let src_rel = RelPath::new("changing_file.dat").unwrap();
    let file_path = sender_dir.path().join("changing_file.dat");
    std::fs::write(&file_path, &file_content).unwrap();

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&file_path)
        .unwrap();
    file.write_all(b"extra appended bytes").unwrap();
    drop(file);

    let (mut ctrl_sender, ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, data_receiver) = memory_stream_pair();
    drop(ctrl_receiver);
    drop(data_receiver);
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 65536,
        item: &prepared,
    };

    let err = send_file(&sender_vfs, &send_req, &mut sender_streams)
        .await
        .unwrap_err();

    assert!(matches!(err, TransferSessionError::SourceChanged));
    assert_eq!(
        err.to_string(),
        "the file changed size since it was offered"
    );
}

struct TruncatedReadVfs {
    inner: NativeVfs,
    reported_size: u64,
}

impl Vfs for TruncatedReadVfs {
    fn list<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        self.inner.list(root, at)
    }

    fn stat<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            let mut meta = self.inner.stat(root, at).await?;
            meta.size_bytes = self.reported_size;
            Ok(meta)
        })
    }

    fn open_read<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        self.inner.open_read(root, at)
    }

    fn create_dir<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        self.inner.create_dir(root, at)
    }

    fn open_write<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        self.inner.open_write(root, at)
    }

    fn rename<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        self.inner.rename(root, from, to)
    }

    fn rename_no_replace<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        self.inner.rename_no_replace(root, from, to)
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        self.inner.remove(root, at)
    }
}

#[tokio::test]
async fn file_read_shorter_than_prepared_size_fails_with_source_changed() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(800);

    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .unwrap();

    let file_content = vec![0x3cu8; 64 * 1024];
    let src_rel = RelPath::new("short_read.dat").unwrap();
    let file_path = sender_dir.path().join("short_read.dat");
    std::fs::write(&file_path, &file_content).unwrap();

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src_rel,
        sender_vfs.scratch_file().unwrap(),
    )
    .await
    .unwrap();

    std::fs::write(&file_path, &file_content[..1024]).unwrap();

    let double_vfs = TruncatedReadVfs {
        inner: sender_vfs,
        reported_size: prepared.size(),
    };

    let (mut ctrl_sender, ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, mut data_receiver) = memory_stream_pair();
    let transfer_id = sample_transfer();
    let item_id = sample_item();

    let mut sender_streams = SessionStreams {
        control_send: &mut ctrl_sender.0,
        control_recv: &mut ctrl_sender.1,
        data_send: &mut data_sender.0,
        data_recv: &mut data_sender.1,
    };

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src_rel,
        transfer_id,
        item_id,
        max_frame_size: 65536,
        item: &prepared,
    };

    let req = ChunkRequest::new(transfer_id, item_id, ChunkIndex::new(0), 1);
    let req_frame = encode_chunk_request_frame(&req, 65536).unwrap();
    data_receiver.0.write_all(&req_frame).await.unwrap();

    drop(ctrl_receiver);
    drop(data_receiver.0);

    let err = send_file(&double_vfs, &send_req, &mut sender_streams)
        .await
        .unwrap_err();

    assert!(matches!(err, TransferSessionError::SourceChanged));
    assert_eq!(
        err.to_string(),
        "the file changed size since it was offered"
    );
}

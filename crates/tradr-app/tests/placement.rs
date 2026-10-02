//! Integration tests for atomic placement and collision avoidance during transfer.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tradr_app::transfer::{
    ReceiveRequest, SendRequest, SessionStreams, prepare_item, receive_file, send_file,
};
use tradr_core::{
    BoxFuture, DirEntry, ItemId, Metadata, ReadAt, RecvStream, RelPath, RootId, SendStream,
    TransferId, TransportError, Vfs, VfsError, WriteAt,
};
use tradr_integrity::BaoVerifier;
use tradr_proto::data::decode_item_complete_frame;
use tradr_proto::framing::FrameDecoder;
use tradr_vfs::NativeVfs;

const FRAME_BOUND: u32 = 2 * 1024 * 1024;

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

struct SnoopingSendStream {
    inner: MemorySendStream,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl SendStream for SnoopingSendStream {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        self.captured.lock().unwrap().extend_from_slice(buf);
        self.inner.write_all(buf)
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        self.inner.finish()
    }
}

fn memory_stream_pair() -> (
    (MemorySendStream, MemoryRecvStream),
    (MemorySendStream, MemoryRecvStream),
) {
    let (tx_a_to_b, rx_a_to_b) = tokio::sync::mpsc::channel(64);
    let (tx_b_to_a, rx_b_to_a) = tokio::sync::mpsc::channel(64);
    (
        (
            MemorySendStream {
                sender: Some(tx_a_to_b),
            },
            MemoryRecvStream {
                receiver: rx_b_to_a,
                buffered: Vec::new(),
            },
        ),
        (
            MemorySendStream {
                sender: Some(tx_b_to_a),
            },
            MemoryRecvStream {
                receiver: rx_a_to_b,
                buffered: Vec::new(),
            },
        ),
    )
}

struct RacingVfs {
    inner: NativeVfs,
    target_path: PathBuf,
    competing_content: Vec<u8>,
    raced: AtomicBool,
}

impl RacingVfs {
    fn trigger_race_before_move(&self, to: &RelPath) {
        if to.as_str() == "photo.jpg" && !self.raced.swap(true, Ordering::SeqCst) {
            std::fs::write(&self.target_path, &self.competing_content)
                .expect("write competing file at target");
        }
    }
}

impl Vfs for RacingVfs {
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
        self.inner.stat(root, at)
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
        self.trigger_race_before_move(to);
        self.inner.rename(root, from, to)
    }

    fn rename_no_replace<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        self.trigger_race_before_move(to);
        self.inner.rename_no_replace(root, from, to)
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        self.inner.remove(root, at)
    }
}

#[tokio::test]
async fn item_racing_target_lands_as_collision_number_and_leaves_target_untouched() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");

    let file_content = b"camera sensor bytes for photo".to_vec();
    let competing_content = b"another concurrent placement won the race".to_vec();

    std::fs::write(sender_dir.path().join("photo.jpg"), &file_content).expect("write src file");

    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .expect("register sender root");

    let receiver_native_vfs = NativeVfs::new();
    let root_receiver = RootId::new(2);
    receiver_native_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register receiver root");

    let racing_vfs = RacingVfs {
        inner: receiver_native_vfs,
        target_path: receiver_dir.path().join("photo.jpg"),
        competing_content: competing_content.clone(),
        raced: AtomicBool::new(false),
    };

    let src = RelPath::new("photo.jpg").expect("src relpath");
    let dest = RelPath::new("photo.jpg").expect("dest relpath");
    let transfer_id: TransferId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("transfer id");
    let item_id = ItemId::new("photo_item_1").expect("item id");

    let prepared = prepare_item(
        &sender_vfs,
        root_sender,
        &src,
        sender_vfs.scratch_file().expect("scratch file"),
    )
    .await
    .expect("prepare item");

    let send_req = SendRequest {
        root: root_sender,
        rel_path: &src,
        transfer_id,
        item_id,
        max_frame_size: FRAME_BOUND,
        item: &prepared,
    };

    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest,
        total_bytes: file_content.len() as u64,
        content_hash: prepared.hash(),
        transfer_id,
        item_id,
        max_frame_size: FRAME_BOUND,
    };

    let (mut sender_ctrl, mut receiver_ctrl) = memory_stream_pair();
    let (mut sender_data, mut receiver_data) = memory_stream_pair();

    let captured_control = Arc::new(Mutex::new(Vec::new()));
    let mut snooping_control_send = SnoopingSendStream {
        inner: receiver_ctrl.0,
        captured: Arc::clone(&captured_control),
    };

    let mut sender_streams = SessionStreams {
        control_send: &mut sender_ctrl.0,
        control_recv: &mut sender_ctrl.1,
        data_send: &mut sender_data.0,
        data_recv: &mut sender_data.1,
    };

    let mut receiver_streams = SessionStreams {
        control_send: &mut snooping_control_send,
        control_recv: &mut receiver_ctrl.1,
        data_send: &mut receiver_data.0,
        data_recv: &mut receiver_data.1,
    };

    let (send_res, recv_res) = tokio::join!(
        send_file(&sender_vfs, &send_req, &mut sender_streams),
        receive_file(&racing_vfs, &recv_req, &BaoVerifier, &mut receiver_streams,)
    );

    let sender_status = send_res.expect("send_file must succeed");
    assert!(sender_status, "sender must observe item completion");

    let final_path = recv_res.expect("receive_file must succeed");
    assert_eq!(
        final_path.as_str(),
        "photo (2).jpg",
        "file must be placed as photo (2).jpg due to collision race"
    );

    let competing_file = receiver_dir.path().join("photo.jpg");
    let placed_file = receiver_dir.path().join("photo (2).jpg");

    assert_eq!(
        std::fs::read(&competing_file).expect("read competing file"),
        competing_content,
        "competing file must remain untouched"
    );

    assert_eq!(
        std::fs::read(&placed_file).expect("read placed file"),
        file_content,
        "placed file must match sent content"
    );

    let captured_bytes = captured_control.lock().unwrap().clone();
    let mut decoder = FrameDecoder::new(FRAME_BOUND);
    decoder.feed(&captured_bytes);
    let frame = decoder
        .next_frame()
        .expect("decode framing")
        .expect("frame must be present");
    let item_complete = decode_item_complete_frame(&frame).expect("decode ItemComplete");
    assert!(item_complete.is_verified(), "item must be verified");
    assert_eq!(
        item_complete.final_path().map(|p| p.as_str()),
        Some("photo (2).jpg"),
        "ItemComplete must report photo (2).jpg"
    );
}

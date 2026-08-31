//! Supervisor-mandated tests for plane discipline and frame classification
//! (docs/04-protocol.md, "The three planes", and WI-M1-021).
//! Verifies that wrong-plane frames, zero codes, and out-of-order control codes
//! are refused with ProtocolViolation, while unassigned in-plane codes are skipped.

use tauri_plugin_tradr::transfer::{
    ReceiveRequest, SendRequest, SessionStreams, TransferSessionError, receive_file, send_file,
};
use tradr_core::{
    BoxFuture, ChunkDataHeader, ChunkIndex, ChunkRequest, ItemComplete, ItemId, RecvStream,
    RelPath, RootId, SendStream, TransferId, TransportError,
};
use tradr_integrity::{BaoVerifier, outboard, slice};
use tradr_proto::data::{
    decode_chunk_data_header_frame, encode_chunk_data_header_frame, encode_chunk_request_frame,
    encode_item_complete_frame,
};
use tradr_proto::framing::{FrameDecoder, encode_frame};
use tradr_vfs::NativeVfs;

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
const FRAME_BOUND: u32 = 2 * 1024 * 1024;

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

async fn read_exact_test(
    recv: &mut MemoryRecvStream,
    buf: &mut [u8],
) -> Result<(), TransportError> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = recv.read(&mut buf[offset..]).await?;
        if n == 0 {
            return Err(TransportError::Closed);
        }
        offset += n;
    }
    Ok(())
}

async fn read_frame_test(
    recv: &mut MemoryRecvStream,
    limit: u32,
) -> Result<tradr_proto::framing::Frame, TransportError> {
    let mut len_bytes = [0u8; 4];
    read_exact_test(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    read_exact_test(recv, &mut raw[4..]).await?;

    let mut decoder = FrameDecoder::new(limit);
    decoder.feed(&raw);
    decoder
        .next_frame()
        .map_err(|_| TransportError::Io(std::io::ErrorKind::InvalidData))?
        .ok_or(TransportError::Closed)
}

#[tokio::test]
async fn item_complete_on_the_data_stream_is_refused() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let sender_vfs = NativeVfs::new();
    let root_sender = RootId::new(1);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .expect("register root");

    let file_content = vec![0x42u8; 1024];
    std::fs::write(sender_dir.path().join("doc.txt"), &file_content).expect("write file");

    let (mut ctrl_sender, mut _ctrl_receiver) = memory_stream_pair();
    let (mut data_sender, mut data_receiver) = memory_stream_pair();

    let transfer_id = sample_transfer();
    let item_id = sample_item();
    let src_rel = RelPath::new("doc.txt").expect("relpath");

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
        max_frame_size: FRAME_BOUND,
    };

    let peer_task = async {
        // Receiver requests chunk 0
        let req = ChunkRequest::new(transfer_id, item_id, ChunkIndex::new(0), 1);
        let req_frame =
            encode_chunk_request_frame(&req, FRAME_BOUND).expect("encode chunk request");
        data_receiver
            .0
            .write_all(&req_frame)
            .await
            .expect("write request");

        // Receiver reads ChunkData header and payload
        let header_frame = read_frame_test(&mut data_receiver.1, FRAME_BOUND)
            .await
            .expect("read header");
        let header = decode_chunk_data_header_frame(&header_frame).expect("decode header");
        let mut payload = vec![0u8; header.payload_len() as usize];
        read_exact_test(&mut data_receiver.1, &mut payload)
            .await
            .expect("read payload");

        // Errant peer writes ItemComplete directly to the DATA stream
        let item_complete = ItemComplete::new(transfer_id, item_id, true, Some(src_rel.clone()));
        let item_complete_frame =
            encode_item_complete_frame(&item_complete, FRAME_BOUND).expect("encode item complete");
        data_receiver
            .0
            .write_all(&item_complete_frame)
            .await
            .expect("write item complete");
    };

    let (sender_res, _) = tokio::join!(
        send_file(&sender_vfs, &send_req, &mut sender_streams),
        peer_task,
    );

    let err = sender_res.expect_err("ItemComplete on Data stream must be refused");
    assert!(
        matches!(err, TransferSessionError::ProtocolViolation(_)),
        "expected ProtocolViolation, got: {err:?}"
    );
}

#[tokio::test]
async fn a_control_plane_code_on_the_data_stream_is_refused() {
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(2);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register root");

    let (mut receiver_ctrl, _peer_ctrl) = memory_stream_pair();
    let (mut receiver_data, mut peer_data) = memory_stream_pair();

    let mut receiver_streams = SessionStreams {
        control_send: &mut receiver_ctrl.0,
        control_recv: &mut receiver_ctrl.1,
        data_send: &mut receiver_data.0,
        data_recv: &mut receiver_data.1,
    };

    let dest = RelPath::new("photo.raw").expect("relpath");
    let (_, hash) = outboard(b"some content");
    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest,
        total_bytes: 12,
        content_hash: &hash,
        transfer_id: sample_transfer(),
        item_id: sample_item(),
        max_frame_size: FRAME_BOUND,
    };

    // Peer writes Hello (0x01, Control plane) onto the Data stream
    let hello_frame = encode_frame(0x01, b"hello-payload", FRAME_BOUND).expect("encode hello");
    peer_data
        .0
        .write_all(&hello_frame)
        .await
        .expect("write hello");

    let outcome = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
    )
    .await;

    let err = outcome.expect_err("Control plane code on Data stream must be refused");
    match err {
        TransferSessionError::ProtocolViolation(msg) => {
            assert!(
                msg.contains("belongs to Control's range"),
                "expected refusal mentioning Control's range, got: {msg}"
            );
        }
        other => panic!("expected ProtocolViolation, got: {other:?}"),
    }
}

#[tokio::test]
async fn a_zero_type_code_on_the_data_stream_is_refused() {
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(2);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register root");

    let (mut receiver_ctrl, _peer_ctrl) = memory_stream_pair();
    let (mut receiver_data, mut peer_data) = memory_stream_pair();

    let mut receiver_streams = SessionStreams {
        control_send: &mut receiver_ctrl.0,
        control_recv: &mut receiver_ctrl.1,
        data_send: &mut receiver_data.0,
        data_recv: &mut receiver_data.1,
    };

    let dest = RelPath::new("photo.raw").expect("relpath");
    let (_, hash) = outboard(b"some content");
    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest,
        total_bytes: 12,
        content_hash: &hash,
        transfer_id: sample_transfer(),
        item_id: sample_item(),
        max_frame_size: FRAME_BOUND,
    };

    // Peer writes a frame with 0x00 type byte onto the Data stream
    let zero_frame = encode_frame(0x00, b"", FRAME_BOUND).expect("encode 0x00");
    peer_data
        .0
        .write_all(&zero_frame)
        .await
        .expect("write zero frame");

    let outcome = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
    )
    .await;

    let err = outcome.expect_err("0x00 code on Data stream must be refused");
    match err {
        TransferSessionError::ProtocolViolation(msg) => {
            assert!(
                msg.contains("0x00 is never a valid type byte"),
                "expected refusal mentioning 0x00 is never valid, got: {msg}"
            );
        }
        other => panic!("expected ProtocolViolation, got: {other:?}"),
    }
}

#[tokio::test]
async fn an_unassigned_data_plane_code_is_skipped() {
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let receiver_vfs = NativeVfs::new();
    let root_receiver = RootId::new(2);
    receiver_vfs
        .register_root(root_receiver, receiver_dir.path().to_path_buf(), false)
        .expect("register root");

    let (mut receiver_ctrl, _peer_ctrl) = memory_stream_pair();
    let (mut receiver_data, mut peer_data) = memory_stream_pair();

    let file_content = b"honest chunk payload";
    let (ob, hash) = outboard(file_content);
    let piece_slice = slice(file_content, &ob, 0, file_content.len() as u64).expect("extract");

    let dest = RelPath::new("photo.raw").expect("relpath");
    let recv_req = ReceiveRequest {
        root: root_receiver,
        dest_rel_path: &dest,
        total_bytes: file_content.len() as u64,
        content_hash: &hash,
        transfer_id: sample_transfer(),
        item_id: sample_item(),
        max_frame_size: FRAME_BOUND,
    };

    // 1. Peer sends unassigned Data plane code 0x24 ahead of the real chunk
    let unassigned_frame =
        encode_frame(0x24, b"arbitrary-future-extension", FRAME_BOUND).expect("encode unassigned");
    peer_data
        .0
        .write_all(&unassigned_frame)
        .await
        .expect("write unassigned frame");

    // 2. Peer sends genuine ChunkData header and piece slice
    let header = ChunkDataHeader::new(
        sample_transfer(),
        sample_item(),
        ChunkIndex::new(0),
        piece_slice.len() as u32,
        true,
        0,
    )
    .expect("header");
    let header_frame = encode_chunk_data_header_frame(&header, FRAME_BOUND).expect("encode header");
    peer_data
        .0
        .write_all(&header_frame)
        .await
        .expect("write header");
    peer_data
        .0
        .write_all(&piece_slice)
        .await
        .expect("write payload");

    let mut receiver_streams = SessionStreams {
        control_send: &mut receiver_ctrl.0,
        control_recv: &mut receiver_ctrl.1,
        data_send: &mut receiver_data.0,
        data_recv: &mut receiver_data.1,
    };

    let outcome = receive_file(
        &receiver_vfs,
        &recv_req,
        &BaoVerifier,
        &mut receiver_streams,
    )
    .await;

    let final_path = outcome.expect("unassigned data plane code must be skipped cleanly");
    assert_eq!(final_path.as_str(), "photo.raw");
    let landed = std::fs::read(receiver_dir.path().join("photo.raw")).expect("read file");
    assert_eq!(landed, file_content);
}

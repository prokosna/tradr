//! Supervisor-authored tests that a receiver verifies before it writes
//! (CLAUDE.md section 6). docs/04: "Written the other way round, the same
//! code appears to work and defends nothing." These drive a hostile sender
//! that speaks the wire directly, because a well-behaved `send_file` cannot
//! produce the frames that matter here.

use tauri_plugin_tradr::transfer::{receive_file, send_file};
use tradr_core::{
    BoxFuture, ChunkDataHeader, ChunkIndex, ItemId, RecvStream, RelPath, RootId, SendStream,
    TransferId, TransportError,
};
use tradr_integrity::{BaoVerifier, outboard, slice};
use tradr_proto::data::encode_chunk_data_header_frame;
use tradr_vfs::PosixVfs;

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
const MIB: u64 = 1024 * 1024;
const FRAME_BOUND: u32 = 2 * 1024 * 1024;

fn sample_transfer() -> TransferId {
    VALID_V7.parse().expect("valid transfer id")
}

fn sample_item() -> ItemId {
    ItemId::new("photo_1").expect("valid item id")
}

fn content(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u32 = 0x9e37_79b9;
    while out.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
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

fn receiver_root(dir: &std::path::Path) -> (PosixVfs, RootId) {
    let vfs = PosixVfs::new();
    let root = RootId::new(2);
    vfs.register_root(root, dir.to_path_buf(), false)
        .expect("register root");
    (vfs, root)
}

// One ChunkData header plus its payload, as a peer would put them on the
// wire. The header is well formed in every case here: what is under test
// is whether the receiver checks the bytes, not whether it parses them.
async fn feed_piece(
    send: &mut MemorySendStream,
    chunk_index: u64,
    offset_in_chunk: u32,
    last: bool,
    payload: &[u8],
) {
    let header = ChunkDataHeader::new(
        sample_transfer(),
        sample_item(),
        ChunkIndex::new(chunk_index),
        payload.len() as u32,
        last,
        offset_in_chunk,
    )
    .expect("the header itself is inside every bound");
    let frame = encode_chunk_data_header_frame(&header, FRAME_BOUND).expect("encodes");
    send.write_all(&frame).await.expect("buffered channel");
    send.write_all(payload).await.expect("buffered channel");
}

#[tokio::test]
async fn a_verified_transfer_arrives_byte_identical() {
    let sender_dir = tempfile::tempdir().expect("sender tempdir");
    let receiver_dir = tempfile::tempdir().expect("receiver tempdir");
    let file_content = content((2 * MIB + 4096) as usize);
    std::fs::write(sender_dir.path().join("photo.raw"), &file_content).expect("write source");

    let sender_vfs = PosixVfs::new();
    let root_sender = RootId::new(1);
    sender_vfs
        .register_root(root_sender, sender_dir.path().to_path_buf(), false)
        .expect("register sender root");
    let (receiver_vfs, root_receiver) = receiver_root(receiver_dir.path());

    let (_, hash) = outboard(&file_content);
    let (mut sender_streams, mut receiver_streams) = memory_stream_pair();
    let src = RelPath::new("photo.raw").expect("relpath");
    let dest = RelPath::new("photo.raw").expect("relpath");

    let (sent, received) = tokio::join!(
        send_file(
            &sender_vfs,
            root_sender,
            &src,
            &mut sender_streams.0,
            &mut sender_streams.1,
            sample_transfer(),
            sample_item(),
            FRAME_BOUND,
        ),
        receive_file(
            &receiver_vfs,
            root_receiver,
            &dest,
            file_content.len() as u64,
            &hash,
            &BaoVerifier,
            &mut receiver_streams.0,
            &mut receiver_streams.1,
            sample_transfer(),
            sample_item(),
            FRAME_BOUND,
        )
    );

    let final_path = received.expect("an honest transfer must complete");
    sent.expect("the sender must see it complete");
    let landed = std::fs::read(receiver_dir.path().join(final_path.as_str())).expect("read result");
    assert_eq!(
        landed, file_content,
        "the bytes that arrived must be the bytes that were sent"
    );
}

#[tokio::test]
async fn a_corrupted_piece_leaves_nothing_at_the_destination() {
    let receiver_dir = tempfile::tempdir().expect("tempdir");
    let file_content = content(MIB as usize);
    let (ob, hash) = outboard(&file_content);
    let mut tampered = slice(&file_content, &ob, 0, MIB).expect("extract");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let (receiver_vfs, root_receiver) = receiver_root(receiver_dir.path());
    let (mut hostile, mut receiver_streams) = memory_stream_pair();
    feed_piece(&mut hostile.0, 0, 0, true, &tampered).await;

    let dest = RelPath::new("photo.raw").expect("relpath");
    let outcome = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest,
        file_content.len() as u64,
        &hash,
        &BaoVerifier,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        sample_transfer(),
        sample_item(),
        FRAME_BOUND,
    )
    .await;

    assert!(
        outcome.is_err(),
        "a piece that does not verify must not complete a transfer"
    );
    assert!(
        !receiver_dir.path().join("photo.raw").exists(),
        "nothing that failed verification may reach the destination"
    );
}

#[tokio::test]
async fn a_piece_for_another_chunk_is_refused() {
    let receiver_dir = tempfile::tempdir().expect("tempdir");
    let file_content = content((3 * MIB) as usize);
    let (ob, hash) = outboard(&file_content);
    // Chunk 1's bytes, verifiable in their own right, offered as chunk 0.
    let borrowed = slice(&file_content, &ob, MIB, MIB).expect("extract");

    let (receiver_vfs, root_receiver) = receiver_root(receiver_dir.path());
    let (mut hostile, mut receiver_streams) = memory_stream_pair();
    feed_piece(&mut hostile.0, 0, 0, false, &borrowed).await;

    let dest = RelPath::new("photo.raw").expect("relpath");
    let outcome = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest,
        file_content.len() as u64,
        &hash,
        &BaoVerifier,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        sample_transfer(),
        sample_item(),
        FRAME_BOUND,
    )
    .await;

    assert!(
        outcome.is_err(),
        "docs/04: a wrong offset must fail verification rather than corrupt the file"
    );
    assert!(!receiver_dir.path().join("photo.raw").exists());
}

#[tokio::test]
async fn a_chunk_index_past_the_item_is_refused_before_anything_is_written() {
    let receiver_dir = tempfile::tempdir().expect("tempdir");
    let file_content = content(MIB as usize);
    let (ob, hash) = outboard(&file_content);
    let honest = slice(&file_content, &ob, 0, MIB).expect("extract");

    let (receiver_vfs, root_receiver) = receiver_root(receiver_dir.path());
    let (mut hostile, mut receiver_streams) = memory_stream_pair();
    // A one-chunk item, and the peer names chunk 4096: the absolute offset
    // is four gigabytes, and computing it before bounding it is what turns
    // a refusal into a sparse file the size of the claim.
    feed_piece(&mut hostile.0, 4096, 0, true, &honest).await;

    let dest = RelPath::new("photo.raw").expect("relpath");
    let outcome = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest,
        file_content.len() as u64,
        &hash,
        &BaoVerifier,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        sample_transfer(),
        sample_item(),
        FRAME_BOUND,
    )
    .await;

    assert!(
        outcome.is_err(),
        "a chunk the item does not contain must be refused"
    );
    let partial_bytes: u64 = walkdir(receiver_dir.path());
    assert!(
        partial_bytes <= MIB,
        "refusing after the write leaves {partial_bytes} bytes on disk for a one-chunk item"
    );
}

fn walkdir(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            total += walkdir(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

#[tokio::test]
async fn a_piece_with_wrong_transfer_id_is_refused() {
    let receiver_dir = tempfile::tempdir().expect("tempdir");
    let file_content = content(MIB as usize);
    let (ob, hash) = outboard(&file_content);
    let honest = slice(&file_content, &ob, 0, MIB).expect("extract");

    let (receiver_vfs, root_receiver) = receiver_root(receiver_dir.path());
    let (mut hostile, mut receiver_streams) = memory_stream_pair();

    // Construct a header with the WRONG transfer_id
    let wrong_transfer_id: TransferId = "017f22e2-79b0-7cc3-98c4-dc0c0c07398e".parse().unwrap();
    let header = ChunkDataHeader::new(
        wrong_transfer_id,
        sample_item(),
        ChunkIndex::new(0),
        honest.len() as u32,
        true,
        0,
    )
    .unwrap();

    let frame = encode_chunk_data_header_frame(&header, FRAME_BOUND).unwrap();
    hostile.0.write_all(&frame).await.unwrap();
    hostile.0.write_all(&honest).await.unwrap();
    hostile.0.finish().await.unwrap(); // Close stream to unblock receive_file

    let dest = RelPath::new("photo.raw").expect("relpath");
    let outcome = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest,
        file_content.len() as u64,
        &hash,
        &BaoVerifier,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        sample_transfer(), // The session's transfer ID
        sample_item(),
        FRAME_BOUND,
    )
    .await;

    assert!(
        outcome.is_err(),
        "a chunk for a different transfer must be refused"
    );
}

#[tokio::test]
async fn a_piece_with_wrong_item_id_is_refused() {
    let receiver_dir = tempfile::tempdir().expect("tempdir");
    let file_content = content(MIB as usize);
    let (ob, hash) = outboard(&file_content);
    let honest = slice(&file_content, &ob, 0, MIB).expect("extract");

    let (receiver_vfs, root_receiver) = receiver_root(receiver_dir.path());
    let (mut hostile, mut receiver_streams) = memory_stream_pair();

    // Construct a header with the WRONG item_id
    let wrong_item_id = ItemId::new("wrong_item").unwrap();
    let header = ChunkDataHeader::new(
        sample_transfer(),
        wrong_item_id,
        ChunkIndex::new(0),
        honest.len() as u32,
        true,
        0,
    )
    .unwrap();

    let frame = encode_chunk_data_header_frame(&header, FRAME_BOUND).unwrap();
    hostile.0.write_all(&frame).await.unwrap();
    hostile.0.write_all(&honest).await.unwrap();
    hostile.0.finish().await.unwrap();

    let dest = RelPath::new("photo.raw").expect("relpath");
    let outcome = receive_file(
        &receiver_vfs,
        root_receiver,
        &dest,
        file_content.len() as u64,
        &hash,
        &BaoVerifier,
        &mut receiver_streams.0,
        &mut receiver_streams.1,
        sample_transfer(),
        sample_item(),
        FRAME_BOUND,
    )
    .await;

    assert!(
        outcome.is_err(),
        "a chunk for a different item must be refused"
    );
}

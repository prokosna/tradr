//! Supervisor-authored tests for chunk resumption in tradr-core.
//! Breaking chunk-level resumption collapses the whole path-selection design.
//! See docs/04-protocol.md, docs/03-discovery-and-transport.md, and AGENTS.md section 6.

use tradr_core::{ChunkIndex, ItemId, ItemResumption, REFERENCE_CHUNK_SIZE_BYTES, ResumptionError};

fn sample_item() -> ItemId {
    ItemId::new("test_item_1").expect("valid item id")
}

#[test]
fn zero_byte_item_has_zero_chunks_and_is_immediately_complete() {
    let item = ItemResumption::new(sample_item(), 0);

    assert_eq!(item.total_bytes(), 0);
    assert_eq!(item.total_chunks(), 0);
    assert!(item.is_item_complete());
    assert_eq!(item.bytes_received(), 0);
    assert_eq!(item.next_chunk_request(64), None);
    assert!(item.missing_chunks().is_empty());
}

#[test]
fn single_byte_item_has_one_chunk_of_size_one() {
    let mut item = ItemResumption::new(sample_item(), 1);

    assert_eq!(item.total_bytes(), 1);
    assert_eq!(item.total_chunks(), 1);
    assert!(!item.is_item_complete());
    assert_eq!(item.chunk_size(ChunkIndex::new(0)), Ok(1));
    assert_eq!(item.next_chunk_request(64), Some((ChunkIndex::new(0), 1)));

    let complete = item
        .record_piece(ChunkIndex::new(0), 0, 1)
        .expect("recording 1-byte piece must succeed");
    assert!(complete);
    assert_eq!(item.is_chunk_complete(ChunkIndex::new(0)), Ok(true));
    assert_eq!(item.is_chunk_verified(ChunkIndex::new(0)), Ok(false));

    item.mark_verified(ChunkIndex::new(0))
        .expect("marking verified must succeed");
    assert_eq!(item.is_chunk_verified(ChunkIndex::new(0)), Ok(true));
    assert!(item.is_item_complete());
    assert_eq!(item.next_chunk_request(64), None);
    assert!(item.missing_chunks().is_empty());
}

#[test]
fn exact_one_mebibyte_boundary_has_one_full_chunk() {
    let item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES);

    assert_eq!(item.total_chunks(), 1);
    assert_eq!(
        item.chunk_size(ChunkIndex::new(0)),
        Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
    );
}

#[test]
fn one_mebibyte_plus_one_byte_has_two_chunks() {
    let item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES + 1);

    assert_eq!(item.total_chunks(), 2);
    assert_eq!(
        item.chunk_size(ChunkIndex::new(0)),
        Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
    );
    assert_eq!(item.chunk_size(ChunkIndex::new(1)), Ok(1));
}

#[test]
fn multi_mebibyte_item_chunk_sizes() {
    let size = 3 * REFERENCE_CHUNK_SIZE_BYTES + 500;
    let item = ItemResumption::new(sample_item(), size);

    assert_eq!(item.total_chunks(), 4);
    assert_eq!(
        item.chunk_size(ChunkIndex::new(0)),
        Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
    );
    assert_eq!(
        item.chunk_size(ChunkIndex::new(1)),
        Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
    );
    assert_eq!(
        item.chunk_size(ChunkIndex::new(2)),
        Ok(REFERENCE_CHUNK_SIZE_BYTES as u32)
    );
    assert_eq!(item.chunk_size(ChunkIndex::new(3)), Ok(500));
    assert_eq!(
        item.chunk_size(ChunkIndex::new(4)),
        Err(ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(4),
            total_chunks: 4,
        })
    );
}

#[test]
fn subdivided_pieces_ble_four_kib_progress_and_completion() {
    let mut item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES);
    let piece_size = 4096u32;
    let num_pieces = (REFERENCE_CHUNK_SIZE_BYTES as u32) / piece_size;

    // Simulate arriving out of order: odd pieces first, then even pieces.
    for i in (1..num_pieces).step_by(2) {
        let offset = i * piece_size;
        let is_complete = item
            .record_piece(ChunkIndex::new(0), offset, piece_size)
            .expect("piece within bounds");
        assert!(!is_complete);
    }

    // Duplicate piece delivery must be idempotent and not double-count bytes.
    let before_dup = item.bytes_received();
    item.record_piece(ChunkIndex::new(0), piece_size, piece_size)
        .expect("duplicate piece");
    assert_eq!(item.bytes_received(), before_dup);

    for i in (0..num_pieces).step_by(2) {
        let offset = i * piece_size;
        let is_complete = item
            .record_piece(ChunkIndex::new(0), offset, piece_size)
            .expect("piece within bounds");
        if i == num_pieces - 2 {
            assert!(is_complete);
        }
    }

    assert_eq!(item.is_chunk_complete(ChunkIndex::new(0)), Ok(true));
    assert_eq!(item.bytes_received(), REFERENCE_CHUNK_SIZE_BYTES);
}

#[test]
fn subdivided_pieces_relay_256_kib_progress() {
    let mut item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES);
    let piece_size = 256 * 1024u32;

    assert!(
        !item
            .record_piece(ChunkIndex::new(0), 0, piece_size)
            .unwrap()
    );
    assert!(
        !item
            .record_piece(ChunkIndex::new(0), piece_size, piece_size)
            .unwrap()
    );
    assert!(
        !item
            .record_piece(ChunkIndex::new(0), 2 * piece_size, piece_size)
            .unwrap()
    );
    assert!(
        item.record_piece(ChunkIndex::new(0), 3 * piece_size, piece_size)
            .unwrap()
    );

    assert_eq!(item.is_chunk_complete(ChunkIndex::new(0)), Ok(true));
}

#[test]
fn path_switch_resumption_from_ble_to_quic() {
    let total_bytes = 5 * REFERENCE_CHUNK_SIZE_BYTES;
    let mut item = ItemResumption::new(sample_item(), total_bytes);

    // Chunk 0 fully received over 4 KiB BLE pieces.
    let piece_size = 4096u32;
    let num_pieces = (REFERENCE_CHUNK_SIZE_BYTES as u32) / piece_size;
    for i in 0..num_pieces {
        item.record_piece(ChunkIndex::new(0), i * piece_size, piece_size)
            .unwrap();
    }
    item.mark_verified(ChunkIndex::new(0)).unwrap();

    // Chunk 1 partially received over BLE (first 64 KiB).
    for i in 0..16 {
        item.record_piece(ChunkIndex::new(1), i * piece_size, piece_size)
            .unwrap();
    }

    // Path switch to QUIC occurs after disconnection.
    // Resumption requests from the first unverified chunk (chunk 1).
    assert_eq!(item.next_chunk_request(64), Some((ChunkIndex::new(1), 4)));

    // QUIC sends full 1 MiB chunk for chunk 1, overwriting partial BLE ranges.
    let complete = item
        .record_piece(ChunkIndex::new(1), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    assert!(complete);
    item.mark_verified(ChunkIndex::new(1)).unwrap();

    // Remaining chunks 2, 3, 4 received over QUIC in 1 MiB chunks.
    for c in 2..5 {
        let idx = ChunkIndex::new(c);
        item.record_piece(idx, 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
            .unwrap();
        item.mark_verified(idx).unwrap();
    }

    assert!(item.is_item_complete());
    assert_eq!(item.bytes_received(), total_bytes);
    assert_eq!(item.next_chunk_request(64), None);
}

#[test]
fn path_switch_resumption_from_relay_to_ble() {
    let mut item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES);

    // First 512 KiB received via two 256 KiB relay pieces.
    item.record_piece(ChunkIndex::new(0), 0, 256 * 1024)
        .unwrap();
    item.record_piece(ChunkIndex::new(0), 256 * 1024, 256 * 1024)
        .unwrap();

    // Transport switches to BLE: remainder received in 4 KiB pieces from 512 KiB to 1 MiB.
    let start_piece = (512 * 1024) / 4096;
    let end_piece = (1024 * 1024) / 4096;
    for i in start_piece..end_piece {
        item.record_piece(ChunkIndex::new(0), i * 4096, 4096)
            .unwrap();
    }

    assert_eq!(item.is_chunk_complete(ChunkIndex::new(0)), Ok(true));
    item.mark_verified(ChunkIndex::new(0)).unwrap();
    assert!(item.is_item_complete());
}

#[test]
fn piece_out_of_bounds_errors() {
    let mut item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES + 100);

    // Piece extends past 1 MiB in chunk 0.
    let err = item
        .record_piece(ChunkIndex::new(0), 1024 * 1024 - 10, 20)
        .unwrap_err();
    assert_eq!(
        err,
        ResumptionError::PieceOutOfBounds {
            index: ChunkIndex::new(0),
            offset_in_chunk: 1024 * 1024 - 10,
            payload_len: 20,
            chunk_size: REFERENCE_CHUNK_SIZE_BYTES as u32,
        }
    );

    // Piece extends past 100 bytes in last chunk (chunk 1).
    let err_last = item.record_piece(ChunkIndex::new(1), 50, 60).unwrap_err();
    assert_eq!(
        err_last,
        ResumptionError::PieceOutOfBounds {
            index: ChunkIndex::new(1),
            offset_in_chunk: 50,
            payload_len: 60,
            chunk_size: 100,
        }
    );

    // Piece on out-of-bounds chunk index.
    let err_idx = item.record_piece(ChunkIndex::new(2), 0, 10).unwrap_err();
    assert_eq!(
        err_idx,
        ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(2),
            total_chunks: 2,
        }
    );
}

#[test]
fn chunk_out_of_bounds_errors() {
    let mut item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES);

    assert_eq!(
        item.chunk_size(ChunkIndex::new(1)),
        Err(ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(1),
            total_chunks: 1,
        })
    );
    assert_eq!(
        item.is_chunk_complete(ChunkIndex::new(1)),
        Err(ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(1),
            total_chunks: 1,
        })
    );
    assert_eq!(
        item.is_chunk_verified(ChunkIndex::new(1)),
        Err(ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(1),
            total_chunks: 1,
        })
    );
    assert_eq!(
        item.mark_verified(ChunkIndex::new(1)),
        Err(ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(1),
            total_chunks: 1,
        })
    );
    assert_eq!(
        item.mark_failed(ChunkIndex::new(1)),
        Err(ResumptionError::ChunkOutOfBounds {
            index: ChunkIndex::new(1),
            total_chunks: 1,
        })
    );
}

#[test]
fn next_chunk_request_batching_and_skipping() {
    let total_bytes = 10 * REFERENCE_CHUNK_SIZE_BYTES;
    let mut item = ItemResumption::new(sample_item(), total_bytes);

    // Chunks 0 and 1 are verified.
    item.record_piece(ChunkIndex::new(0), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    item.mark_verified(ChunkIndex::new(0)).unwrap();
    item.record_piece(ChunkIndex::new(1), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    item.mark_verified(ChunkIndex::new(1)).unwrap();

    // Next request with batch size 4 should ask for chunks 2..6.
    assert_eq!(item.next_chunk_request(4), Some((ChunkIndex::new(2), 4)));

    // Complete and verify chunks 2, 3, 4, 5.
    for c in 2..6 {
        let idx = ChunkIndex::new(c);
        item.record_piece(idx, 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
            .unwrap();
        item.mark_verified(idx).unwrap();
    }

    // Next request with batch size 4 should ask for chunks 6..10.
    assert_eq!(item.next_chunk_request(4), Some((ChunkIndex::new(6), 4)));

    // Complete and verify chunks 6, 7, 8, 9.
    for c in 6..10 {
        let idx = ChunkIndex::new(c);
        item.record_piece(idx, 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
            .unwrap();
        item.mark_verified(idx).unwrap();
    }

    assert_eq!(item.next_chunk_request(4), None);
    assert!(item.is_item_complete());
}

#[test]
fn verification_failure_tracking_and_three_attempt_limit() {
    let mut item = ItemResumption::new(sample_item(), REFERENCE_CHUNK_SIZE_BYTES);

    // Chunk arrives but fails verification.
    item.record_piece(ChunkIndex::new(0), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    assert_eq!(item.is_chunk_complete(ChunkIndex::new(0)), Ok(true));

    let attempts1 = item.mark_failed(ChunkIndex::new(0)).unwrap();
    assert_eq!(attempts1, 1);
    // After failure, chunk is reset and no longer complete.
    assert_eq!(item.is_chunk_complete(ChunkIndex::new(0)), Ok(false));

    // Second arrival and failure.
    item.record_piece(ChunkIndex::new(0), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    let attempts2 = item.mark_failed(ChunkIndex::new(0)).unwrap();
    assert_eq!(attempts2, 2);

    // Third arrival and failure (reaching the 3-attempt limit from docs/04).
    item.record_piece(ChunkIndex::new(0), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    let attempts3 = item.mark_failed(ChunkIndex::new(0)).unwrap();
    assert_eq!(attempts3, 3);

    // Fourth arrival passes verification.
    item.record_piece(ChunkIndex::new(0), 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
        .unwrap();
    item.mark_verified(ChunkIndex::new(0)).unwrap();
    assert_eq!(item.is_chunk_verified(ChunkIndex::new(0)), Ok(true));
    assert!(item.is_item_complete());
}

#[test]
fn missing_chunks_reports_all_unverified_indices() {
    let mut item = ItemResumption::new(sample_item(), 5 * REFERENCE_CHUNK_SIZE_BYTES);

    // Verify chunks 0, 2, 4.
    for c in [0, 2, 4] {
        let idx = ChunkIndex::new(c);
        item.record_piece(idx, 0, REFERENCE_CHUNK_SIZE_BYTES as u32)
            .unwrap();
        item.mark_verified(idx).unwrap();
    }

    assert_eq!(
        item.missing_chunks(),
        vec![ChunkIndex::new(1), ChunkIndex::new(3)]
    );
}

//! Supervisor-authored tests for Data plane domain messages in tradr-core.
//! Covers ChunkRequest, ChunkRerequest, ChunkDataHeader, ItemComplete,
//! FlowControl, and TransferProgress invariants. See docs/04-protocol.md.

use tradr_core::{
    ChunkDataHeader, ChunkIndex, ChunkRequest, ChunkRerequest, FlowControl, ItemComplete, ItemId,
    RelPath, TransferId, TransferProgress,
};

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn sample_transfer() -> TransferId {
    VALID_V7.parse().expect("valid transfer id")
}

fn sample_item() -> ItemId {
    ItemId::new("item_1").expect("valid item id")
}

#[test]
fn chunk_request_constructs_and_exposes_fields() {
    let req = ChunkRequest::new(sample_transfer(), sample_item(), ChunkIndex::new(5), 64);

    assert_eq!(req.transfer_id(), sample_transfer());
    assert_eq!(req.item_id(), &sample_item());
    assert_eq!(req.from_chunk(), ChunkIndex::new(5));
    assert_eq!(req.count(), 64);
}

#[test]
fn chunk_rerequest_constructs_and_exposes_chunks() {
    let chunks = vec![ChunkIndex::new(1), ChunkIndex::new(4), ChunkIndex::new(7)];
    let req = ChunkRerequest::new(sample_transfer(), sample_item(), chunks.clone());

    assert_eq!(req.transfer_id(), sample_transfer());
    assert_eq!(req.item_id(), &sample_item());
    assert_eq!(req.chunks(), &chunks[..]);
}

#[test]
fn chunk_data_header_constructs_and_exposes_subdivision_fields() {
    let header = ChunkDataHeader::new(
        sample_transfer(),
        sample_item(),
        ChunkIndex::new(2),
        4096,
        vec![1, 2, 3, 4],
        false,
        8192,
    );

    assert_eq!(header.transfer_id(), sample_transfer());
    assert_eq!(header.item_id(), &sample_item());
    assert_eq!(header.chunk_index(), ChunkIndex::new(2));
    assert_eq!(header.payload_len(), 4096);
    assert_eq!(header.verify_path(), &[1, 2, 3, 4]);
    assert!(!header.is_last());
    assert_eq!(header.offset_in_chunk(), 8192);
}

#[test]
fn item_complete_constructs_and_exposes_status() {
    let path = RelPath::new("photos/cat.jpg").expect("valid rel path");
    let complete = ItemComplete::new(sample_transfer(), sample_item(), true, Some(path.clone()));

    assert_eq!(complete.transfer_id(), sample_transfer());
    assert_eq!(complete.item_id(), &sample_item());
    assert!(complete.is_verified());
    assert_eq!(complete.final_path(), Some(&path));

    let failed = ItemComplete::new(sample_transfer(), sample_item(), false, None);
    assert!(!failed.is_verified());
    assert_eq!(failed.final_path(), None);
}

#[test]
fn flow_control_constructs_and_exposes_backpressure() {
    let fc = FlowControl::new(sample_transfer(), 0, Some("slow disk".to_string()));

    assert_eq!(fc.transfer_id(), sample_transfer());
    assert_eq!(fc.max_inflight_chunks(), 0);
    assert_eq!(fc.reason(), Some("slow disk"));
}

#[test]
fn transfer_progress_constructs_and_exposes_metrics() {
    let progress = TransferProgress::new(
        sample_transfer(),
        1048576,
        5242880,
        1,
        5,
        12500000.0,
        Some("direct-quic".to_string()),
    );

    assert_eq!(progress.transfer_id(), sample_transfer());
    assert_eq!(progress.bytes_received(), 1048576);
    assert_eq!(progress.bytes_total(), 5242880);
    assert_eq!(progress.items_completed(), 1);
    assert_eq!(progress.items_total(), 5);
    assert_eq!(progress.throughput_bps(), 12500000.0);
    assert_eq!(progress.active_transport(), Some("direct-quic"));
}

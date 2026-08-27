//! Supervisor-authored wire conversion and framing tests for Data plane messages.
//! Tests encoding and decoding of ChunkRequest, ChunkRerequest, ChunkData,
//! ItemComplete, FlowControl, and TransferProgress frames. See docs/04-protocol.md.

use tradr_core::{
    ChunkDataHeader, ChunkIndex, ChunkRequest, ChunkRerequest, FlowControl, ItemComplete, ItemId,
    RelPath, TransferId, TransferProgress,
};
use tradr_proto::data::{
    TransferFrameError, TransferWireError, decode_chunk_data_header_frame,
    decode_chunk_request_frame, decode_chunk_rerequest_frame, decode_flow_control_frame,
    decode_item_complete_frame, decode_transfer_progress_frame, encode_chunk_data_header_frame,
    encode_chunk_request_frame, encode_chunk_rerequest_frame, encode_flow_control_frame,
    encode_item_complete_frame, encode_transfer_progress_frame,
};
use tradr_proto::framing::{FrameDecoder, encode_frame};
use tradr_proto::message_type::MessageType;

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn sample_transfer() -> TransferId {
    VALID_V7.parse().expect("valid transfer id")
}

fn sample_item() -> ItemId {
    ItemId::new("photo_1").expect("valid item id")
}

#[test]
fn chunk_request_round_trips_through_wire_and_frames() {
    let req = ChunkRequest::new(sample_transfer(), sample_item(), ChunkIndex::new(3), 64);
    let bytes = encode_chunk_request_frame(&req, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&bytes);
    let frame = decoder.next_frame().unwrap().expect("frame is complete");

    assert_eq!(frame.type_code(), MessageType::ChunkRequest.code());
    let decoded = decode_chunk_request_frame(&frame).expect("decoding must succeed");
    assert_eq!(decoded, req);
}

#[test]
fn chunk_rerequest_round_trips_through_wire_and_frames() {
    let req = ChunkRerequest::new(
        sample_transfer(),
        sample_item(),
        vec![ChunkIndex::new(0), ChunkIndex::new(2), ChunkIndex::new(5)],
    );
    let bytes = encode_chunk_rerequest_frame(&req, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&bytes);
    let frame = decoder.next_frame().unwrap().expect("frame is complete");

    assert_eq!(frame.type_code(), MessageType::ChunkRerequest.code());
    let decoded = decode_chunk_rerequest_frame(&frame).expect("decoding must succeed");
    assert_eq!(decoded, req);
}

#[test]
fn chunk_data_header_round_trips_through_wire_and_frames() {
    let header = ChunkDataHeader::new(
        sample_transfer(),
        sample_item(),
        ChunkIndex::new(4),
        4096,
        vec![0xaa, 0xbb, 0xcc, 0xdd],
        true,
        8192,
    );
    let bytes = encode_chunk_data_header_frame(&header, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&bytes);
    let frame = decoder.next_frame().unwrap().expect("frame is complete");

    assert_eq!(frame.type_code(), MessageType::ChunkData.code());
    let decoded = decode_chunk_data_header_frame(&frame).expect("decoding must succeed");
    assert_eq!(decoded, header);
}

#[test]
fn item_complete_round_trips_through_wire_and_frames() {
    let path = RelPath::new("photos/vacation.jpg").expect("valid path");
    let complete = ItemComplete::new(sample_transfer(), sample_item(), true, Some(path));
    let bytes = encode_item_complete_frame(&complete, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&bytes);
    let frame = decoder.next_frame().unwrap().expect("frame is complete");

    assert_eq!(frame.type_code(), MessageType::ItemComplete.code());
    let decoded = decode_item_complete_frame(&frame).expect("decoding must succeed");
    assert_eq!(decoded, complete);
}

#[test]
fn flow_control_round_trips_through_wire_and_frames() {
    let fc = FlowControl::new(sample_transfer(), 16, Some("battery low".to_string()));
    let bytes = encode_flow_control_frame(&fc, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&bytes);
    let frame = decoder.next_frame().unwrap().expect("frame is complete");

    assert_eq!(frame.type_code(), MessageType::FlowControl.code());
    let decoded = decode_flow_control_frame(&frame).expect("decoding must succeed");
    assert_eq!(decoded, fc);
}

#[test]
fn transfer_progress_round_trips_through_wire_and_frames() {
    let progress = TransferProgress::new(
        sample_transfer(),
        1048576,
        10485760,
        1,
        10,
        2500000.0,
        Some("direct-quic".to_string()),
    );
    let bytes = encode_transfer_progress_frame(&progress, 65536).expect("encoding must succeed");

    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&bytes);
    let frame = decoder.next_frame().unwrap().expect("frame is complete");

    assert_eq!(frame.type_code(), MessageType::TransferProgress.code());
    let decoded = decode_transfer_progress_frame(&frame).expect("decoding must succeed");
    assert_eq!(decoded, progress);
}

#[test]
fn wrong_message_type_is_refused() {
    let frame = encode_frame(MessageType::KeepAlive.code(), &[], 65536).unwrap();
    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame);
    let decoded_frame = decoder.next_frame().unwrap().unwrap();

    let err = decode_chunk_request_frame(&decoded_frame).unwrap_err();
    assert_eq!(
        err,
        TransferFrameError::WrongMessageType {
            expected: MessageType::ChunkRequest.code(),
            got: MessageType::KeepAlive.code(),
        }
    );
}

#[test]
fn wire_validation_rejects_zero_count_in_chunk_request() {
    let raw = tradr_proto::v1::ChunkRequest {
        transfer_id: VALID_V7.to_string(),
        item_id: "item_1".to_string(),
        from_chunk: 0,
        count: 0,
    };
    use prost::Message;
    let payload = raw.encode_to_vec();
    let frame_bytes = encode_frame(MessageType::ChunkRequest.code(), &payload, 65536).unwrap();
    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder.next_frame().unwrap().unwrap();

    let err = decode_chunk_request_frame(&frame).unwrap_err();
    assert_eq!(err, TransferFrameError::Wire(TransferWireError::ZeroCount));
}

#[test]
fn wire_validation_rejects_empty_chunks_in_chunk_rerequest() {
    let raw = tradr_proto::v1::ChunkRerequest {
        transfer_id: VALID_V7.to_string(),
        item_id: "item_1".to_string(),
        chunks: vec![],
    };
    use prost::Message;
    let payload = raw.encode_to_vec();
    let frame_bytes = encode_frame(MessageType::ChunkRerequest.code(), &payload, 65536).unwrap();
    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder.next_frame().unwrap().unwrap();

    let err = decode_chunk_rerequest_frame(&frame).unwrap_err();
    assert_eq!(
        err,
        TransferFrameError::Wire(TransferWireError::EmptyChunks)
    );
}

#[test]
fn wire_validation_rejects_invalid_transfer_id() {
    let raw = tradr_proto::v1::ChunkRequest {
        transfer_id: "not-a-valid-uuid".to_string(),
        item_id: "item_1".to_string(),
        from_chunk: 0,
        count: 1,
    };
    use prost::Message;
    let payload = raw.encode_to_vec();
    let frame_bytes = encode_frame(MessageType::ChunkRequest.code(), &payload, 65536).unwrap();
    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder.next_frame().unwrap().unwrap();

    let err = decode_chunk_request_frame(&frame).unwrap_err();
    assert!(matches!(
        err,
        TransferFrameError::Wire(TransferWireError::InvalidTransferId(_))
    ));
}

#[test]
fn wire_validation_rejects_invalid_item_id() {
    let raw = tradr_proto::v1::ChunkRequest {
        transfer_id: VALID_V7.to_string(),
        item_id: "INVALID/ITEM".to_string(),
        from_chunk: 0,
        count: 1,
    };
    use prost::Message;
    let payload = raw.encode_to_vec();
    let frame_bytes = encode_frame(MessageType::ChunkRequest.code(), &payload, 65536).unwrap();
    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(&frame_bytes);
    let frame = decoder.next_frame().unwrap().unwrap();

    let err = decode_chunk_request_frame(&frame).unwrap_err();
    assert!(matches!(
        err,
        TransferFrameError::Wire(TransferWireError::InvalidItemId(_))
    ));
}

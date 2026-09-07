//! Tests for the in-band multiplexing frame (docs/04-protocol.md).

use tradr_proto::framing::{FrameDecoder, FrameError};
use tradr_proto::mux::{
    MuxError, MuxKind, StreamAllocator, StreamId, StreamOpener, encode_mux_frame, max_mux_payload,
    mux_frame_from_wire,
};

fn decode_one_frame(raw: &[u8]) -> tradr_proto::framing::Frame {
    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(raw);
    decoder
        .next_frame()
        .expect("wire bytes must decode")
        .expect("complete frame must be present")
}

#[test]
fn encode_is_byte_for_byte() {
    let encoded = encode_mux_frame(MuxKind::Data, StreamId::new(0x01020304), b"hi", 1024)
        .expect("frame within limit");
    assert_eq!(
        encoded,
        vec![
            0x00, 0x00, 0x00, 0x07, 0x60, 0x01, 0x02, 0x03, 0x04, b'h', b'i'
        ]
    );
}

#[test]
fn round_trip_through_frame_decoder_and_mux_frame_from_wire() {
    let payload = b"hello stream world";
    let stream_id = StreamId::new(42);
    let encoded =
        encode_mux_frame(MuxKind::Data, stream_id, payload, 1024).expect("frame within limit");

    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&encoded);
    let frame = decoder
        .next_frame()
        .expect("valid frame must decode")
        .expect("whole frame present");

    let mux_frame = mux_frame_from_wire(&frame).expect("valid mux frame");
    assert_eq!(mux_frame.kind(), MuxKind::Data);
    assert_eq!(mux_frame.stream_id(), stream_id);
    assert_eq!(mux_frame.payload(), payload);
}

#[test]
fn fin_encodes_with_empty_payload_and_round_trips() {
    let stream_id = StreamId::new(8);
    let encoded =
        encode_mux_frame(MuxKind::Fin, stream_id, b"", 1024).expect("empty fin within limit");

    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&encoded);
    let frame = decoder
        .next_frame()
        .expect("valid frame must decode")
        .expect("whole frame present");

    let mux_frame = mux_frame_from_wire(&frame).expect("valid fin frame");
    assert_eq!(mux_frame.kind(), MuxKind::Fin);
    assert_eq!(mux_frame.stream_id(), stream_id);
    assert_eq!(mux_frame.payload(), b"" as &[u8]);
}

#[test]
fn negative_fin_encoding_refuses_non_empty_payload() {
    let err = encode_mux_frame(MuxKind::Fin, StreamId::CONTROL, b"x", 1024)
        .expect_err("fin cannot carry payload");
    assert_eq!(err, MuxError::FinCarriesPayload(1));
}

#[test]
fn negative_payload_one_byte_over_max_mux_payload_is_oversized() {
    let limit = 512;
    let max = max_mux_payload(limit);
    let fits = vec![0xAB; max];
    let too_large = vec![0xAB; max + 1];

    assert!(encode_mux_frame(MuxKind::Data, StreamId::CONTROL, &fits, limit).is_ok());

    let err = encode_mux_frame(MuxKind::Data, StreamId::CONTROL, &too_large, limit)
        .expect_err("oversized payload must fail");
    assert_eq!(
        err,
        MuxError::Frame(FrameError::Oversized {
            announced: (limit + 1) as u64,
            limit,
        })
    );
}

#[test]
fn negative_frame_with_type_code_outside_mux_range() {
    let raw_5f = [0x00, 0x00, 0x00, 0x05, 0x5f, 0x00, 0x00, 0x00, 0x00];
    let frame_5f = decode_one_frame(&raw_5f);
    assert_eq!(
        mux_frame_from_wire(&frame_5f),
        Err(MuxError::NotAMuxCode(0x5f))
    );

    let raw_80 = [0x00, 0x00, 0x00, 0x05, 0x80, 0x00, 0x00, 0x00, 0x00];
    let frame_80 = decode_one_frame(&raw_80);
    assert_eq!(
        mux_frame_from_wire(&frame_80),
        Err(MuxError::NotAMuxCode(0x80))
    );
}

#[test]
fn negative_frame_with_unassigned_mux_type_code() {
    let raw_62 = [0x00, 0x00, 0x00, 0x05, 0x62, 0x00, 0x00, 0x00, 0x00];
    let frame_62 = decode_one_frame(&raw_62);
    assert_eq!(
        mux_frame_from_wire(&frame_62),
        Err(MuxError::UnassignedCode(0x62))
    );

    let raw_7f = [0x00, 0x00, 0x00, 0x05, 0x7f, 0x00, 0x00, 0x00, 0x00];
    let frame_7f = decode_one_frame(&raw_7f);
    assert_eq!(
        mux_frame_from_wire(&frame_7f),
        Err(MuxError::UnassignedCode(0x7f))
    );
}

#[test]
fn negative_data_frame_with_truncated_header() {
    let raw_3 = [0x00, 0x00, 0x00, 0x04, 0x60, 0x01, 0x02, 0x03];
    let frame_3 = decode_one_frame(&raw_3);
    assert_eq!(
        mux_frame_from_wire(&frame_3),
        Err(MuxError::TruncatedHeader(3))
    );

    let raw_0 = [0x00, 0x00, 0x00, 0x01, 0x60];
    let frame_0 = decode_one_frame(&raw_0);
    assert_eq!(
        mux_frame_from_wire(&frame_0),
        Err(MuxError::TruncatedHeader(0))
    );
}

#[test]
fn negative_fin_frame_carrying_payload_beyond_stream_id() {
    let raw = [0x00, 0x00, 0x00, 0x06, 0x61, 0x00, 0x00, 0x00, 0x01, 0xFF];
    let frame = decode_one_frame(&raw);
    assert_eq!(
        mux_frame_from_wire(&frame),
        Err(MuxError::FinCarriesPayload(1))
    );
}

#[test]
fn control_stream_is_dialler_bidirectional() {
    assert_eq!(StreamId::CONTROL.value(), 0);
    assert_eq!(StreamId::CONTROL.opened_by(), StreamOpener::Dialler);
    assert!(StreamId::CONTROL.is_bidirectional());
}

#[test]
fn four_residue_classes_determine_opener_and_directionality() {
    let s0 = StreamId::new(0);
    assert_eq!(s0.opened_by(), StreamOpener::Dialler);
    assert!(s0.is_bidirectional());

    let s1 = StreamId::new(1);
    assert_eq!(s1.opened_by(), StreamOpener::Listener);
    assert!(s1.is_bidirectional());

    let s2 = StreamId::new(2);
    assert_eq!(s2.opened_by(), StreamOpener::Dialler);
    assert!(!s2.is_bidirectional());

    let s3 = StreamId::new(3);
    assert_eq!(s3.opened_by(), StreamOpener::Listener);
    assert!(!s3.is_bidirectional());
}

#[test]
fn dialler_allocator_yields_expected_stream_sequences() {
    let mut alloc = StreamAllocator::new(StreamOpener::Dialler);
    assert_eq!(alloc.next_bidirectional().expect("id available").value(), 0);
    assert_eq!(alloc.next_bidirectional().expect("id available").value(), 4);
    assert_eq!(alloc.next_bidirectional().expect("id available").value(), 8);

    assert_eq!(
        alloc.next_unidirectional().expect("id available").value(),
        2
    );
    assert_eq!(
        alloc.next_unidirectional().expect("id available").value(),
        6
    );
    assert_eq!(
        alloc.next_unidirectional().expect("id available").value(),
        10
    );
}

#[test]
fn listener_allocator_yields_expected_stream_sequences() {
    let mut alloc = StreamAllocator::new(StreamOpener::Listener);
    assert_eq!(alloc.next_bidirectional().expect("id available").value(), 1);
    assert_eq!(alloc.next_bidirectional().expect("id available").value(), 5);
    assert_eq!(alloc.next_bidirectional().expect("id available").value(), 9);

    assert_eq!(
        alloc.next_unidirectional().expect("id available").value(),
        3
    );
    assert_eq!(
        alloc.next_unidirectional().expect("id available").value(),
        7
    );
    assert_eq!(
        alloc.next_unidirectional().expect("id available").value(),
        11
    );
}

#[test]
fn allocated_identifiers_report_their_opener() {
    let mut dialler_alloc = StreamAllocator::new(StreamOpener::Dialler);
    for _ in 0..10 {
        assert_eq!(
            dialler_alloc.next_bidirectional().expect("id").opened_by(),
            StreamOpener::Dialler
        );
        assert_eq!(
            dialler_alloc.next_unidirectional().expect("id").opened_by(),
            StreamOpener::Dialler
        );
    }

    let mut listener_alloc = StreamAllocator::new(StreamOpener::Listener);
    for _ in 0..10 {
        assert_eq!(
            listener_alloc.next_bidirectional().expect("id").opened_by(),
            StreamOpener::Listener
        );
        assert_eq!(
            listener_alloc
                .next_unidirectional()
                .expect("id")
                .opened_by(),
            StreamOpener::Listener
        );
    }
}

#[test]
fn next_in_space_exhaustion_at_ceiling_without_wrap() {
    let near_ceiling_0 = StreamId::new(u32::MAX - 7);
    let ceiling_0 = near_ceiling_0.next_in_space();
    assert_eq!(ceiling_0, Some(StreamId::new(u32::MAX - 3)));
    assert_eq!(ceiling_0.expect("ceiling").next_in_space(), None);

    let near_ceiling_3 = StreamId::new(u32::MAX - 4);
    let ceiling_3 = near_ceiling_3.next_in_space();
    assert_eq!(ceiling_3, Some(StreamId::new(u32::MAX)));
    assert_eq!(ceiling_3.expect("ceiling").next_in_space(), None);

    for residue in 0..4 {
        let current = StreamId::new(residue);
        let next = current.next_in_space().expect("within bounds");
        assert_eq!(next.opened_by(), current.opened_by());
        assert_eq!(next.is_bidirectional(), current.is_bidirectional());
    }
}

#[test]
fn max_mux_payload_calculation_and_saturation() {
    assert_eq!(max_mux_payload(512), 507);
    assert_eq!(max_mux_payload(4), 0);
    assert_eq!(max_mux_payload(5), 0);
    assert_eq!(max_mux_payload(0), 0);
}

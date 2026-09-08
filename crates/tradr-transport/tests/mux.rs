//! Tests for the sans-io stream multiplexer state machine (docs/04-protocol.md).

use tradr_proto::framing::{Frame, FrameDecoder};
use tradr_proto::mux::{
    MuxFrame, MuxKind, StreamId, StreamOpener, encode_mux_frame, mux_frame_from_wire,
};
use tradr_transport::mux::{
    MAX_PENDING_STREAMS, MIN_RECORD_LIMIT, Multiplexer, MuxFault, MuxRefusal, ReadOutcome,
};

fn decode_one_frame(raw: &[u8]) -> Frame {
    let mut decoder = FrameDecoder::new(65536);
    decoder.feed(raw);
    match decoder.next_frame() {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!("expected complete frame in buffer"),
        Err(err) => panic!("frame decode error: {err}"),
    }
}

fn parse_mux_frame(raw: &[u8]) -> MuxFrame {
    let frame = decode_one_frame(raw);
    match mux_frame_from_wire(&frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    }
}

#[test]
fn dialler_first_open_bidirectional_is_control_and_emits_no_frame() {
    let mut mux = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected init error: {err}"),
    };
    let stream_id = match mux.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    assert_eq!(stream_id, StreamId::CONTROL);
}

#[test]
fn write_1200_bytes_at_record_limit_512_chops_into_three_frames() {
    let mut mux = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected init error: {err}"),
    };
    let stream = match mux.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let input: Vec<u8> = (0..1200).map(|i| (i % 251) as u8).collect();
    let encoded_frames = match mux.write(stream, &input) {
        Ok(frames) => frames,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    assert_eq!(encoded_frames.len(), 3);

    let mut reassembled = Vec::new();
    let expected_lens = [507, 507, 186];
    for (i, raw_frame) in encoded_frames.iter().enumerate() {
        let frame = decode_one_frame(raw_frame);
        let mux_frame = match mux_frame_from_wire(&frame) {
            Ok(mf) => mf,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        assert_eq!(mux_frame.kind(), MuxKind::Data);
        assert_eq!(mux_frame.stream_id(), stream);
        assert_eq!(mux_frame.payload().len(), expected_lens[i]);
        reassembled.extend_from_slice(mux_frame.payload());
    }
    assert_eq!(reassembled, input);
}

#[test]
fn writing_empty_slice_yields_no_frames() {
    let mut mux = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected init error: {err}"),
    };
    let stream = match mux.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let frames = match mux.write(stream, &[]) {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    assert!(frames.is_empty());
}

#[test]
fn finish_yields_single_fin_and_subsequent_finish_or_write_is_already_finished() {
    let mut mux = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected init error: {err}"),
    };
    let stream = match mux.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let fin_frame_bytes = match mux.finish(stream) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let frame = decode_one_frame(&fin_frame_bytes);
    let mux_frame = match mux_frame_from_wire(&frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    assert_eq!(mux_frame.kind(), MuxKind::Fin);
    assert_eq!(mux_frame.stream_id(), stream);
    assert!(mux_frame.payload().is_empty());

    let second_finish = mux.finish(stream);
    assert_eq!(second_finish, Err(MuxFault::AlreadyFinished(stream)));

    let later_write = mux.write(stream, b"payload");
    assert_eq!(later_write, Err(MuxFault::AlreadyFinished(stream)));
}

#[test]
fn full_round_trip_dialler_writes_listener_reads_then_pending_then_finished() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let data = b"round-trip payload data";
    let encoded_data = match dialler.write(stream, data) {
        Ok(frames) => frames,
        Err(err) => panic!("unexpected write error: {err}"),
    };

    for raw in &encoded_data {
        let frame = decode_one_frame(raw);
        let mux_frame = match mux_frame_from_wire(&frame) {
            Ok(mf) => mf,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        match listener.on_frame(&mux_frame) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }
    }

    let accepted = match listener.accept_bidirectional() {
        Some(id) => id,
        None => panic!("expected stream to be accepted"),
    };
    assert_eq!(accepted, stream);

    let mut buf = vec![0u8; 128];
    let outcome1 = match listener.read(accepted, &mut buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome1, ReadOutcome::Read(data.len()));
    assert_eq!(&buf[..data.len()], data);

    let outcome2 = match listener.read(accepted, &mut buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome2, ReadOutcome::Pending);

    let fin_bytes = match dialler.finish(stream) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let fin_frame = decode_one_frame(&fin_bytes);
    let mux_fin = match mux_frame_from_wire(&fin_frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match listener.on_frame(&mux_fin) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let outcome3 = match listener.read(accepted, &mut buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome3, ReadOutcome::Finished);
}

#[test]
fn peer_opened_stream_queues_strictly_by_directionality() {
    let mut peer = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected peer init error: {err}"),
    };
    let mut local = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected local init error: {err}"),
    };

    let uni_stream = match peer.open_unidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let uni_frames = match peer.write(uni_stream, b"uni data") {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    let frame0 = decode_one_frame(&uni_frames[0]);
    let mux_frame0 = match mux_frame_from_wire(&frame0) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match local.on_frame(&mux_frame0) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(local.accept_bidirectional(), None);
    assert_eq!(local.accept_unidirectional(), Some(uni_stream));

    let bi_stream = match peer.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let bi_frames = match peer.write(bi_stream, b"bi data") {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    let frame1 = decode_one_frame(&bi_frames[0]);
    let mux_frame1 = match mux_frame_from_wire(&frame1) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match local.on_frame(&mux_frame1) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(local.accept_unidirectional(), None);
    assert_eq!(local.accept_bidirectional(), Some(bi_stream));
}

#[test]
fn partial_read_leaves_remainder_and_ends_in_pending() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let input = b"0123456789";
    let frames = match dialler.write(stream, input) {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    for raw in &frames {
        let f = decode_one_frame(raw);
        let mf = match mux_frame_from_wire(&f) {
            Ok(m) => m,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        match listener.on_frame(&mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }
    }
    let accepted = match listener.accept_bidirectional() {
        Some(id) => id,
        None => panic!("expected stream to be accepted"),
    };

    let mut buf = [0u8; 3];
    assert_eq!(listener.read(accepted, &mut buf), Ok(ReadOutcome::Read(3)));
    assert_eq!(&buf, b"012");
    assert_eq!(listener.read(accepted, &mut buf), Ok(ReadOutcome::Read(3)));
    assert_eq!(&buf, b"345");
    assert_eq!(listener.read(accepted, &mut buf), Ok(ReadOutcome::Read(3)));
    assert_eq!(&buf, b"678");
    assert_eq!(listener.read(accepted, &mut buf), Ok(ReadOutcome::Read(1)));
    assert_eq!(&buf[..1], b"9");
    assert_eq!(listener.read(accepted, &mut buf), Ok(ReadOutcome::Pending));
}

#[test]
fn negative_listener_frame_on_unopened_stream_in_own_space_is_peer_allocated_in_our_space() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let raw = match encode_mux_frame(MuxKind::Data, StreamId::new(1), b"spoofed", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let frame = decode_one_frame(&raw);
    let mux_frame = match mux_frame_from_wire(&frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };

    let result = listener.on_frame(&mux_frame);
    assert_eq!(
        result,
        Err(MuxRefusal::PeerAllocatedInOurSpace(StreamId::new(1)))
    );
    assert_eq!(
        listener.refusal(),
        Some(MuxRefusal::PeerAllocatedInOurSpace(StreamId::new(1)))
    );
}

#[test]
fn negative_frame_on_locally_opened_unidirectional_stream_is_wrote_to_our_unidirectional_stream() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let uni_stream = match dialler.open_unidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    assert_eq!(uni_stream, StreamId::new(2));

    let raw = match encode_mux_frame(MuxKind::Data, uni_stream, b"illegal reply", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let frame = decode_one_frame(&raw);
    let mux_frame = match mux_frame_from_wire(&frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };

    let result = dialler.on_frame(&mux_frame);
    assert_eq!(
        result,
        Err(MuxRefusal::WroteToOurUnidirectionalStream(uni_stream))
    );
    assert_eq!(
        dialler.refusal(),
        Some(MuxRefusal::WroteToOurUnidirectionalStream(uni_stream))
    );
}

#[test]
fn negative_frame_after_stream_fin_is_frame_after_fin() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let fin_raw = match dialler.finish(stream) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let fin_frame = decode_one_frame(&fin_raw);
    let mux_fin = match mux_frame_from_wire(&fin_frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match listener.on_frame(&mux_fin) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let after_fin_raw = match encode_mux_frame(MuxKind::Data, stream, b"after fin", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let after_fin_frame = decode_one_frame(&after_fin_raw);
    let mux_after_fin = match mux_frame_from_wire(&after_fin_frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };

    let result = listener.on_frame(&mux_after_fin);
    assert_eq!(result, Err(MuxRefusal::FrameAfterFin(stream)));
    assert_eq!(listener.refusal(), Some(MuxRefusal::FrameAfterFin(stream)));
}

#[test]
fn negative_receive_window_is_exact_boundary() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 1, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let stream = StreamId::new(0);

    let exact_128 = vec![b'x'; 128];
    let raw_128 = match encode_mux_frame(MuxKind::Data, stream, &exact_128, 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let frame_128 = decode_one_frame(&raw_128);
    let mux_128 = match mux_frame_from_wire(&frame_128) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match listener.on_frame(&mux_128) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let one_more = [b'y'; 1];
    let raw_more = match encode_mux_frame(MuxKind::Data, stream, &one_more, 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let frame_more = decode_one_frame(&raw_more);
    let mux_more = match mux_frame_from_wire(&frame_more) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    let result = listener.on_frame(&mux_more);
    assert_eq!(result, Err(MuxRefusal::ReceiveWindowExceeded(stream)));
    assert_eq!(
        listener.refusal(),
        Some(MuxRefusal::ReceiveWindowExceeded(stream))
    );
}

#[test]
fn negative_pending_stream_cap() {
    assert_eq!(MAX_PENDING_STREAMS, 64);
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    for i in 0..MAX_PENDING_STREAMS {
        let stream = if i % 2 == 0 {
            StreamId::new(((i / 2) * 4) as u32)
        } else {
            StreamId::new(((i / 2) * 4 + 2) as u32)
        };
        let raw = match encode_mux_frame(MuxKind::Data, stream, b"init", 512) {
            Ok(b) => b,
            Err(err) => panic!("unexpected encode error: {err}"),
        };
        let f = decode_one_frame(&raw);
        let mf = match mux_frame_from_wire(&f) {
            Ok(m) => m,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        match listener.on_frame(&mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }
    }

    let excess_stream = StreamId::new(((MAX_PENDING_STREAMS / 2) * 4) as u32);
    let raw = match encode_mux_frame(MuxKind::Data, excess_stream, b"overflow", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let f = decode_one_frame(&raw);
    let mf = match mux_frame_from_wire(&f) {
        Ok(m) => m,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    let result = listener.on_frame(&mf);
    assert_eq!(result, Err(MuxRefusal::TooManyPendingStreams));
    assert_eq!(listener.refusal(), Some(MuxRefusal::TooManyPendingStreams));
}

#[test]
fn accepting_as_they_arrive_never_reaches_pending_cap() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let total = MAX_PENDING_STREAMS * 3;
    for i in 0..total {
        let stream = StreamId::new((i * 4) as u32);
        let raw = match encode_mux_frame(MuxKind::Data, stream, b"init", 512) {
            Ok(b) => b,
            Err(err) => panic!("unexpected encode error: {err}"),
        };
        let f = decode_one_frame(&raw);
        let mf = match mux_frame_from_wire(&f) {
            Ok(m) => m,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        match listener.on_frame(&mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }
        let accepted = listener.accept_bidirectional();
        assert_eq!(accepted, Some(stream));
    }
}

#[test]
fn negative_unidirectional_directionality_enforcement() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let dialler_uni = match dialler.open_unidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let mut buf = [0u8; 16];
    assert_eq!(
        dialler.read(dialler_uni, &mut buf),
        Err(MuxFault::NotReadable(dialler_uni))
    );

    let listener_uni = match listener.open_unidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let frames = match listener.write(listener_uni, b"from listener") {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    let f = decode_one_frame(&frames[0]);
    let mf = match mux_frame_from_wire(&f) {
        Ok(m) => m,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match dialler.on_frame(&mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(
        dialler.write(listener_uni, b"bad write"),
        Err(MuxFault::NotWritable(listener_uni))
    );
}

#[test]
fn negative_read_and_write_on_unknown_stream_is_no_such_stream() {
    let mut mux = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected mux init error: {err}"),
    };
    let unknown = StreamId::new(42);
    let mut buf = [0u8; 16];
    assert_eq!(
        mux.read(unknown, &mut buf),
        Err(MuxFault::NoSuchStream(unknown))
    );
    assert_eq!(
        mux.write(unknown, b"data"),
        Err(MuxFault::NoSuchStream(unknown))
    );
}

#[test]
fn negative_new_record_limit_boundary() {
    assert_eq!(MIN_RECORD_LIMIT, 6);
    let err = match Multiplexer::new(StreamOpener::Dialler, 512, 5) {
        Ok(_) => panic!("expected RecordLimitTooSmall error"),
        Err(e) => e,
    };
    assert_eq!(err, MuxFault::RecordLimitTooSmall(5));
    assert!(Multiplexer::new(StreamOpener::Dialler, 512, 6).is_ok());
}

#[test]
fn refusal_is_permanent_across_all_multiplexer_operations() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let spoofed_stream = StreamId::new(1);
    let raw = match encode_mux_frame(MuxKind::Data, spoofed_stream, b"bad", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let f = decode_one_frame(&raw);
    let mf = match mux_frame_from_wire(&f) {
        Ok(m) => m,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };

    let refusal = MuxRefusal::PeerAllocatedInOurSpace(spoofed_stream);
    assert_eq!(listener.on_frame(&mf), Err(refusal));
    assert_eq!(listener.refusal(), Some(refusal));

    let fresh_peer_stream = StreamId::new(0);
    let fresh_raw = match encode_mux_frame(MuxKind::Data, fresh_peer_stream, b"good", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let fresh_f = decode_one_frame(&fresh_raw);
    let fresh_mf = match mux_frame_from_wire(&fresh_f) {
        Ok(m) => m,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    assert_eq!(listener.on_frame(&fresh_mf), Err(refusal));

    let mut buf = [0u8; 16];
    assert_eq!(
        listener.read(spoofed_stream, &mut buf),
        Err(MuxFault::Refused(refusal))
    );
    assert_eq!(
        listener.write(spoofed_stream, b"data"),
        Err(MuxFault::Refused(refusal))
    );
    assert_eq!(
        listener.finish(spoofed_stream),
        Err(MuxFault::Refused(refusal))
    );
    assert_eq!(
        listener.open_bidirectional(),
        Err(MuxFault::Refused(refusal))
    );
    assert_eq!(listener.refusal(), Some(refusal));
}

#[test]
fn accept_order_is_first_in_first_out() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let bidi_streams = [StreamId::new(0), StreamId::new(4), StreamId::new(8)];
    for stream in bidi_streams {
        let raw = match encode_mux_frame(MuxKind::Data, stream, b"bidi", 512) {
            Ok(b) => b,
            Err(err) => panic!("unexpected encode error: {err}"),
        };
        let f = decode_one_frame(&raw);
        let mf = match mux_frame_from_wire(&f) {
            Ok(m) => m,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        match listener.on_frame(&mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }
    }

    assert_eq!(listener.accept_bidirectional(), Some(bidi_streams[0]));
    assert_eq!(listener.accept_bidirectional(), Some(bidi_streams[1]));
    assert_eq!(listener.accept_bidirectional(), Some(bidi_streams[2]));
    assert_eq!(listener.accept_bidirectional(), None);

    let uni_streams = [StreamId::new(2), StreamId::new(6), StreamId::new(10)];
    for stream in uni_streams {
        let raw = match encode_mux_frame(MuxKind::Data, stream, b"uni", 512) {
            Ok(b) => b,
            Err(err) => panic!("unexpected encode error: {err}"),
        };
        let f = decode_one_frame(&raw);
        let mf = match mux_frame_from_wire(&f) {
            Ok(m) => m,
            Err(err) => panic!("unexpected mux parse error: {err}"),
        };
        match listener.on_frame(&mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }
    }

    assert_eq!(listener.accept_unidirectional(), Some(uni_streams[0]));
    assert_eq!(listener.accept_unidirectional(), Some(uni_streams[1]));
    assert_eq!(listener.accept_unidirectional(), Some(uni_streams[2]));
    assert_eq!(listener.accept_unidirectional(), None);
}

#[test]
fn retired_bidirectional_stream_refuses_further_frames_as_frame_after_fin_and_closes_channel() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let dialler_fin = match dialler.finish(stream) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let dialler_fin_mf = parse_mux_frame(&dialler_fin);
    match listener.on_frame(&dialler_fin_mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let accepted = match listener.accept_bidirectional() {
        Some(id) => id,
        None => panic!("expected accepted stream"),
    };
    assert_eq!(accepted, stream);

    let listener_fin = match listener.finish(accepted) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let listener_fin_mf = parse_mux_frame(&listener_fin);
    match dialler.on_frame(&listener_fin_mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let mut buf = [0u8; 16];
    assert_eq!(dialler.read(stream, &mut buf), Ok(ReadOutcome::Finished));

    dialler.retire(stream);
    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );

    let extra_raw = match encode_mux_frame(MuxKind::Data, stream, b"late", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let extra_mf = parse_mux_frame(&extra_raw);
    assert_eq!(
        dialler.on_frame(&extra_mf),
        Err(MuxRefusal::FrameAfterFin(stream))
    );
    assert_eq!(dialler.refusal(), Some(MuxRefusal::FrameAfterFin(stream)));
}

#[test]
fn finished_and_drained_stream_before_retire_remains_readable_and_answers_finished() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    let dialler_fin = match dialler.finish(stream) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let dialler_fin_mf = parse_mux_frame(&dialler_fin);
    match listener.on_frame(&dialler_fin_mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }
    let accepted = match listener.accept_bidirectional() {
        Some(id) => id,
        None => panic!("expected accepted stream"),
    };
    let listener_fin = match listener.finish(accepted) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };
    let listener_fin_mf = parse_mux_frame(&listener_fin);
    match dialler.on_frame(&listener_fin_mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let mut buf = [0u8; 16];
    assert_eq!(dialler.read(stream, &mut buf), Ok(ReadOutcome::Finished));
    assert_eq!(dialler.read(stream, &mut buf), Ok(ReadOutcome::Finished));

    dialler.retire(stream);
    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );
}

#[test]
fn retire_called_with_buffered_bytes_does_not_forget_stream_until_drained() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    match dialler.finish(stream) {
        Ok(_) => {}
        Err(err) => panic!("unexpected finish error: {err}"),
    }

    let data_raw = match encode_mux_frame(MuxKind::Data, stream, b"hello world", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match dialler.on_frame(&parse_mux_frame(&data_raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }
    let fin_raw = match encode_mux_frame(MuxKind::Fin, stream, &[], 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match dialler.on_frame(&parse_mux_frame(&fin_raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    dialler.retire(stream);

    let mut buf = [0u8; 5];
    assert_eq!(dialler.read(stream, &mut buf), Ok(ReadOutcome::Read(5)));
    assert_eq!(&buf, b"hello");

    let mut remaining = [0u8; 16];
    assert_eq!(
        dialler.read(stream, &mut remaining),
        Ok(ReadOutcome::Read(6))
    );
    assert_eq!(&remaining[..6], b" world");

    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );
}

#[test]
fn retire_called_before_local_finish_preserves_stream_until_finished() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };

    let fin_raw = match encode_mux_frame(MuxKind::Fin, stream, &[], 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match dialler.on_frame(&parse_mux_frame(&fin_raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    dialler.retire(stream);

    let frames = match dialler.write(stream, b"still open") {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    assert_eq!(frames.len(), 1);

    match dialler.finish(stream) {
        Ok(_) => {}
        Err(err) => panic!("unexpected finish error: {err}"),
    }

    assert_eq!(
        dialler.write(stream, b"after"),
        Err(MuxFault::NoSuchStream(stream))
    );
    assert_eq!(dialler.finish(stream), Err(MuxFault::NoSuchStream(stream)));
}

#[test]
fn retiring_unknown_twice_or_after_refusal_is_idempotent_and_does_not_panic() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };

    dialler.retire(StreamId::new(42));
    dialler.retire(StreamId::new(0));

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    match dialler.finish(stream) {
        Ok(_) => {}
        Err(err) => panic!("unexpected finish error: {err}"),
    }
    let fin_raw = match encode_mux_frame(MuxKind::Fin, stream, &[], 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match dialler.on_frame(&parse_mux_frame(&fin_raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    dialler.retire(stream);
    let mut buf = [0u8; 16];
    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );
    dialler.retire(stream);
    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );

    let spoof_raw = match encode_mux_frame(MuxKind::Data, StreamId::new(4), b"spoof", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let refusal = dialler.on_frame(&parse_mux_frame(&spoof_raw));
    assert_eq!(
        refusal,
        Err(MuxRefusal::PeerAllocatedInOurSpace(StreamId::new(4)))
    );

    dialler.retire(stream);
    dialler.retire(StreamId::new(999));
    assert_eq!(
        dialler.refusal(),
        Some(MuxRefusal::PeerAllocatedInOurSpace(StreamId::new(4)))
    );
}

#[test]
fn peer_first_frame_three_steps_above_base_implicitly_opens_lower_unopened_streams() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream8 = StreamId::new(8);
    let raw = match encode_mux_frame(MuxKind::Data, stream8, b"payload on eight", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match listener.on_frame(&parse_mux_frame(&raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(listener.accept_bidirectional(), Some(StreamId::new(0)));
    assert_eq!(listener.accept_bidirectional(), Some(StreamId::new(4)));
    assert_eq!(listener.accept_bidirectional(), Some(StreamId::new(8)));
    assert_eq!(listener.accept_bidirectional(), None);

    let mut buf = [0u8; 32];
    assert_eq!(
        listener.read(StreamId::new(0), &mut buf),
        Ok(ReadOutcome::Pending)
    );
    assert_eq!(
        listener.read(StreamId::new(4), &mut buf),
        Ok(ReadOutcome::Pending)
    );
    assert_eq!(
        listener.read(StreamId::new(8), &mut buf),
        Ok(ReadOutcome::Read(16))
    );
    assert_eq!(&buf[..16], b"payload on eight");
}

#[test]
fn implicit_opening_exceeding_pending_stream_cap_is_refused_with_too_many_pending_streams() {
    assert_eq!(MAX_PENDING_STREAMS, 64);
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let excessive_stream = StreamId::new(256);
    let raw = match encode_mux_frame(MuxKind::Data, excessive_stream, b"overflow", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let result = listener.on_frame(&parse_mux_frame(&raw));
    assert_eq!(result, Err(MuxRefusal::TooManyPendingStreams));
    assert_eq!(listener.refusal(), Some(MuxRefusal::TooManyPendingStreams));
}

#[test]
fn implicit_opening_does_not_cross_directionality_between_bidi_and_uni() {
    let mut listener_uni_target = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let uni6 = StreamId::new(6);
    let raw_uni = match encode_mux_frame(MuxKind::Data, uni6, b"uni data", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match listener_uni_target.on_frame(&parse_mux_frame(&raw_uni)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(listener_uni_target.accept_bidirectional(), None);
    let mut buf = [0u8; 16];
    assert_eq!(
        listener_uni_target.read(StreamId::new(0), &mut buf),
        Err(MuxFault::NoSuchStream(StreamId::new(0)))
    );
    assert_eq!(
        listener_uni_target.read(StreamId::new(4), &mut buf),
        Err(MuxFault::NoSuchStream(StreamId::new(4)))
    );
    assert_eq!(
        listener_uni_target.accept_unidirectional(),
        Some(StreamId::new(2))
    );
    assert_eq!(
        listener_uni_target.accept_unidirectional(),
        Some(StreamId::new(6))
    );
    assert_eq!(listener_uni_target.accept_unidirectional(), None);

    let mut listener_bidi_target = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let bidi4 = StreamId::new(4);
    let raw_bidi = match encode_mux_frame(MuxKind::Data, bidi4, b"bidi data", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match listener_bidi_target.on_frame(&parse_mux_frame(&raw_bidi)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(listener_bidi_target.accept_unidirectional(), None);
    assert_eq!(
        listener_bidi_target.read(StreamId::new(2), &mut buf),
        Err(MuxFault::NoSuchStream(StreamId::new(2)))
    );
    assert_eq!(
        listener_bidi_target.accept_bidirectional(),
        Some(StreamId::new(0))
    );
    assert_eq!(
        listener_bidi_target.accept_bidirectional(),
        Some(StreamId::new(4))
    );
    assert_eq!(listener_bidi_target.accept_bidirectional(), None);
}

#[test]
fn unidirectional_stream_retires_without_unused_direction_fin() {
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let peer_uni = StreamId::new(2);
    let data_raw = match encode_mux_frame(MuxKind::Data, peer_uni, b"peer uni data", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match listener.on_frame(&parse_mux_frame(&data_raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }
    let fin_raw = match encode_mux_frame(MuxKind::Fin, peer_uni, &[], 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    match listener.on_frame(&parse_mux_frame(&fin_raw)) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(listener.accept_unidirectional(), Some(peer_uni));
    let mut buf = [0u8; 32];
    assert_eq!(listener.read(peer_uni, &mut buf), Ok(ReadOutcome::Read(13)));
    assert_eq!(&buf[..13], b"peer uni data");

    listener.retire(peer_uni);
    assert_eq!(
        listener.read(peer_uni, &mut buf),
        Err(MuxFault::NoSuchStream(peer_uni))
    );

    let extra_raw = match encode_mux_frame(MuxKind::Data, peer_uni, b"more", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    assert_eq!(
        listener.on_frame(&parse_mux_frame(&extra_raw)),
        Err(MuxRefusal::FrameAfterFin(peer_uni))
    );

    let mut local_listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };
    let local_uni = match local_listener.open_unidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    assert_eq!(local_uni, StreamId::new(3));
    match local_listener.write(local_uni, b"local payload") {
        Ok(_) => {}
        Err(err) => panic!("unexpected write error: {err}"),
    }
    match local_listener.finish(local_uni) {
        Ok(_) => {}
        Err(err) => panic!("unexpected finish error: {err}"),
    }

    local_listener.retire(local_uni);
    assert_eq!(
        local_listener.write(local_uni, b"more"),
        Err(MuxFault::NoSuchStream(local_uni))
    );
    assert_eq!(
        local_listener.finish(local_uni),
        Err(MuxFault::NoSuchStream(local_uni))
    );
    let peer_frame = match encode_mux_frame(MuxKind::Data, local_uni, b"echo", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    assert_eq!(
        local_listener.on_frame(&parse_mux_frame(&peer_frame)),
        Err(MuxRefusal::FrameAfterFin(local_uni))
    );
}

#[test]
fn repeated_open_finish_drain_retire_cycles_do_not_leak_streams_in_map() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let mut opened = Vec::new();
    let mut buf = [0u8; 16];
    for _ in 0..100 {
        let stream = match dialler.open_bidirectional() {
            Ok(id) => id,
            Err(err) => panic!("unexpected open error: {err}"),
        };
        opened.push(stream);

        let data_frames = match dialler.write(stream, b"payload") {
            Ok(f) => f,
            Err(err) => panic!("unexpected write error: {err}"),
        };
        let fin_frame = match dialler.finish(stream) {
            Ok(b) => b,
            Err(err) => panic!("unexpected finish error: {err}"),
        };

        for raw in data_frames {
            let mf = parse_mux_frame(&raw);
            match listener.on_frame(&mf) {
                Ok(()) => {}
                Err(err) => panic!("unexpected on_frame error: {err}"),
            }
        }
        let fin_mf = parse_mux_frame(&fin_frame);
        match listener.on_frame(&fin_mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }

        let accepted = match listener.accept_bidirectional() {
            Some(id) => id,
            None => panic!("expected stream to be accepted"),
        };
        assert_eq!(accepted, stream);

        match listener.read(accepted, &mut buf) {
            Ok(ReadOutcome::Read(7)) => {}
            other => panic!("expected ReadOutcome::Read(7), got {other:?}"),
        }
        match listener.read(accepted, &mut buf) {
            Ok(ReadOutcome::Finished) => {}
            other => panic!("expected ReadOutcome::Finished, got {other:?}"),
        }

        let listener_fin = match listener.finish(accepted) {
            Ok(b) => b,
            Err(err) => panic!("unexpected finish error: {err}"),
        };
        let listener_fin_mf = parse_mux_frame(&listener_fin);
        match dialler.on_frame(&listener_fin_mf) {
            Ok(()) => {}
            Err(err) => panic!("unexpected on_frame error: {err}"),
        }

        match dialler.read(stream, &mut buf) {
            Ok(ReadOutcome::Finished) => {}
            other => panic!("expected ReadOutcome::Finished, got {other:?}"),
        }

        dialler.retire(stream);
        listener.retire(stream);
    }

    assert_eq!(opened.len(), 100);
    for stream in &opened {
        assert_eq!(
            dialler.read(*stream, &mut buf),
            Err(MuxFault::NoSuchStream(*stream))
        );
        assert_eq!(
            dialler.write(*stream, b"x"),
            Err(MuxFault::NoSuchStream(*stream))
        );
        assert_eq!(
            dialler.finish(*stream),
            Err(MuxFault::NoSuchStream(*stream))
        );
        assert_eq!(
            listener.read(*stream, &mut buf),
            Err(MuxFault::NoSuchStream(*stream))
        );
        assert_eq!(
            listener.write(*stream, b"x"),
            Err(MuxFault::NoSuchStream(*stream))
        );
        assert_eq!(
            listener.finish(*stream),
            Err(MuxFault::NoSuchStream(*stream))
        );
    }

    assert_eq!(dialler.accept_bidirectional(), None);
    assert_eq!(dialler.accept_unidirectional(), None);
    assert_eq!(listener.accept_bidirectional(), None);
    assert_eq!(listener.accept_unidirectional(), None);
    assert_eq!(dialler.refusal(), None);
    assert_eq!(listener.refusal(), None);

    let late_raw = match encode_mux_frame(MuxKind::Data, opened[0], b"ping", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let late_mf = parse_mux_frame(&late_raw);
    assert_eq!(
        dialler.on_frame(&late_mf),
        Err(MuxRefusal::FrameAfterFin(opened[0]))
    );
}

#[test]
fn bidirectional_stream_retired_locally_stays_alive_for_peer_data_until_peer_fin_and_drained() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };

    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };

    let dialler_frames = match dialler.write(stream, b"initial dialler request") {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    assert_eq!(dialler_frames.len(), 1);

    let _fin_frame = match dialler.finish(stream) {
        Ok(b) => b,
        Err(err) => panic!("unexpected finish error: {err}"),
    };

    dialler.retire(stream);

    let peer_data = b"peer response while dialler send closed";
    let data_raw = match encode_mux_frame(MuxKind::Data, stream, peer_data, 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let data_frame = decode_one_frame(&data_raw);
    let mux_data = match mux_frame_from_wire(&data_frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match dialler.on_frame(&mux_data) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let mut buf = [0u8; 64];
    let outcome1 = match dialler.read(stream, &mut buf[..13]) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome1, ReadOutcome::Read(13));
    assert_eq!(&buf[..13], b"peer response");

    let fin_raw = match encode_mux_frame(MuxKind::Fin, stream, &[], 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let fin_frame = decode_one_frame(&fin_raw);
    let mux_fin = match mux_frame_from_wire(&fin_frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    match dialler.on_frame(&mux_fin) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let remaining_len = peer_data.len() - 13;
    let outcome2 = match dialler.read(stream, &mut buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome2, ReadOutcome::Read(remaining_len));
    assert_eq!(&buf[..remaining_len], &peer_data[13..]);

    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );

    let late_raw = match encode_mux_frame(MuxKind::Data, stream, b"late", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let late_frame = decode_one_frame(&late_raw);
    let mux_late = match mux_frame_from_wire(&late_frame) {
        Ok(mf) => mf,
        Err(err) => panic!("unexpected mux parse error: {err}"),
    };
    assert_eq!(
        dialler.on_frame(&mux_late),
        Err(MuxRefusal::FrameAfterFin(stream))
    );
    assert_eq!(dialler.refusal(), Some(MuxRefusal::FrameAfterFin(stream)));
}

#[test]
fn dialler_receives_listener_opened_bidirectional_stream_and_can_reply() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match listener.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    assert_eq!(stream, StreamId::new(1));

    let listener_payload = b"listener bidirectional request";
    let frames = match listener.write(stream, listener_payload) {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    let mf = parse_mux_frame(&frames[0]);
    match dialler.on_frame(&mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(dialler.accept_bidirectional(), Some(stream));
    assert_eq!(dialler.accept_unidirectional(), None);

    let mut buf = [0u8; 64];
    let outcome = match dialler.read(stream, &mut buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome, ReadOutcome::Read(listener_payload.len()));
    assert_eq!(&buf[..listener_payload.len()], listener_payload);

    let dialler_reply = b"dialler reply on listener bidi";
    let reply_frames = match dialler.write(stream, dialler_reply) {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    let reply_mf = parse_mux_frame(&reply_frames[0]);
    match listener.on_frame(&reply_mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let mut listener_buf = [0u8; 64];
    let listener_outcome = match listener.read(stream, &mut listener_buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(listener_outcome, ReadOutcome::Read(dialler_reply.len()));
    assert_eq!(&listener_buf[..dialler_reply.len()], dialler_reply);
}

#[test]
fn dialler_receives_listener_opened_unidirectional_stream_and_cannot_write() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let mut listener = match Multiplexer::new(StreamOpener::Listener, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected listener init error: {err}"),
    };

    let stream = match listener.open_unidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };
    assert_eq!(stream, StreamId::new(3));

    let listener_payload = b"listener unidirectional stream";
    let frames = match listener.write(stream, listener_payload) {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    let mf = parse_mux_frame(&frames[0]);
    match dialler.on_frame(&mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(dialler.accept_unidirectional(), Some(stream));
    assert_eq!(dialler.accept_bidirectional(), None);

    let mut buf = [0u8; 64];
    let outcome = match dialler.read(stream, &mut buf) {
        Ok(o) => o,
        Err(err) => panic!("unexpected read error: {err}"),
    };
    assert_eq!(outcome, ReadOutcome::Read(listener_payload.len()));
    assert_eq!(&buf[..listener_payload.len()], listener_payload);

    assert_eq!(
        dialler.write(stream, b"illegal"),
        Err(MuxFault::NotWritable(stream))
    );
}

#[test]
fn dialler_implicitly_opens_lower_listener_bidirectional_streams() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };

    let stream5 = StreamId::new(5);
    let payload = b"payload on five";
    let raw = match encode_mux_frame(MuxKind::Data, stream5, payload, 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let mf = parse_mux_frame(&raw);
    match dialler.on_frame(&mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    assert_eq!(dialler.accept_bidirectional(), Some(StreamId::new(1)));
    assert_eq!(dialler.accept_bidirectional(), Some(StreamId::new(5)));
    assert_eq!(dialler.accept_bidirectional(), None);
    assert_eq!(dialler.accept_unidirectional(), None);

    let mut buf = [0u8; 32];
    assert_eq!(
        dialler.read(StreamId::new(1), &mut buf),
        Ok(ReadOutcome::Pending)
    );
    assert_eq!(
        dialler.read(StreamId::new(5), &mut buf),
        Ok(ReadOutcome::Read(payload.len()))
    );
    assert_eq!(&buf[..payload.len()], payload);
}

#[test]
fn peer_fin_retires_bidirectional_stream_when_send_closed_and_retired_first() {
    let mut dialler = match Multiplexer::new(StreamOpener::Dialler, 512, 512) {
        Ok(m) => m,
        Err(err) => panic!("unexpected dialler init error: {err}"),
    };
    let stream = match dialler.open_bidirectional() {
        Ok(id) => id,
        Err(err) => panic!("unexpected open error: {err}"),
    };

    let dialler_frames = match dialler.write(stream, b"dialler request") {
        Ok(f) => f,
        Err(err) => panic!("unexpected write error: {err}"),
    };
    assert_eq!(dialler_frames.len(), 1);

    match dialler.finish(stream) {
        Ok(_) => {}
        Err(err) => panic!("unexpected finish error: {err}"),
    }

    dialler.retire(stream);

    let fin_raw = match encode_mux_frame(MuxKind::Fin, stream, &[], 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let fin_mf = parse_mux_frame(&fin_raw);
    match dialler.on_frame(&fin_mf) {
        Ok(()) => {}
        Err(err) => panic!("unexpected on_frame error: {err}"),
    }

    let mut buf = [0u8; 16];
    assert_eq!(
        dialler.read(stream, &mut buf),
        Err(MuxFault::NoSuchStream(stream))
    );
    assert_eq!(
        dialler.write(stream, b"late"),
        Err(MuxFault::NoSuchStream(stream))
    );
    assert_eq!(dialler.finish(stream), Err(MuxFault::NoSuchStream(stream)));

    let late_raw = match encode_mux_frame(MuxKind::Data, stream, b"late", 512) {
        Ok(b) => b,
        Err(err) => panic!("unexpected encode error: {err}"),
    };
    let late_mf = parse_mux_frame(&late_raw);
    assert_eq!(
        dialler.on_frame(&late_mf),
        Err(MuxRefusal::FrameAfterFin(stream))
    );
    assert_eq!(dialler.refusal(), Some(MuxRefusal::FrameAfterFin(stream)));
}

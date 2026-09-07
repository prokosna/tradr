//! Tests for the sans-io stream multiplexer state machine (docs/04-protocol.md).

use tradr_proto::framing::{Frame, FrameDecoder};
use tradr_proto::mux::{MuxKind, StreamId, StreamOpener, encode_mux_frame, mux_frame_from_wire};
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

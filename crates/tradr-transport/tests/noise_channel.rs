mod common;

use std::sync::Arc;
use std::time::Duration;

use tradr_core::{SecureChannel, TransportError, TransportId};
use tradr_proto::framing::FrameDecoder;
use tradr_proto::mux::{MuxKind, StreamId, StreamOpener, encode_mux_frame, mux_frame_from_wire};
use tradr_transport::noise::{
    BLE_GATT_MAX_FRAME_SIZE, LinkSink, LinkSource, NoiseChannel, NoiseChannelConfig,
};

#[tokio::test]
async fn test_bidirectional_stream_exchanges_bytes_in_both_directions() {
    let (dialler, listener) = common::connected_channels(false);

    let (mut d_send, mut d_recv) = dialler.open_bi().await.expect("dialler opens bi");
    d_send
        .write_all(b"ping from dialler")
        .await
        .expect("dialler writes");
    d_send.finish().await.expect("dialler finishes");

    let (mut l_send, mut l_recv) = listener.accept_bi().await.expect("listener accepts bi");
    let mut d_bytes = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = l_recv.read(&mut buf).await.expect("listener reads");
        if n == 0 {
            break;
        }
        d_bytes.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&d_bytes, b"ping from dialler");

    l_send
        .write_all(b"pong from listener")
        .await
        .expect("listener writes");
    l_send.finish().await.expect("listener finishes");

    let mut l_bytes = Vec::new();
    loop {
        let n = d_recv.read(&mut buf).await.expect("dialler reads");
        if n == 0 {
            break;
        }
        l_bytes.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&l_bytes, b"pong from listener");
}

#[tokio::test]
async fn test_unidirectional_stream_carries_bytes_and_finishes_with_ok_zero() {
    let (dialler, listener) = common::connected_channels(false);

    let mut send = dialler.open_uni().await.expect("open_uni succeeds");
    send.write_all(b"unidirectional data payload")
        .await
        .expect("write_all succeeds");
    send.finish().await.expect("finish succeeds");

    let mut recv = listener.accept_uni().await.expect("accept_uni succeeds");
    let mut received = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = recv.read(&mut buf).await.expect("read succeeds");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&received, b"unidirectional data payload");

    let after_fin = recv
        .read(&mut buf)
        .await
        .expect("read after finish succeeds");
    assert_eq!(after_fin, 0);
}

#[tokio::test]
async fn test_write_larger_than_record_limit_reassembles_input() {
    let (dialler, listener) = common::connected_channels_with_limit(512, false);

    let payload: Vec<u8> = (0..1200).map(|i| (i % 251) as u8).collect();
    let mut send = dialler.open_uni().await.expect("open_uni succeeds");
    send.write_all(&payload).await.expect("write_all succeeds");
    send.finish().await.expect("finish succeeds");

    let mut recv = listener.accept_uni().await.expect("accept_uni succeeds");
    let mut received = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = recv.read(&mut buf).await.expect("read succeeds");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received.len(), 1200);
    assert_eq!(received, payload);
}

#[tokio::test]
async fn test_accept_bi_does_not_return_before_peers_first_frame_arrives() {
    let (dialler, listener) = common::connected_channels(false);

    let (mut send, _recv) = dialler.open_bi().await.expect("open_bi succeeds");

    let listener_arc = Arc::new(listener);
    let l_clone = Arc::clone(&listener_arc);
    let accept_task = tokio::spawn(async move { l_clone.accept_bi().await });

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        !accept_task.is_finished(),
        "accept_bi must wait until first frame arrives"
    );

    send.write_all(b"first frame arrives")
        .await
        .expect("write_all succeeds");

    let accept_result = accept_task
        .await
        .expect("join succeeds")
        .expect("accept_bi succeeds");
    let (_l_send, mut l_recv) = accept_result;
    let mut buf = [0u8; 64];
    let n = l_recv.read(&mut buf).await.expect("read succeeds");
    assert_eq!(&buf[..n], b"first frame arrives");
}

#[tokio::test]
async fn test_concurrent_writes_on_separate_streams_arrive_intact_under_yield() {
    let (dialler, listener) = common::connected_channels(true);
    let dialler = Arc::new(dialler);
    let listener = Arc::new(listener);

    let mut send1 = dialler.open_uni().await.expect("open stream 1");
    let mut send2 = dialler.open_uni().await.expect("open stream 2");

    let task1 = tokio::spawn(async move {
        for i in 0..40 {
            let chunk = format!("stream-1-chunk-{i:03}\n").into_bytes();
            send1.write_all(&chunk).await.expect("send1 write_all");
        }
        send1.finish().await.expect("send1 finish");
    });

    let task2 = tokio::spawn(async move {
        for i in 0..40 {
            let chunk = format!("stream-2-chunk-{i:03}\n").into_bytes();
            send2.write_all(&chunk).await.expect("send2 write_all");
        }
        send2.finish().await.expect("send2 finish");
    });

    let l_clone1 = Arc::clone(&listener);
    let l_clone2 = Arc::clone(&listener);
    let read_task1 = tokio::spawn(async move {
        let mut recv = l_clone1.accept_uni().await.expect("accept stream");
        let mut buf = [0u8; 256];
        let mut received = Vec::new();
        loop {
            let n = recv.read(&mut buf).await.expect("read stream");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        received
    });

    let read_task2 = tokio::spawn(async move {
        let mut recv = l_clone2.accept_uni().await.expect("accept stream");
        let mut buf = [0u8; 256];
        let mut received = Vec::new();
        loop {
            let n = recv.read(&mut buf).await.expect("read stream");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        received
    });

    task1.await.expect("task1 completes");
    task2.await.expect("task2 completes");
    let res1 = read_task1.await.expect("read_task1 completes");
    let res2 = read_task2.await.expect("read_task2 completes");

    let expected1: Vec<u8> = (0..40)
        .flat_map(|i| format!("stream-1-chunk-{i:03}\n").into_bytes())
        .collect();
    let expected2: Vec<u8> = (0..40)
        .flat_map(|i| format!("stream-2-chunk-{i:03}\n").into_bytes())
        .collect();

    let matches_normal = res1 == expected1 && res2 == expected2;
    let matches_swapped = res1 == expected2 && res2 == expected1;
    assert!(
        matches_normal || matches_swapped,
        "both streams must match completely"
    );
}

#[tokio::test]
async fn test_negative_flipped_byte_in_record_causes_authentication_failed() {
    let (mut dialler_session, responder_session) = common::handshaken_pair();
    let (sink, source) = common::memory_channel(32, false);

    let config = NoiseChannelConfig {
        transport: TransportId::new("ble-gatt"),
        opener: StreamOpener::Listener,
        max_frame_size: BLE_GATT_MAX_FRAME_SIZE,
        record_limit: BLE_GATT_MAX_FRAME_SIZE,
        rtt: Duration::from_millis(50),
    };

    let dummy_sink = common::MemorySink::dummy();
    let listener =
        NoiseChannel::new(responder_session, dummy_sink, source, config).expect("listener builds");

    let frame = encode_mux_frame(MuxKind::Data, StreamId::new(0), b"some data", 512)
        .expect("encode frame succeeds");
    let mut record = dialler_session.encrypt(&frame).expect("encrypt succeeds");
    record[0] ^= 0x01;

    sink.send_record(&record)
        .await
        .expect("send_record succeeds");

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    assert_eq!(
        listener.open_bi().await.map(|_| ()),
        Err(TransportError::AuthenticationFailed)
    );
    assert_eq!(
        listener.open_uni().await.map(|_| ()),
        Err(TransportError::AuthenticationFailed)
    );
    assert_eq!(
        listener.accept_bi().await.map(|_| ()),
        Err(TransportError::AuthenticationFailed)
    );
    assert_eq!(
        listener.accept_uni().await.map(|_| ()),
        Err(TransportError::AuthenticationFailed)
    );
}

#[tokio::test]
async fn test_negative_frame_naming_stream_in_receivers_own_space_closes_channel() {
    let (mut dialler_session, responder_session) = common::handshaken_pair();
    let (sink, source) = common::memory_channel(32, false);

    let config = NoiseChannelConfig {
        transport: TransportId::new("ble-gatt"),
        opener: StreamOpener::Listener,
        max_frame_size: BLE_GATT_MAX_FRAME_SIZE,
        record_limit: BLE_GATT_MAX_FRAME_SIZE,
        rtt: Duration::from_millis(50),
    };

    let dummy_sink = common::MemorySink::dummy();
    let listener =
        NoiseChannel::new(responder_session, dummy_sink, source, config).expect("listener builds");

    let frame = encode_mux_frame(MuxKind::Data, StreamId::new(1), b"trespass", 512)
        .expect("encode frame succeeds");
    let record = dialler_session.encrypt(&frame).expect("encrypt succeeds");
    sink.send_record(&record)
        .await
        .expect("send_record succeeds");

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    assert_eq!(
        listener.open_bi().await.map(|_| ()),
        Err(TransportError::Closed)
    );
    assert_eq!(
        listener.accept_bi().await.map(|_| ()),
        Err(TransportError::Closed)
    );
}

#[tokio::test]
async fn test_frame_on_retired_stream_closes_channel() {
    let (mut dialler_session, responder_session) = common::handshaken_pair();
    // `memory_link_pair` returns one full endpoint per tuple; the listener owns one whole
    // endpoint and the test drives the other, never mixing a sink from one with a source from
    // the other, which is the self-loop that made `accept_bi` wait forever.
    let (listener_endpoint, driver_endpoint) = common::memory_link_pair(32, false);
    let (listener_sink, listener_source) = listener_endpoint;
    let (driver_sink, mut driver_source) = driver_endpoint;

    let config = NoiseChannelConfig {
        transport: TransportId::new("ble-gatt"),
        opener: StreamOpener::Listener,
        max_frame_size: BLE_GATT_MAX_FRAME_SIZE,
        record_limit: BLE_GATT_MAX_FRAME_SIZE,
        rtt: Duration::from_millis(50),
    };

    let listener = NoiseChannel::new(responder_session, listener_sink, listener_source, config)
        .expect("listener builds");

    let frame_data =
        encode_mux_frame(MuxKind::Data, StreamId::new(0), b"first", 512).expect("encode data");
    let record_data = dialler_session.encrypt(&frame_data).expect("encrypt data");
    driver_sink
        .send_record(&record_data)
        .await
        .expect("send data");

    let frame_fin = encode_mux_frame(MuxKind::Fin, StreamId::new(0), b"", 512).expect("encode fin");
    let record_fin = dialler_session.encrypt(&frame_fin).expect("encrypt fin");
    driver_sink
        .send_record(&record_fin)
        .await
        .expect("send fin");

    {
        let (mut send, mut recv) = listener.accept_bi().await.expect("accept_bi");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"first");
        send.finish().await.expect("finish");
        let eof = recv.read(&mut buf).await.expect("read eof");
        assert_eq!(eof, 0);
    }

    let listener_record = driver_source
        .recv_record()
        .await
        .expect("recv record")
        .expect("record present");
    let decrypted = dialler_session
        .decrypt(&listener_record)
        .expect("decrypt listener record");
    // The listener's `finish()` sent a `StreamFin` frame, never an empty record.
    let mut decoder = FrameDecoder::new(BLE_GATT_MAX_FRAME_SIZE);
    decoder.feed(&decrypted);
    let wire_frame = decoder
        .next_frame()
        .expect("frame decodes")
        .expect("one whole frame is buffered");
    let mux_frame = mux_frame_from_wire(&wire_frame).expect("mux frame decodes");
    assert_eq!(mux_frame.kind(), MuxKind::Fin);
    assert_eq!(mux_frame.stream_id(), StreamId::new(0));

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    let extra_frame =
        encode_mux_frame(MuxKind::Data, StreamId::new(0), b"ghost", 512).expect("encode ghost");
    let extra_record = dialler_session
        .encrypt(&extra_frame)
        .expect("encrypt ghost");
    driver_sink
        .send_record(&extra_record)
        .await
        .expect("send ghost");

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    assert_eq!(
        listener.accept_bi().await.map(|_| ()),
        Err(TransportError::Closed)
    );
    assert_eq!(
        listener.open_bi().await.map(|_| ()),
        Err(TransportError::Closed)
    );
}

#[tokio::test]
async fn test_close_makes_pending_read_return_closed() {
    let (dialler, listener) = common::connected_channels(false);

    let (mut d_send, _d_recv) = dialler.open_bi().await.expect("open_bi");
    d_send.write_all(b"initial").await.expect("write_all");

    let (_l_send, mut l_recv) = listener.accept_bi().await.expect("accept_bi");
    let mut buf = [0u8; 64];
    let n = l_recv.read(&mut buf).await.expect("read initial");
    assert_eq!(&buf[..n], b"initial");

    let read_task = tokio::spawn(async move {
        let mut buf2 = [0u8; 64];
        l_recv.read(&mut buf2).await
    });

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!read_task.is_finished());

    listener.close().await.expect("close succeeds");

    let read_result = read_task.await.expect("join succeeds");
    assert_eq!(read_result, Err(TransportError::Closed));
}

#[tokio::test]
async fn test_dropping_channel_wakes_a_surviving_streams_pending_read() {
    let (dialler, listener) = common::connected_channels(false);

    let (mut d_send, _d_recv) = dialler.open_bi().await.expect("open_bi");
    d_send.write_all(b"initial").await.expect("write_all");

    let (_l_send, mut l_recv) = listener.accept_bi().await.expect("accept_bi");
    let mut buf = [0u8; 64];
    let n = l_recv.read(&mut buf).await.expect("read initial");
    assert_eq!(&buf[..n], b"initial");

    // `l_recv` outlives `listener` in the spawned task below, holding its own `Arc` of the
    // shared state; nothing but the channel's `Drop` can wake this pending read.
    let read_task = tokio::spawn(async move {
        let mut buf2 = [0u8; 64];
        l_recv.read(&mut buf2).await
    });

    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!read_task.is_finished());

    drop(listener);

    let read_result = tokio::time::timeout(Duration::from_secs(5), read_task)
        .await
        .expect("read task completes before the timeout instead of hanging")
        .expect("join succeeds");
    assert_eq!(read_result, Err(TransportError::Closed));
}

#[tokio::test]
async fn test_empty_write_to_a_finished_stream_is_refused_not_silently_accepted() {
    let (dialler, _listener) = common::connected_channels(false);

    let mut send = dialler.open_uni().await.expect("open_uni succeeds");
    send.finish().await.expect("finish succeeds");

    // The multiplexer already refuses `AlreadyFinished` before it would answer an empty
    // write with `Ok(Vec::new())`, so an empty buffer must reach that refusal rather than
    // short-circuiting in `write_all` before the multiplexer is consulted.
    let result = send.write_all(b"").await;
    assert_eq!(result, Err(TransportError::Closed));
}

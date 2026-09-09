use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tradr_core::{BoxFuture, TransportError};
use tradr_transport::noise::{
    BLE_GATT_MAX_RECORD, ByteSink, ByteSource, LinkSink, LinkSource, RecordSink, RecordSource,
};

#[derive(Clone, Default)]
struct RecordingByteSink {
    recorded: Arc<Mutex<Vec<u8>>>,
    closed: Arc<AtomicBool>,
}

impl RecordingByteSink {
    fn new() -> Self {
        Self::default()
    }

    fn written(&self) -> Vec<u8> {
        self.recorded
            .lock()
            .expect("no test poisons this lock")
            .clone()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl ByteSink for RecordingByteSink {
    fn send_bytes<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.recorded
                .lock()
                .expect("no test poisons this lock")
                .extend_from_slice(bytes);
            Ok(())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
}

type DeliverySlot = Result<Option<Vec<u8>>, TransportError>;

#[derive(Clone)]
struct ListByteSource {
    deliveries: Arc<Mutex<VecDeque<DeliverySlot>>>,
    read_count: Arc<AtomicUsize>,
}

impl ListByteSource {
    fn new(deliveries: Vec<Vec<u8>>) -> Self {
        Self {
            deliveries: Arc::new(Mutex::new(
                deliveries.into_iter().map(|d| Ok(Some(d))).collect(),
            )),
            read_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_eofs(deliveries: Vec<Option<Vec<u8>>>) -> Self {
        Self {
            deliveries: Arc::new(Mutex::new(deliveries.into_iter().map(Ok).collect())),
            read_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_results(deliveries: Vec<DeliverySlot>) -> Self {
        Self {
            deliveries: Arc::new(Mutex::new(VecDeque::from(deliveries))),
            read_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn read_count(&self) -> usize {
        self.read_count.load(Ordering::SeqCst)
    }

    fn remaining_deliveries(&self) -> usize {
        self.deliveries
            .lock()
            .expect("no test poisons this lock")
            .len()
    }
}

impl ByteSource for ListByteSource {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            self.read_count.fetch_add(1, Ordering::SeqCst);
            match self
                .deliveries
                .lock()
                .expect("no test poisons this lock")
                .pop_front()
            {
                Some(res) => res,
                None => Ok(None),
            }
        })
    }
}

#[tokio::test]
async fn test_one_record_round_trips_through_sink_and_source() {
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), BLE_GATT_MAX_RECORD);

    let payload = b"hello from tradr transport";
    sink.send_record(payload).await.expect("send succeeds");
    sink.close().await.expect("close succeeds");
    assert!(sink_double.is_closed());

    let bytes = sink_double.written();
    let source_double = ListByteSource::new(vec![bytes]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let received = source.recv_record().await.expect("recv succeeds");
    assert_eq!(received.as_deref(), Some(&payload[..]));

    let eof = source.recv_record().await.expect("eof succeeds");
    assert_eq!(eof, None);
}

#[tokio::test]
async fn test_bytes_sink_writes_are_two_byte_big_endian_length_followed_by_record() {
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), BLE_GATT_MAX_RECORD);

    let payload = b"framed-record";
    sink.send_record(payload).await.expect("send succeeds");

    let mut expected = Vec::new();
    expected.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    expected.extend_from_slice(payload);

    assert_eq!(sink_double.written(), expected);
}

#[tokio::test]
async fn test_three_records_written_in_turn_are_returned_one_at_a_time_in_order() {
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), BLE_GATT_MAX_RECORD);

    sink.send_record(b"first").await.expect("send first");
    sink.send_record(b"second").await.expect("send second");
    sink.send_record(b"third").await.expect("send third");

    let source_double = ListByteSource::new(vec![sink_double.written()]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    assert_eq!(
        source.recv_record().await.expect("first").as_deref(),
        Some(&b"first"[..])
    );
    assert_eq!(
        source.recv_record().await.expect("second").as_deref(),
        Some(&b"second"[..])
    );
    assert_eq!(
        source.recv_record().await.expect("third").as_deref(),
        Some(&b"third"[..])
    );
    assert_eq!(source.recv_record().await.expect("eof"), None);
}

#[tokio::test]
async fn test_several_whole_records_arriving_in_one_delivery_are_returned_in_order() {
    let mut delivery = Vec::new();
    let records: &[&[u8]] = &[b"record-1", b"record-2", b"record-3"];
    for r in records {
        delivery.extend_from_slice(&(r.len() as u16).to_be_bytes());
        delivery.extend_from_slice(r);
    }

    let source_double = ListByteSource::new(vec![delivery]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    for expected in records {
        let got = source.recv_record().await.expect("recv record");
        assert_eq!(got.as_deref(), Some(*expected));
    }
    assert_eq!(source.recv_record().await.expect("eof"), None);
}

#[tokio::test]
async fn test_one_record_split_across_many_deliveries_one_byte_at_a_time_is_reassembled() {
    let payload = b"piecemeal-delivery-bytes";
    let mut full = Vec::new();
    full.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    full.extend_from_slice(payload);

    let deliveries: Vec<Vec<u8>> = full.iter().map(|&b| vec![b]).collect();
    let source_double = ListByteSource::new(deliveries);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let received = source.recv_record().await.expect("reassembled record");
    assert_eq!(received.as_deref(), Some(&payload[..]));
    assert_eq!(source.recv_record().await.expect("eof"), None);
}

#[tokio::test]
async fn test_delivery_holding_tail_of_one_record_and_head_of_next_is_handled() {
    let r1 = b"first-record-tail";
    let r2 = b"second-record-head";

    let mut w1 = Vec::new();
    w1.extend_from_slice(&(r1.len() as u16).to_be_bytes());
    w1.extend_from_slice(r1);

    let mut w2 = Vec::new();
    w2.extend_from_slice(&(r2.len() as u16).to_be_bytes());
    w2.extend_from_slice(r2);

    let d1 = w1[..10].to_vec();
    let mut d2 = w1[10..].to_vec();
    d2.extend_from_slice(&w2[..6]);
    let d3 = w2[6..].to_vec();

    let source_double = ListByteSource::new(vec![d1, d2, d3]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    assert_eq!(
        source.recv_record().await.expect("r1").as_deref(),
        Some(&r1[..])
    );
    assert_eq!(
        source.recv_record().await.expect("r2").as_deref(),
        Some(&r2[..])
    );
    assert_eq!(source.recv_record().await.expect("eof"), None);
}

#[tokio::test]
async fn test_record_of_exactly_max_record_bytes_round_trips() {
    let max = BLE_GATT_MAX_RECORD;
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), max);

    let payload = vec![0x3a; max as usize];
    sink.send_record(&payload).await.expect("send max record");

    let source_double = ListByteSource::new(vec![sink_double.written()]);
    let mut source = RecordSource::new(source_double, max);

    let rec = source.recv_record().await.expect("recv max record");
    assert_eq!(rec, Some(payload));
    assert_eq!(source.recv_record().await.expect("eof"), None);
}

#[tokio::test]
async fn test_record_of_exactly_one_byte_round_trips() {
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), BLE_GATT_MAX_RECORD);

    let payload = vec![0x99];
    sink.send_record(&payload)
        .await
        .expect("send 1-byte record");

    let source_double = ListByteSource::new(vec![sink_double.written()]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let rec = source.recv_record().await.expect("recv 1-byte record");
    assert_eq!(rec, Some(payload));
    assert_eq!(source.recv_record().await.expect("eof"), None);
}

#[tokio::test]
async fn test_sink_refuses_empty_record_with_invalid_input_and_writes_nothing() {
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), BLE_GATT_MAX_RECORD);

    let res = sink.send_record(&[]).await;
    assert_eq!(
        res,
        Err(TransportError::Io(std::io::ErrorKind::InvalidInput))
    );
    assert!(sink_double.written().is_empty());
}

#[tokio::test]
async fn test_sink_refuses_record_exceeding_max_record_with_invalid_input_and_writes_nothing() {
    let max = BLE_GATT_MAX_RECORD;
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), max);

    let oversized = vec![0xaa; max as usize + 1];
    let res = sink.send_record(&oversized).await;
    assert_eq!(
        res,
        Err(TransportError::Io(std::io::ErrorKind::InvalidInput))
    );
    assert!(sink_double.written().is_empty());
}

#[tokio::test]
async fn test_sink_refusal_does_not_latch_and_the_next_record_is_sent_normally() {
    let sink_double = RecordingByteSink::new();
    let sink = RecordSink::new(sink_double.clone(), BLE_GATT_MAX_RECORD);

    let res1 = sink.send_record(&[]).await;
    assert_eq!(
        res1,
        Err(TransportError::Io(std::io::ErrorKind::InvalidInput))
    );

    let payload = b"second record after refusal";
    sink.send_record(payload)
        .await
        .expect("second record sent normally");

    let mut expected = Vec::new();
    expected.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    expected.extend_from_slice(payload);

    assert_eq!(sink_double.written(), expected);
}

#[tokio::test]
async fn test_length_prefix_of_zero_is_refused_with_invalid_data() {
    let source_double = ListByteSource::new(vec![vec![0x00, 0x00]]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let res = source.recv_record().await;
    assert_eq!(
        res,
        Err(TransportError::Io(std::io::ErrorKind::InvalidData))
    );
}

#[tokio::test]
async fn test_length_prefix_greater_than_max_record_refused_before_payload_arrives() {
    let max = BLE_GATT_MAX_RECORD;
    let oversized_len = max + 1;
    let prefix = oversized_len.to_be_bytes().to_vec();
    let payload = vec![0x55; oversized_len as usize];

    let source_double = ListByteSource::new(vec![prefix, payload]);
    let double_handle = source_double.clone();
    let mut source = RecordSource::new(source_double, max);

    let res = source.recv_record().await;
    assert_eq!(
        res,
        Err(TransportError::Io(std::io::ErrorKind::InvalidData))
    );
    assert_eq!(double_handle.read_count(), 1);
    assert_eq!(double_handle.remaining_deliveries(), 1);
}

#[tokio::test]
async fn test_link_ending_with_nothing_buffered_is_ok_none() {
    let source_double = ListByteSource::new(vec![]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let res = source.recv_record().await.expect("clean eof");
    assert_eq!(res, None);
}

#[tokio::test]
async fn test_link_ending_with_partial_record_buffered_is_invalid_data() {
    let partial = vec![0x00, 0x0a, 1, 2, 3, 4];
    let source_double = ListByteSource::new(vec![partial]);
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let res = source.recv_record().await;
    assert_eq!(
        res,
        Err(TransportError::Io(std::io::ErrorKind::InvalidData))
    );
}

#[tokio::test]
async fn test_delivery_larger_than_max_record_plus_two_is_refused() {
    let max = BLE_GATT_MAX_RECORD;
    let mut delivery = vec![0x11; max as usize + 3];
    delivery[0] = 0x00;
    delivery[1] = 0x05;

    let source_double = ListByteSource::new(vec![delivery]);
    let mut source = RecordSource::new(source_double, max);

    let res = source.recv_record().await;
    assert_eq!(
        res,
        Err(TransportError::Io(std::io::ErrorKind::InvalidData))
    );
}

#[tokio::test]
async fn test_refusal_is_permanent_and_source_is_never_read_again() {
    let max = BLE_GATT_MAX_RECORD;
    let well_formed = vec![0x00, 0x02, 0x11, 0x22];

    {
        let source_double = ListByteSource::new(vec![vec![0x00, 0x00], well_formed.clone()]);
        let double_handle = source_double.clone();
        let mut source = RecordSource::new(source_double, max);

        let err1 = source.recv_record().await;
        assert_eq!(
            err1,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        let reads_after_first = double_handle.read_count();

        let err2 = source.recv_record().await;
        assert_eq!(
            err2,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        assert_eq!(double_handle.read_count(), reads_after_first);
        assert_eq!(double_handle.remaining_deliveries(), 1);
    }

    {
        let prefix = (max + 1).to_be_bytes().to_vec();
        let source_double = ListByteSource::new(vec![prefix, well_formed.clone()]);
        let double_handle = source_double.clone();
        let mut source = RecordSource::new(source_double, max);

        let err1 = source.recv_record().await;
        assert_eq!(
            err1,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        let reads_after_first = double_handle.read_count();

        let err2 = source.recv_record().await;
        assert_eq!(
            err2,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        assert_eq!(double_handle.read_count(), reads_after_first);
        assert_eq!(double_handle.remaining_deliveries(), 1);
    }

    {
        let partial = vec![0x00, 0x05, 1, 2];
        let source_double =
            ListByteSource::with_eofs(vec![Some(partial), None, Some(well_formed.clone())]);
        let double_handle = source_double.clone();
        let mut source = RecordSource::new(source_double, max);

        let err1 = source.recv_record().await;
        assert_eq!(
            err1,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        let reads_after_first = double_handle.read_count();

        let err2 = source.recv_record().await;
        assert_eq!(
            err2,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        assert_eq!(double_handle.read_count(), reads_after_first);
        assert_eq!(double_handle.remaining_deliveries(), 1);
    }

    {
        let mut oversized_delivery = vec![0x11; max as usize + 3];
        oversized_delivery[0] = 0x00;
        oversized_delivery[1] = 0x05;
        let source_double = ListByteSource::new(vec![oversized_delivery, well_formed.clone()]);
        let double_handle = source_double.clone();
        let mut source = RecordSource::new(source_double, max);

        let err1 = source.recv_record().await;
        assert_eq!(
            err1,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        let reads_after_first = double_handle.read_count();

        let err2 = source.recv_record().await;
        assert_eq!(
            err2,
            Err(TransportError::Io(std::io::ErrorKind::InvalidData))
        );
        assert_eq!(double_handle.read_count(), reads_after_first);
        assert_eq!(double_handle.remaining_deliveries(), 1);
    }
}

#[tokio::test]
async fn test_inner_error_latches_and_the_source_is_never_read_again() {
    let partial = vec![0x00, 0x05, 0x01, 0x02];
    let err = TransportError::Io(std::io::ErrorKind::ConnectionReset);
    let well_formed = vec![0x00, 0x02, 0xaa, 0xbb];

    let source_double =
        ListByteSource::with_results(vec![Ok(Some(partial)), Err(err), Ok(Some(well_formed))]);
    let double_handle = source_double.clone();
    let mut source = RecordSource::new(source_double, BLE_GATT_MAX_RECORD);

    let err1 = source.recv_record().await;
    assert_eq!(err1, Err(err));
    let reads_after_first = double_handle.read_count();

    let err2 = source.recv_record().await;
    assert_eq!(err2, Err(err));
    assert_eq!(double_handle.read_count(), reads_after_first);
    assert_eq!(double_handle.remaining_deliveries(), 1);
}

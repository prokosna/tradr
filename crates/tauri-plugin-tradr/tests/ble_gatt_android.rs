//! Unit and integration tests for Android BLE GATT server glue (docs/03, DCR-099, DCR-101, DCR-102).
//! Carries no cfg so host cargo test validates mappings, queues, and registry invariants.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tauri_plugin_tradr::ble_gatt_android::{
    GATT_LINK_QUEUE_CAPACITY, GattAcceptor, GattIncoming, GattLink, GattLinkSource, GattLinks,
    GattPush, GattSendOutcome, GattServerOutcome, send_outcome_error, server_outcome_error,
};
use tokio::sync::Notify;
use tradr_core::{
    BoxFuture, DeviceId, Incoming, RecvStream, SecureChannel, SendStream, TransportError,
    TransportId,
};
use tradr_transport::noise::ByteSource;

// A rule that stops answering must fail this suite rather than park it (rule E1); the bound
// turns a hang into a failure and is not a wall-clock wait, which is rule E3's distinction.
async fn bounded<T>(body: impl Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(10), body)
        .await
        .expect("the rule under test answered rather than hanging")
}

#[test]
fn server_outcome_error_maps_all_variants_and_isolates_unsupported_and_permission_denied() {
    assert_eq!(server_outcome_error(&GattServerOutcome::Ok), None);
    assert_eq!(
        server_outcome_error(&GattServerOutcome::Unsupported),
        Some(TransportError::Io(ErrorKind::Unsupported))
    );
    assert_eq!(
        server_outcome_error(&GattServerOutcome::PermissionDenied),
        Some(TransportError::Io(ErrorKind::PermissionDenied))
    );
    assert_eq!(
        server_outcome_error(&GattServerOutcome::AdapterUnavailable),
        Some(TransportError::Io(ErrorKind::NotConnected))
    );
    assert_eq!(
        server_outcome_error(&GattServerOutcome::ServerFailed),
        Some(TransportError::Io(ErrorKind::Other))
    );

    let unsupported = server_outcome_error(&GattServerOutcome::Unsupported).unwrap();
    let permission_denied = server_outcome_error(&GattServerOutcome::PermissionDenied).unwrap();
    assert_ne!(unsupported, permission_denied);
}

#[test]
fn send_outcome_error_maps_all_variants_and_ensures_no_such_link_is_closed() {
    assert_eq!(send_outcome_error(&GattSendOutcome::Ok), None);
    assert_eq!(
        send_outcome_error(&GattSendOutcome::NoSuchLink),
        Some(TransportError::Closed)
    );
    assert_eq!(
        send_outcome_error(&GattSendOutcome::SendFailed),
        Some(TransportError::Io(ErrorKind::Other))
    );

    let no_such_link = send_outcome_error(&GattSendOutcome::NoSuchLink).unwrap();
    assert_eq!(no_such_link, TransportError::Closed);
    assert!(!matches!(no_such_link, TransportError::Io(_)));
}

#[test]
fn gatt_push_serde_round_trip_pins_wire_key_names() {
    let sub_wire = r#"{"push":"subscribed","handle":"AA:BB:CC:DD:EE:FF"}"#;
    let sub: GattPush = serde_json::from_str(sub_wire).expect("deserialize subscribed");
    assert_eq!(
        sub,
        GattPush::Subscribed {
            handle: "AA:BB:CC:DD:EE:FF".to_string(),
        }
    );
    let sub_reserialized = serde_json::to_string(&sub).expect("serialize subscribed");
    assert_eq!(sub_reserialized, sub_wire);

    let bytes_wire = r#"{"push":"bytes","handle":"AA:BB:CC:DD:EE:FF","data":"AQIDBA=="}"#;
    let bytes: GattPush = serde_json::from_str(bytes_wire).expect("deserialize bytes");
    assert_eq!(
        bytes,
        GattPush::Bytes {
            handle: "AA:BB:CC:DD:EE:FF".to_string(),
            data: "AQIDBA==".to_string(),
        }
    );
    let bytes_reserialized = serde_json::to_string(&bytes).expect("serialize bytes");
    assert_eq!(bytes_reserialized, bytes_wire);

    let unsub_wire = r#"{"push":"unsubscribed","handle":"AA:BB:CC:DD:EE:FF"}"#;
    let unsub: GattPush = serde_json::from_str(unsub_wire).expect("deserialize unsubscribed");
    assert_eq!(
        unsub,
        GattPush::Unsubscribed {
            handle: "AA:BB:CC:DD:EE:FF".to_string(),
        }
    );
    let unsub_reserialized = serde_json::to_string(&unsub).expect("serialize unsubscribed");
    assert_eq!(unsub_reserialized, unsub_wire);

    let disc_wire = r#"{"push":"disconnected","handle":"AA:BB:CC:DD:EE:FF"}"#;
    let disc: GattPush = serde_json::from_str(disc_wire).expect("deserialize disconnected");
    assert_eq!(
        disc,
        GattPush::Disconnected {
            handle: "AA:BB:CC:DD:EE:FF".to_string(),
        }
    );
    let disc_reserialized = serde_json::to_string(&disc).expect("serialize disconnected");
    assert_eq!(disc_reserialized, disc_wire);
}

#[tokio::test]
async fn pop_yields_deliveries_in_push_order_and_awaits_when_empty() {
    bounded(async {
        // A regression here waits for concurrent delivery forever;
        // a timeout turns that hang into a failure rather than waiting on wall-clock time (rule E3).
        let link = GattLink::new();
        link.push(vec![1, 2, 3]);
        link.push(vec![4, 5]);

        let first = link.pop().await.expect("pop first delivery");
        assert_eq!(first, Some(vec![1, 2, 3]));

        let second = link.pop().await.expect("pop second delivery");
        assert_eq!(second, Some(vec![4, 5]));

        let (third, ()) = tokio::join!(link.pop(), async {
            link.push(vec![6, 7, 8]);
        });
        assert_eq!(third.expect("pop concurrent delivery"), Some(vec![6, 7, 8]));
    })
    .await;
}

#[tokio::test]
async fn pop_answers_ok_none_once_stream_ended_and_queued_exhausted() {
    bounded(async {
        let link = GattLink::new();
        link.push(vec![10]);
        link.push(vec![20]);
        link.end();

        assert_eq!(link.pop().await.unwrap(), Some(vec![10]));
        assert_eq!(link.pop().await.unwrap(), Some(vec![20]));
        assert_eq!(link.pop().await.unwrap(), None);
        assert_eq!(link.pop().await.unwrap(), None);
    })
    .await;
}

#[tokio::test]
async fn push_above_capacity_latches_out_of_memory_and_exact_bound_is_accepted() {
    bounded(async {
        let exact_link = GattLink::new();
        let exact_bound_payload = vec![0x42; GATT_LINK_QUEUE_CAPACITY];
        exact_link.push(exact_bound_payload.clone());
        let popped = exact_link.pop().await.expect("pop exact bound delivery");
        assert_eq!(popped, Some(exact_bound_payload));

        let overflow_link = GattLink::new();
        overflow_link.push(vec![0x42; GATT_LINK_QUEUE_CAPACITY]);
        overflow_link.push(vec![0x99; 1]);
        overflow_link.end();
        let err = overflow_link
            .pop()
            .await
            .expect_err("capacity overflow latched error");
        assert_eq!(err, TransportError::Io(ErrorKind::OutOfMemory));
    })
    .await;
}

#[tokio::test]
async fn latched_error_is_permanent_and_persists_across_push_and_end() {
    bounded(async {
        let link = GattLink::new();
        link.push(vec![0xAA; GATT_LINK_QUEUE_CAPACITY + 1]);

        let err1 = link
            .pop()
            .await
            .expect_err("first pop fails with latched error");
        assert_eq!(err1, TransportError::Io(ErrorKind::OutOfMemory));

        link.push(vec![1, 2, 3]);
        let err2 = link
            .pop()
            .await
            .expect_err("second pop fails after later push");
        assert_eq!(err2, TransportError::Io(ErrorKind::OutOfMemory));

        link.end();
        let err3 = link
            .pop()
            .await
            .expect_err("third pop fails after stream end");
        assert_eq!(err3, TransportError::Io(ErrorKind::OutOfMemory));
    })
    .await;
}

#[tokio::test]
async fn push_after_end_is_discarded_and_changes_nothing() {
    bounded(async {
        let link = GattLink::new();
        link.end();

        assert_eq!(link.pop().await.unwrap(), None);

        link.push(vec![1, 2, 3]);
        assert_eq!(link.pop().await.unwrap(), None);
    })
    .await;
}

#[tokio::test]
async fn subscribed_opens_link_and_next_link_yields_in_arrival_order() {
    bounded(async {
        let links = GattLinks::new();
        links.apply(&GattPush::Subscribed {
            handle: "handle-1".to_string(),
        });
        links.apply(&GattPush::Subscribed {
            handle: "handle-2".to_string(),
        });

        let first_handle = links.next_link().await;
        assert_eq!(first_handle, "handle-1");

        let second_handle = links.next_link().await;
        assert_eq!(second_handle, "handle-2");

        assert!(links.link("handle-1").is_some());
        assert!(links.link("handle-2").is_some());
    })
    .await;
}

#[tokio::test]
async fn subscribed_for_existing_handle_ends_link_opens_fresh_and_reannounces() {
    bounded(async {
        // A regression omitting the old link's end() or deduplicating next_link would
        // hang forever; a timeout turns that hang into a failure rather than waiting
        // on wall-clock time (rule E3).
        let links = GattLinks::new();
        links.apply(&GattPush::Subscribed {
            handle: "handle-reused".to_string(),
        });

        let first_arc = links.link("handle-reused").expect("first link exists");
        first_arc.push(vec![1, 2, 3]);

        links.apply(&GattPush::Subscribed {
            handle: "handle-reused".to_string(),
        });

        let second_arc = links.link("handle-reused").expect("second link exists");
        assert!(!Arc::ptr_eq(&first_arc, &second_arc));

        assert_eq!(first_arc.pop().await.unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(first_arc.pop().await.unwrap(), None);

        assert_eq!(links.next_link().await, "handle-reused");
        assert_eq!(links.next_link().await, "handle-reused");
    })
    .await;
}

#[tokio::test]
async fn bytes_pushes_decoded_data_into_held_link() {
    bounded(async {
        let links = GattLinks::new();
        links.apply(&GattPush::Subscribed {
            handle: "device-bytes".to_string(),
        });

        let raw = vec![11, 22, 33, 44];
        links.apply(&GattPush::Bytes {
            handle: "device-bytes".to_string(),
            data: STANDARD.encode(&raw),
        });

        let link = links.link("device-bytes").unwrap();
        let popped = link.pop().await.unwrap();
        assert_eq!(popped, Some(raw));
    })
    .await;
}

#[tokio::test]
async fn bytes_for_unlinked_handle_is_discarded_without_poisoning() {
    bounded(async {
        let links = GattLinks::new();
        links.apply(&GattPush::Bytes {
            handle: "unregistered".to_string(),
            data: STANDARD.encode([1, 2, 3]),
        });
        assert!(links.link("unregistered").is_none());

        links.apply(&GattPush::Subscribed {
            handle: "unregistered".to_string(),
        });

        let link = links.link("unregistered").unwrap();
        let (popped, ()) = tokio::join!(link.pop(), async {
            link.push(vec![99]);
        });
        assert_eq!(popped.unwrap(), Some(vec![99]));
    })
    .await;
}

#[tokio::test]
async fn invalid_base64_latches_invalid_data_error_on_held_link() {
    bounded(async {
        let links = GattLinks::new();
        links.apply(&GattPush::Subscribed {
            handle: "device-invalid-b64".to_string(),
        });

        links.apply(&GattPush::Bytes {
            handle: "device-invalid-b64".to_string(),
            data: "!!!not-valid-base64!!!".to_string(),
        });

        let link = links.link("device-invalid-b64").unwrap();
        // Ending the link prevents pop from hanging if the error was dropped;
        // the latched error must still take precedence over the clean end.
        link.end();
        let err = link.pop().await.expect_err("invalid base64 latches error");
        assert_eq!(err, TransportError::Io(ErrorKind::InvalidData));
        assert_ne!(err, TransportError::Io(ErrorKind::OutOfMemory));
    })
    .await;
}

#[tokio::test]
async fn unsubscribed_and_disconnected_end_held_link_and_noop_if_absent() {
    bounded(async {
        let links = GattLinks::new();
        links.apply(&GattPush::Subscribed {
            handle: "dev-unsub".to_string(),
        });
        let unsub_link = links.link("dev-unsub").unwrap();
        links.apply(&GattPush::Unsubscribed {
            handle: "dev-unsub".to_string(),
        });
        assert_eq!(unsub_link.pop().await.unwrap(), None);

        links.apply(&GattPush::Unsubscribed {
            handle: "dev-unsub".to_string(),
        });

        links.apply(&GattPush::Subscribed {
            handle: "dev-disc".to_string(),
        });
        let disc_link = links.link("dev-disc").unwrap();
        links.apply(&GattPush::Disconnected {
            handle: "dev-disc".to_string(),
        });
        assert_eq!(disc_link.pop().await.unwrap(), None);

        links.apply(&GattPush::Disconnected {
            handle: "non-existent".to_string(),
        });
    })
    .await;
}

#[tokio::test]
async fn second_end_for_same_handle_changes_nothing() {
    bounded(async {
        let links = GattLinks::new();
        links.apply(&GattPush::Subscribed {
            handle: "dev-twice".to_string(),
        });
        let link = links.link("dev-twice").unwrap();

        links.apply(&GattPush::Disconnected {
            handle: "dev-twice".to_string(),
        });
        assert_eq!(link.pop().await.unwrap(), None);

        links.apply(&GattPush::Disconnected {
            handle: "dev-twice".to_string(),
        });
        links.apply(&GattPush::Unsubscribed {
            handle: "dev-twice".to_string(),
        });
        assert_eq!(link.pop().await.unwrap(), None);
    })
    .await;
}

#[test]
fn link_answers_none_when_unsubscribed_and_same_arc_while_active() {
    let links = GattLinks::new();
    assert!(links.link("unknown").is_none());

    links.apply(&GattPush::Subscribed {
        handle: "active-device".to_string(),
    });
    let arc1 = links.link("active-device").expect("first link lookup");
    let arc2 = links.link("active-device").expect("second link lookup");
    assert!(Arc::ptr_eq(&arc1, &arc2));

    links.apply(&GattPush::Disconnected {
        handle: "active-device".to_string(),
    });
    assert!(links.link("active-device").is_none());
}

#[tokio::test]
async fn gatt_link_source_driven_through_byte_source() {
    bounded(async {
        let link = Arc::new(GattLink::new());
        let mut source = GattLinkSource::new(Arc::clone(&link));

        link.push(vec![1, 2, 3]);
        let first = source.recv_bytes().await.expect("recv first delivery");
        assert_eq!(first, Some(vec![1, 2, 3]));

        link.end();
        let second = source.recv_bytes().await.expect("recv end");
        assert_eq!(second, None);

        let failing_link = Arc::new(GattLink::new());
        let mut failing_source = GattLinkSource::new(Arc::clone(&failing_link));
        failing_link.push(vec![0xEE; GATT_LINK_QUEUE_CAPACITY + 1]);

        let err = failing_source
            .recv_bytes()
            .await
            .expect_err("recv latched failure");
        assert_eq!(err, TransportError::Io(ErrorKind::OutOfMemory));
    })
    .await;
}

#[tokio::test]
async fn zero_length_delivery_is_discarded_and_queued_deliveries_are_bounded() {
    bounded(async {
        let link = GattLink::new();
        link.push(vec![]);
        link.push(vec![0xAA; GATT_LINK_QUEUE_CAPACITY]);
        link.push(vec![]);
        assert_eq!(
            link.pop().await.unwrap(),
            Some(vec![0xAA; GATT_LINK_QUEUE_CAPACITY])
        );
        link.end();
        assert_eq!(link.pop().await.unwrap(), None);

        let empty_link = GattLink::new();
        for _ in 0..=GATT_LINK_QUEUE_CAPACITY {
            empty_link.push(vec![]);
        }
        empty_link.end();
        assert_eq!(empty_link.pop().await.unwrap(), None);
    })
    .await;
}

struct FakeSecureChannel {
    peer_id: DeviceId,
}

impl FakeSecureChannel {
    fn new(peer_id: DeviceId) -> Self {
        Self { peer_id }
    }
}

impl SecureChannel for FakeSecureChannel {
    fn peer(&self) -> DeviceId {
        self.peer_id
    }

    fn transport(&self) -> TransportId {
        TransportId::new("ble-gatt")
    }

    fn rtt(&self) -> std::time::Duration {
        std::time::Duration::from_millis(50)
    }

    fn max_frame_size(&self) -> u32 {
        512
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async { Ok(()) })
    }
}

enum FakeLinkOutcome {
    Success(DeviceId),
    Failure(TransportError),
    Never,
    SignalsStartAndDrop {
        start_notify: Arc<Notify>,
        drop_notify: Arc<Notify>,
    },
}

struct FakeGattAcceptor {
    queue: Mutex<VecDeque<String>>,
    notify: Notify,
    outcomes: Mutex<HashMap<String, FakeLinkOutcome>>,
}

impl FakeGattAcceptor {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            outcomes: Mutex::new(HashMap::new()),
        }
    }

    fn push_link(&self, handle: impl Into<String>, outcome: FakeLinkOutcome) {
        let handle = handle.into();
        self.outcomes
            .lock()
            .unwrap()
            .insert(handle.clone(), outcome);
        self.queue.lock().unwrap().push_back(handle);
        self.notify.notify_one();
    }
}

impl GattAcceptor for FakeGattAcceptor {
    fn next_link(&self) -> BoxFuture<'_, String> {
        Box::pin(async move {
            loop {
                let notified = self.notify.notified();
                if let Some(handle) = self.queue.lock().unwrap().pop_front() {
                    return handle;
                }
                notified.await;
            }
        })
    }

    fn handshake(
        self: Arc<Self>,
        handle: String,
    ) -> BoxFuture<'static, Result<Box<dyn SecureChannel>, TransportError>> {
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .remove(&handle)
            .unwrap_or(FakeLinkOutcome::Never);

        Box::pin(async move {
            match outcome {
                FakeLinkOutcome::Success(id) => {
                    Ok(Box::new(FakeSecureChannel::new(id)) as Box<dyn SecureChannel>)
                }
                FakeLinkOutcome::Failure(err) => Err(err),
                FakeLinkOutcome::Never => {
                    std::future::pending::<Result<Box<dyn SecureChannel>, TransportError>>().await
                }
                FakeLinkOutcome::SignalsStartAndDrop {
                    start_notify,
                    drop_notify,
                } => {
                    struct DropGuard(Arc<Notify>);
                    impl Drop for DropGuard {
                        fn drop(&mut self) {
                            self.0.notify_one();
                        }
                    }
                    let _guard = DropGuard(drop_notify);
                    start_notify.notify_one();
                    std::future::pending::<Result<Box<dyn SecureChannel>, TransportError>>().await
                }
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn failed_handshake_is_discarded_and_later_successful_link_is_accepted() {
    let fake = Arc::new(FakeGattAcceptor::new());
    let bad_link = "link-bad";
    let good_link = "link-good";
    let good_peer = DeviceId::from_identity_digest(&[0x01; 32]);

    fake.push_link(
        bad_link,
        FakeLinkOutcome::Failure(TransportError::AuthenticationFailed),
    );
    fake.push_link(good_link, FakeLinkOutcome::Success(good_peer));

    let mut incoming = GattIncoming::new(fake);
    let channel = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.accept())
        .await
        .expect("accept did not time out")
        .expect("accept succeeds");
    assert_eq!(channel.peer(), good_peer);
}

#[tokio::test(start_paused = true)]
async fn hanging_handshake_does_not_block_later_link_from_being_accepted() {
    let fake = Arc::new(FakeGattAcceptor::new());
    let hanging_link = "link-hanging";
    let fast_link = "link-fast";
    let fast_peer = DeviceId::from_identity_digest(&[0x02; 32]);

    fake.push_link(hanging_link, FakeLinkOutcome::Never);
    fake.push_link(fast_link, FakeLinkOutcome::Success(fast_peer));

    let mut incoming = GattIncoming::new(fake);
    let channel = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.accept())
        .await
        .expect("accept did not time out")
        .expect("fast link accepted");
    assert_eq!(channel.peer(), fast_peer);
}

#[tokio::test(start_paused = true)]
async fn accept_does_not_resolve_while_no_handshake_has_completed() {
    let fake = Arc::new(FakeGattAcceptor::new());
    let mut incoming = GattIncoming::new(fake);

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.accept()).await;
    assert!(
        result.is_err(),
        "accept must not resolve without completed handshake"
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_incoming_aborts_handshake_still_in_flight() {
    let fake = Arc::new(FakeGattAcceptor::new());
    let start_notify = Arc::new(Notify::new());
    let drop_notify = Arc::new(Notify::new());

    fake.push_link(
        "link-in-flight",
        FakeLinkOutcome::SignalsStartAndDrop {
            start_notify: Arc::clone(&start_notify),
            drop_notify: Arc::clone(&drop_notify),
        },
    );

    let started_notified = start_notify.notified();
    let dropped_notified = drop_notify.notified();

    let incoming = GattIncoming::new(fake);

    tokio::time::timeout(std::time::Duration::from_secs(5), started_notified)
        .await
        .expect("handshake task started");

    drop(incoming);

    tokio::time::timeout(std::time::Duration::from_secs(5), dropped_notified)
        .await
        .expect("handshake future dropped on listener drop");
}

#[tokio::test(start_paused = true)]
async fn two_successful_links_are_both_delivered_one_per_accept() {
    let fake = Arc::new(FakeGattAcceptor::new());
    let peer1 = DeviceId::from_identity_digest(&[0x11; 32]);
    let peer2 = DeviceId::from_identity_digest(&[0x22; 32]);

    fake.push_link("link-1", FakeLinkOutcome::Success(peer1));
    fake.push_link("link-2", FakeLinkOutcome::Success(peer2));

    let mut incoming = GattIncoming::new(fake);
    let ch1 = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.accept())
        .await
        .expect("first accept did not time out")
        .expect("first accepted");
    let ch2 = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.accept())
        .await
        .expect("second accept did not time out")
        .expect("second accepted");

    assert_eq!(ch1.peer(), peer1);
    assert_eq!(ch2.peer(), peer2);
}

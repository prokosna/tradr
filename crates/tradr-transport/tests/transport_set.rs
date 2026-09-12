//! Unit tests for TransportSet candidate dispatch (docs/03, DCR-108).

use std::sync::Arc;

use tradr_core::{
    BoxFuture, Candidate, Incoming, PeerExpectation, SecureChannel, Transport, TransportError,
    TransportId,
};
use tradr_transport::set::TransportSet;

const DIRECT_QUIC: TransportId = TransportId::new("direct-quic");
const BLE_GATT: TransportId = TransportId::new("ble-gatt");
const UNKNOWN_TRANSPORT: TransportId = TransportId::new("custom-transport");

struct StubTransport {
    id: TransportId,
    tag: &'static str,
}

impl StubTransport {
    fn new(id: TransportId, tag: &'static str) -> Self {
        Self { id, tag }
    }
}

impl Transport for StubTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn connect<'a>(
        &'a self,
        _candidate: &'a Candidate,
        _expect: &'a PeerExpectation,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        // Tag distinguishes different instances for replacement verification.
        if self.tag == "second" {
            Box::pin(async { Err(TransportError::TimedOut) })
        } else {
            Box::pin(async { Err(TransportError::Unreachable) })
        }
    }

    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async { Err(TransportError::Io(std::io::ErrorKind::Unsupported)) })
    }
}

#[test]
fn dialler_answers_the_member_whose_id_equals_the_candidates_transport() {
    let quic = Arc::new(StubTransport::new(DIRECT_QUIC, "quic"));
    let set = TransportSet::new(vec![quic]);
    let candidate = Candidate::new(DIRECT_QUIC, "127.0.0.1:21820").expect("candidate");
    let dialler = set.dialler(&candidate).expect("dialler found");
    assert_eq!(dialler.id(), DIRECT_QUIC);
}

#[test]
fn dialler_answers_none_for_a_candidate_naming_a_transport_the_set_does_not_hold() {
    let quic = Arc::new(StubTransport::new(DIRECT_QUIC, "quic"));
    let set = TransportSet::new(vec![quic]);
    let candidate = Candidate::new(BLE_GATT, "AA:BB:CC:DD:EE:FF").expect("candidate");
    assert!(set.dialler(&candidate).is_none());
}

#[test]
fn best_candidate_prefers_direct_quic_over_ble_gatt_when_the_set_holds_both() {
    let quic = Arc::new(StubTransport::new(DIRECT_QUIC, "quic"));
    let ble = Arc::new(StubTransport::new(BLE_GATT, "ble"));
    let set = TransportSet::new(vec![quic, ble]);
    let cand_quic = Candidate::new(DIRECT_QUIC, "127.0.0.1:21820").expect("candidate");
    let cand_ble = Candidate::new(BLE_GATT, "AA:BB:CC:DD:EE:FF").expect("candidate");
    let best = set
        .best_candidate(&[cand_ble, cand_quic.clone()])
        .expect("best candidate");
    assert_eq!(best, cand_quic);
}

#[test]
fn best_candidate_answers_the_ble_gatt_candidate_when_the_set_holds_no_direct_quic_transport_even_though_a_direct_quic_candidate_is_present()
 {
    let ble = Arc::new(StubTransport::new(BLE_GATT, "ble"));
    let set = TransportSet::new(vec![ble]);
    let cand_quic = Candidate::new(DIRECT_QUIC, "127.0.0.1:21820").expect("candidate");
    let cand_ble = Candidate::new(BLE_GATT, "AA:BB:CC:DD:EE:FF").expect("candidate");
    let best = set
        .best_candidate(&[cand_quic, cand_ble.clone()])
        .expect("best candidate");
    assert_eq!(best, cand_ble);
}

#[test]
fn best_candidate_answers_none_when_the_set_can_dial_none_of_the_candidates() {
    let quic = Arc::new(StubTransport::new(DIRECT_QUIC, "quic"));
    let set = TransportSet::new(vec![quic]);
    let cand_ble = Candidate::new(BLE_GATT, "AA:BB:CC:DD:EE:FF").expect("candidate");
    assert!(set.best_candidate(&[cand_ble]).is_none());
}

#[test]
fn best_candidate_answers_none_for_an_empty_candidate_list() {
    let quic = Arc::new(StubTransport::new(DIRECT_QUIC, "quic"));
    let set = TransportSet::new(vec![quic]);
    assert!(set.best_candidate(&[]).is_none());
}

#[test]
fn best_candidate_breaks_a_tie_between_two_candidates_of_the_same_transport_by_the_order_they_were_given_in()
 {
    let quic = Arc::new(StubTransport::new(DIRECT_QUIC, "quic"));
    let set = TransportSet::new(vec![quic]);
    let cand1 = Candidate::new(DIRECT_QUIC, "192.168.1.1:21820").expect("candidate 1");
    let cand2 = Candidate::new(DIRECT_QUIC, "192.168.1.2:21820").expect("candidate 2");
    let best1 = set
        .best_candidate(&[cand1.clone(), cand2.clone()])
        .expect("best candidate");
    assert_eq!(best1, cand1);
    let best2 = set
        .best_candidate(&[cand2.clone(), cand1.clone()])
        .expect("best candidate");
    assert_eq!(best2, cand2);
}

#[test]
fn best_candidate_still_picks_a_transport_class_weight_does_not_recognise_when_it_is_the_only_one_the_set_can_dial()
 {
    let custom = Arc::new(StubTransport::new(UNKNOWN_TRANSPORT, "custom"));
    let set = TransportSet::new(vec![custom]);
    let cand_quic = Candidate::new(DIRECT_QUIC, "127.0.0.1:21820").expect("candidate");
    let cand_custom = Candidate::new(UNKNOWN_TRANSPORT, "custom://host").expect("candidate");
    let best = set
        .best_candidate(&[cand_quic, cand_custom.clone()])
        .expect("best candidate");
    assert_eq!(best, cand_custom);
}

#[tokio::test]
async fn a_second_transport_answering_to_an_id_already_in_the_set_replaces_the_first() {
    let t1 = Arc::new(StubTransport::new(DIRECT_QUIC, "first"));
    let t2 = Arc::new(StubTransport::new(DIRECT_QUIC, "second"));
    let set = TransportSet::new(vec![t1, t2]);
    let candidate = Candidate::new(DIRECT_QUIC, "127.0.0.1:21820").expect("candidate");
    let dialler = set.dialler(&candidate).expect("dialler present");
    let err = match dialler
        .connect(&candidate, &PeerExpectation::Unpinned)
        .await
    {
        Ok(_) => panic!("stub transport should reject dial"),
        Err(e) => e,
    };
    assert_eq!(err, TransportError::TimedOut);
}

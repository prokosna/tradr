//! Unit and integration tests for Known Devices and Deferred Deliveries DTOs (docs/13).

use std::sync::Arc;

mod common;

use common::identity;
use tradr_app::brokr::{
    DeliveryStatus, OutboxEntry, OutboxState, SentDeliveries, delivery_dto, delivery_dtos,
    known_device_dtos,
};
use tradr_core::{DeviceId, DisplayName, TrustTier, UnixTime};
use tradr_identity::{KnownDevice, SystemClock};

fn sample_device(
    seed: u8,
    name: Option<&str>,
    tier: TrustTier,
    last_seen_secs: i64,
) -> KnownDevice {
    let id = identity(seed);
    let display_name = name.and_then(|n| DisplayName::new(n).ok());
    KnownDevice::new(
        id.device_id(),
        id,
        display_name,
        tier,
        UnixTime::from_secs(last_seen_secs),
    )
}

#[test]
fn self_device_is_excluded_from_known_device_dtos() {
    let self_dev = sample_device(1, Some("This Laptop"), TrustTier::SameAccount, 100);
    let peer_dev = sample_device(2, Some("Peer Phone"), TrustTier::SameAccount, 200);
    let known = vec![self_dev.clone(), peer_dev.clone()];

    let dtos = known_device_dtos(&known, self_dev.device_id());
    assert_eq!(dtos.len(), 1);
    assert_eq!(dtos[0].device_id, peer_dev.device_id().to_string());
    assert_eq!(dtos[0].display_name, Some("Peer Phone".to_string()));
    assert_eq!(dtos[0].last_seen, 200);
}

#[test]
fn tier_strings_map_same_account_and_linked() {
    let same_acc = sample_device(10, Some("Desktop"), TrustTier::SameAccount, 1000);
    let linked = sample_device(11, Some("Friend Tablet"), TrustTier::Linked, 2000);
    let dummy_self = DeviceId::from_bytes(&[0xff; 16]).expect("valid device id");
    let known = vec![same_acc, linked];

    let dtos = known_device_dtos(&known, dummy_self);
    assert_eq!(dtos.len(), 2);
    assert_eq!(dtos[0].tier, "same-account");
    assert_eq!(dtos[1].tier, "linked");
}

#[test]
fn recipient_name_resolved_or_none_when_unknown() {
    let known_named = sample_device(20, Some("Alice Phone"), TrustTier::SameAccount, 500);
    let known_unnamed = sample_device(21, None, TrustTier::Linked, 600);
    let known = vec![known_named.clone(), known_unnamed.clone()];

    let status_named = DeliveryStatus {
        id: "del-1".to_string(),
        recipient_device_id: known_named.device_id(),
        names: vec!["file1.txt".to_string()],
        sent_at: UnixTime::from_secs(100),
        state: OutboxState::Waiting,
        collected_at: None,
    };
    let dto_named = delivery_dto(&status_named, &known);
    assert_eq!(dto_named.recipient_name, Some("Alice Phone".to_string()));

    let status_unnamed = DeliveryStatus {
        id: "del-2".to_string(),
        recipient_device_id: known_unnamed.device_id(),
        names: vec!["file2.txt".to_string()],
        sent_at: UnixTime::from_secs(110),
        state: OutboxState::Waiting,
        collected_at: None,
    };
    let dto_unnamed = delivery_dto(&status_unnamed, &known);
    assert_eq!(dto_unnamed.recipient_name, None);

    let unknown_id = DeviceId::from_bytes(&[0xee; 16]).expect("valid device id");
    let status_unknown = DeliveryStatus {
        id: "del-3".to_string(),
        recipient_device_id: unknown_id,
        names: vec!["file3.txt".to_string()],
        sent_at: UnixTime::from_secs(120),
        state: OutboxState::Waiting,
        collected_at: None,
    };
    let dto_unknown = delivery_dto(&status_unknown, &known);
    assert_eq!(dto_unknown.recipient_name, None);
}

#[test]
fn three_states_represented_correctly() {
    let target = sample_device(30, Some("Bob Phone"), TrustTier::SameAccount, 300);
    let known = vec![target.clone()];

    let waiting = DeliveryStatus {
        id: "w-1".to_string(),
        recipient_device_id: target.device_id(),
        names: vec!["notes.txt".to_string()],
        sent_at: UnixTime::from_secs(1000),
        state: OutboxState::Waiting,
        collected_at: None,
    };
    let delivered = DeliveryStatus {
        id: "d-1".to_string(),
        recipient_device_id: target.device_id(),
        names: vec!["photos.zip".to_string()],
        sent_at: UnixTime::from_secs(2000),
        state: OutboxState::Delivered,
        collected_at: Some(2_500_000),
    };
    let expired = DeliveryStatus {
        id: "e-1".to_string(),
        recipient_device_id: target.device_id(),
        names: vec!["archive.tar".to_string()],
        sent_at: UnixTime::from_secs(3000),
        state: OutboxState::Expired,
        collected_at: None,
    };

    let dtos = delivery_dtos(&[waiting, delivered, expired], &known);
    assert_eq!(dtos.len(), 3);

    assert_eq!(dtos[0].id, "w-1");
    assert_eq!(dtos[0].state, "waiting");
    assert_eq!(dtos[0].collected_at, None);

    assert_eq!(dtos[1].id, "d-1");
    assert_eq!(dtos[1].state, "delivered");
    assert_eq!(dtos[1].collected_at, Some(2_500_000));

    assert_eq!(dtos[2].id, "e-1");
    assert_eq!(dtos[2].state, "expired");
    assert_eq!(dtos[2].collected_at, None);
}

#[test]
fn delivery_dtos_from_sent_deliveries_merge() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut journal = SentDeliveries::load_with_clock(temp_dir.path(), Arc::new(SystemClock))
        .expect("load journal");

    let recipient = sample_device(40, Some("Carol Workstation"), TrustTier::Linked, 5000);
    let known = vec![recipient.clone()];

    journal
        .record(
            "del-100",
            recipient.device_id(),
            vec!["doc.pdf".to_string()],
            UnixTime::from_secs(100),
        )
        .expect("record delivery");

    let outbox_entries = vec![OutboxEntry {
        id: "del-100".to_string(),
        recipient_device_id: recipient.device_id().to_string(),
        size: 2048,
        uploaded_at: 100_000,
        state: OutboxState::Delivered,
        collected_at: Some(150_000),
    }];

    let statuses = journal.merge_with(&outbox_entries);
    let dtos = delivery_dtos(&statuses, &known);

    assert_eq!(dtos.len(), 1);
    assert_eq!(dtos[0].id, "del-100");
    assert_eq!(
        dtos[0].recipient_name,
        Some("Carol Workstation".to_string())
    );
    assert_eq!(dtos[0].state, "delivered");
    assert_eq!(dtos[0].collected_at, Some(150_000));
}

//! Tests for the received history recording and known name resolution (docs/12, DCR-184).

use std::time::Instant;

use tauri_plugin_tradr::received::{known_name, record_received};
use tradr_app::received_history::{ReceivedHistory, ReceivedHow};
use tradr_core::{
    Clock, DeviceId, DisplayName, Monotonic, PublicIdentity, PublicKeyPoint, RelPath, TrustTier,
    UnixTime,
};
use tradr_identity::KnownDevice;

struct FixedClock {
    wall: UnixTime,
}

impl Clock for FixedClock {
    fn now(&self) -> UnixTime {
        self.wall
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(Instant::now())
    }
}

fn sample_device(id_byte: u8, name: Option<&str>) -> KnownDevice {
    let device_id = DeviceId::from_bytes(&[id_byte; 16]).expect("16 bytes is valid device id");
    let point =
        PublicKeyPoint::from_bytes(&[id_byte; 65]).expect("65 bytes is valid public key point");
    let identity = PublicIdentity::new(point.clone(), point, device_id);
    let display_name = name.and_then(|n| DisplayName::new(n).ok());
    KnownDevice::new(
        device_id,
        identity,
        display_name,
        TrustTier::SameAccount,
        UnixTime::from_secs(100),
    )
}

#[test]
fn record_received_with_two_paths_writes_rows_in_order_newest_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(dir.path());
    let clock = FixedClock {
        wall: UnixTime::from_secs(1_700_000_000),
    };
    let peer = DeviceId::from_bytes(&[0x11; 16]).expect("valid device id");
    let paths = [
        RelPath::new("first.txt").expect("valid rel path"),
        RelPath::new("second.txt").expect("valid rel path"),
    ];

    record_received(
        &history,
        Some("Peer Laptop".to_string()),
        &clock,
        peer,
        &paths,
        ReceivedHow::Sent,
    )
    .expect("record received");

    let rows = history.rows().expect("read rows");
    assert_eq!(rows.len(), 2);

    assert_eq!(rows[0].path, "second.txt");
    assert_eq!(rows[0].device_id, peer.to_string());
    assert_eq!(rows[0].device_name, Some("Peer Laptop".to_string()));
    assert_eq!(rows[0].received_at, 1_700_000_000);
    assert_eq!(rows[0].how, ReceivedHow::Sent);

    assert_eq!(rows[1].path, "first.txt");
    assert_eq!(rows[1].device_id, peer.to_string());
    assert_eq!(rows[1].device_name, Some("Peer Laptop".to_string()));
    assert_eq!(rows[1].received_at, 1_700_000_000);
    assert_eq!(rows[1].how, ReceivedHow::Sent);
}

#[test]
fn record_received_with_downloaded_and_no_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(dir.path());
    let clock = FixedClock {
        wall: UnixTime::from_secs(1_700_000_500),
    };
    let peer = DeviceId::from_bytes(&[0x22; 16]).expect("valid device id");
    let paths = [RelPath::new("downloaded.png").expect("valid rel path")];

    record_received(
        &history,
        None,
        &clock,
        peer,
        &paths,
        ReceivedHow::Downloaded,
    )
    .expect("record received");

    let rows = history.rows().expect("read rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, "downloaded.png");
    assert_eq!(rows[0].device_id, peer.to_string());
    assert_eq!(rows[0].device_name, None);
    assert_eq!(rows[0].received_at, 1_700_000_500);
    assert_eq!(rows[0].how, ReceivedHow::Downloaded);
}

#[test]
fn record_received_with_empty_paths_records_nothing_and_creates_no_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(dir.path());
    let clock = FixedClock {
        wall: UnixTime::from_secs(1_700_000_000),
    };
    let peer = DeviceId::from_bytes(&[0x33; 16]).expect("valid device id");

    record_received(
        &history,
        Some("Name".to_string()),
        &clock,
        peer,
        &[],
        ReceivedHow::Sent,
    )
    .expect("record received");

    assert!(!dir.path().join("received.json").exists());
    let rows = history.rows().expect("read rows");
    assert!(rows.is_empty());
}

#[test]
fn record_received_over_unreadable_file_returns_error_and_preserves_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("received.json");
    let bad_bytes = b"not valid json content";
    std::fs::write(&file_path, bad_bytes).expect("write bad file");

    let history = ReceivedHistory::new(dir.path());
    let clock = FixedClock {
        wall: UnixTime::from_secs(1_700_000_000),
    };
    let peer = DeviceId::from_bytes(&[0x44; 16]).expect("valid device id");
    let paths = [RelPath::new("file.txt").expect("valid rel path")];

    let result = record_received(&history, None, &clock, peer, &paths, ReceivedHow::Sent);

    assert!(result.is_err());
    let bytes_after = std::fs::read(&file_path).expect("read file");
    assert_eq!(bytes_after, bad_bytes);
}

#[test]
fn known_name_resolves_name_or_none() {
    let dev1 = sample_device(0x10, Some("Desktop Workstation"));
    let dev2 = sample_device(0x20, None);
    let unknown_peer = DeviceId::from_bytes(&[0x30; 16]).expect("valid device id");

    let known = vec![dev1.clone(), dev2.clone()];

    assert_eq!(
        known_name(&known, &dev1.device_id()),
        Some("Desktop Workstation".to_string())
    );
    assert_eq!(known_name(&known, &dev2.device_id()), None);
    assert_eq!(known_name(&known, &unknown_peer), None);
}

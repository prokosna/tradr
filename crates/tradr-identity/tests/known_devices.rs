use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tradr_core::{
    DeviceId, DisplayName, PUBLIC_KEY_POINT_LEN, PublicIdentity, PublicKeyPoint, TrustTier,
    UnixTime,
};
use tradr_identity::{KnownDevice, KnownDevices, KnownDevicesError, RecordOutcome};

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tradr-known-devices-test-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.path.exists() {
            let res = std::fs::remove_dir_all(&self.path);
            if let Err(e) = res {
                eprintln!(
                    "failed to clean up test directory {}: {e}",
                    self.path.display()
                );
            }
        }
    }
}

fn point(byte: u8) -> PublicKeyPoint {
    let mut bytes = [0x04u8; PUBLIC_KEY_POINT_LEN];
    for (i, b) in bytes.iter_mut().enumerate().skip(1) {
        *b = byte.wrapping_add(i as u8);
    }
    PublicKeyPoint::from_bytes(&bytes).expect("valid point bytes")
}

fn sample_device(byte: u8, tier: TrustTier, last_seen_secs: i64) -> KnownDevice {
    let id_pub = point(byte);
    let agree_pub = point(byte.wrapping_add(50));
    let digest = blake3::hash(id_pub.as_bytes());
    let device_id = DeviceId::from_identity_digest(digest.as_bytes());
    let identity = PublicIdentity::new(id_pub, agree_pub, device_id);
    let display_name =
        Some(DisplayName::new(&format!("device-{byte}")).expect("valid display name"));
    let last_seen = UnixTime::from_secs(last_seen_secs);
    KnownDevice::new(device_id, identity, display_name, tier, last_seen)
}

#[test]
fn missing_file_loads_empty() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");

    let registry = KnownDevices::load(&file_path).expect("missing file loads empty");

    assert!(registry.all().is_empty());
    let dummy_id = DeviceId::from_bytes(&[0xaa; 16]).expect("device id from bytes");
    assert!(registry.get(&dummy_id).is_none());
    assert!(!file_path.exists());
}

#[test]
fn record_then_reload_round_trips_every_field() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    let dev1 = sample_device(0x10, TrustTier::SameAccount, 1_800_000_100);
    let outcome1 = registry.record(dev1.clone()).expect("record dev1");
    assert_eq!(outcome1, RecordOutcome::New);

    let id_pub2 = point(0x20);
    let agree_pub2 = point(0x30);
    let digest2 = blake3::hash(id_pub2.as_bytes());
    let id2 = DeviceId::from_identity_digest(digest2.as_bytes());
    let identity2 = PublicIdentity::new(id_pub2, agree_pub2, id2);
    let dev2 = KnownDevice::new(
        id2,
        identity2,
        None,
        TrustTier::Linked,
        UnixTime::from_secs(1_800_000_200),
    );
    let outcome2 = registry.record(dev2.clone()).expect("record dev2");
    assert_eq!(outcome2, RecordOutcome::New);

    let reloaded = KnownDevices::load(&file_path).expect("reload from disk");
    assert_eq!(reloaded.all().len(), 2);

    let fetched1 = reloaded.get(&dev1.device_id()).expect("dev1 present");
    assert_eq!(fetched1.device_id(), dev1.device_id());
    assert_eq!(fetched1.identity(), dev1.identity());
    assert_eq!(fetched1.display_name(), dev1.display_name());
    assert_eq!(fetched1.tier(), dev1.tier());
    assert_eq!(fetched1.last_seen(), dev1.last_seen());
    assert_eq!(fetched1, &dev1);

    let fetched2 = reloaded.get(&dev2.device_id()).expect("dev2 present");
    assert_eq!(fetched2.device_id(), dev2.device_id());
    assert_eq!(fetched2.identity(), dev2.identity());
    assert_eq!(fetched2.display_name(), None);
    assert_eq!(fetched2.tier(), TrustTier::Linked);
    assert_eq!(fetched2.last_seen(), dev2.last_seen());
    assert_eq!(fetched2, &dev2);
}

#[test]
fn all_sorted_by_last_seen_newest_first() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    let dev_old = sample_device(0x10, TrustTier::SameAccount, 100);
    let dev_newest = sample_device(0x20, TrustTier::SameAccount, 300);
    let dev_middle = sample_device(0x30, TrustTier::SameAccount, 200);

    registry.record(dev_old.clone()).expect("record old");
    registry.record(dev_newest.clone()).expect("record newest");
    registry.record(dev_middle.clone()).expect("record middle");

    let in_memory = registry.all();
    assert_eq!(in_memory.len(), 3);
    assert_eq!(in_memory[0].last_seen().as_secs(), 300);
    assert_eq!(in_memory[0].device_id(), dev_newest.device_id());
    assert_eq!(in_memory[1].last_seen().as_secs(), 200);
    assert_eq!(in_memory[1].device_id(), dev_middle.device_id());
    assert_eq!(in_memory[2].last_seen().as_secs(), 100);
    assert_eq!(in_memory[2].device_id(), dev_old.device_id());

    let reloaded = KnownDevices::load(&file_path).expect("reload");
    let on_disk = reloaded.all();
    assert_eq!(on_disk.len(), 3);
    assert_eq!(on_disk[0].last_seen().as_secs(), 300);
    assert_eq!(on_disk[1].last_seen().as_secs(), 200);
    assert_eq!(on_disk[2].last_seen().as_secs(), 100);

    let updated_dev_old = KnownDevice::new(
        dev_old.device_id(),
        dev_old.identity().clone(),
        dev_old.display_name().cloned(),
        dev_old.tier(),
        UnixTime::from_secs(400),
    );
    registry
        .record(updated_dev_old)
        .expect("record updated dev_old");
    assert_eq!(registry.all()[0].device_id(), dev_old.device_id());
    assert_eq!(registry.all()[0].last_seen().as_secs(), 400);
}

#[test]
fn record_outcome_new_refreshed_keys_changed() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load");

    let dev = sample_device(0x10, TrustTier::SameAccount, 100);
    let outcome1 = registry.record(dev.clone()).expect("new record");
    assert_eq!(outcome1, RecordOutcome::New);

    let refreshed = KnownDevice::new(
        dev.device_id(),
        dev.identity().clone(),
        Some(DisplayName::new("Updated Name").expect("valid name")),
        dev.tier(),
        UnixTime::from_secs(150),
    );
    let outcome2 = registry.record(refreshed).expect("refreshed record");
    assert_eq!(outcome2, RecordOutcome::Refreshed);

    let new_agree_pub = point(0x99);
    let identity_agree_changed = PublicIdentity::new(
        dev.identity().identity_pub().clone(),
        new_agree_pub,
        dev.device_id(),
    );
    let dev_agree_changed = KnownDevice::new(
        dev.device_id(),
        identity_agree_changed,
        dev.display_name().cloned(),
        dev.tier(),
        UnixTime::from_secs(200),
    );
    let outcome3 = registry
        .record(dev_agree_changed)
        .expect("keys changed record");
    assert_eq!(outcome3, RecordOutcome::KeysChanged);

    let new_id_pub = point(0x88);
    let identity_id_changed = PublicIdentity::new(new_id_pub, point(0x99), dev.device_id());
    let dev_id_changed = KnownDevice::new(
        dev.device_id(),
        identity_id_changed,
        dev.display_name().cloned(),
        dev.tier(),
        UnixTime::from_secs(250),
    );
    let outcome4 = registry
        .record(dev_id_changed)
        .expect("keys changed record");
    assert_eq!(outcome4, RecordOutcome::KeysChanged);
}

#[test]
fn nearby_ephemeral_refused_with_file_untouched() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load");

    let dev1 = sample_device(0x10, TrustTier::SameAccount, 100);
    registry.record(dev1.clone()).expect("initial record");
    let before_bytes = std::fs::read(&file_path).expect("read before");

    let ephemeral_dev = sample_device(0x20, TrustTier::NearbyEphemeral, 200);
    let outcome = registry.record(ephemeral_dev);
    assert!(matches!(
        outcome,
        Err(KnownDevicesError::InvalidTier(TrustTier::NearbyEphemeral))
    ));

    let after_bytes = std::fs::read(&file_path).expect("read after");
    assert_eq!(before_bytes, after_bytes);
    assert_eq!(registry.all(), std::slice::from_ref(&dev1));

    let rejected_dev = sample_device(0x30, TrustTier::Rejected, 300);
    let outcome2 = registry.record(rejected_dev);
    assert!(matches!(
        outcome2,
        Err(KnownDevicesError::InvalidTier(TrustTier::Rejected))
    ));

    let after_bytes2 = std::fs::read(&file_path).expect("read after rejected");
    assert_eq!(before_bytes, after_bytes2);
    assert_eq!(registry.all(), &[dev1]);
}

#[test]
fn mismatched_device_id_in_file_refused_by_load() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");

    let id_pub = point(0x10);
    let agree_pub = point(0x20);
    let wrong_id_hex = "00112233445566778899aabbccddeeff";
    let id_hex: String = id_pub
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let agree_hex: String = agree_pub
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let json = format!(
        r#"{{"version":1,"devices":[{{"device_id":"{wrong_id_hex}","identity_pub":"{id_hex}","agreement_pub":"{agree_hex}","display_name":"tampered","tier":"same-account","last_seen":100}}]}}"#
    );
    std::fs::write(&file_path, json).expect("write tampered file");

    let result = KnownDevices::load(&file_path);
    assert!(matches!(
        result,
        Err(KnownDevicesError::MismatchedDeviceId { .. })
    ));
}

#[test]
fn unknown_version_in_file_refused_by_load() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");

    let json = r#"{"version":2,"devices":[]}"#;
    std::fs::write(&file_path, json).expect("write version 2 file");

    let result = KnownDevices::load(&file_path);
    assert!(matches!(result, Err(KnownDevicesError::UnknownVersion(2))));
}

#[test]
fn malformed_key_in_file_refused_by_load() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");

    let json = r#"{"version":1,"devices":[{"device_id":"00112233445566778899aabbccddeeff","identity_pub":"bad-hex","agreement_pub":"bad-hex","display_name":null,"tier":"same-account","last_seen":100}]}"#;
    std::fs::write(&file_path, json).expect("write malformed file");

    let result = KnownDevices::load(&file_path);
    assert!(matches!(result, Err(KnownDevicesError::Malformed(_))));
}

#[test]
fn duplicate_device_id_in_file_refused_by_load() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");

    let id_pub = point(0x10);
    let agree_pub = point(0x20);
    let digest = blake3::hash(id_pub.as_bytes());
    let id = DeviceId::from_identity_digest(digest.as_bytes());
    let id_hex: String = id_pub
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let agree_hex: String = agree_pub
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let json = format!(
        r#"{{"version":1,"devices":[
            {{"device_id":"{id}","identity_pub":"{id_hex}","agreement_pub":"{agree_hex}","display_name":"d1","tier":"same-account","last_seen":100}},
            {{"device_id":"{id}","identity_pub":"{id_hex}","agreement_pub":"{agree_hex}","display_name":"d2","tier":"same-account","last_seen":200}}
        ]}}"#
    );
    std::fs::write(&file_path, json).expect("write duplicate file");

    let result = KnownDevices::load(&file_path);
    assert!(matches!(result, Err(KnownDevicesError::Malformed(_))));
}

#[cfg(unix)]
#[test]
fn failed_persist_due_to_read_only_dir_leaves_no_temp_file_and_leaves_previous_file_intact() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    let dev1 = sample_device(0x10, TrustTier::SameAccount, 100);
    registry.record(dev1.clone()).expect("dev1 recorded");
    let original_bytes = std::fs::read(&file_path).expect("read original");

    let original_perms = std::fs::metadata(test_dir.path())
        .expect("metadata")
        .permissions();
    std::fs::set_permissions(test_dir.path(), std::fs::Permissions::from_mode(0o500))
        .expect("chmod 500");

    let dev2 = sample_device(0x20, TrustTier::SameAccount, 200);
    let outcome = registry.record(dev2);
    assert!(outcome.is_err());

    std::fs::set_permissions(test_dir.path(), original_perms).expect("restore perms");

    for entry in std::fs::read_dir(test_dir.path()).expect("read_dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".tmp-"),
            "found orphaned temp file: {name}"
        );
    }

    let current_bytes = std::fs::read(&file_path).expect("read after fail");
    assert_eq!(original_bytes, current_bytes);

    let reloaded = KnownDevices::load(&file_path).expect("reload");
    assert_eq!(reloaded.all(), &[dev1]);
}

#[test]
fn failed_persist_due_to_dir_target_cleans_up_temp_file() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("blocked_dir");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    std::fs::create_dir(&file_path).expect("create blocked dir");
    let canary = file_path.join("canary.txt");
    std::fs::write(&canary, b"canary content").expect("write canary");

    let dev = sample_device(0x10, TrustTier::SameAccount, 100);
    let outcome = registry.record(dev);
    assert!(outcome.is_err());

    for entry in std::fs::read_dir(test_dir.path()).expect("read_dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".tmp-"),
            "found orphaned temp file in test dir: {name}"
        );
    }

    assert_eq!(
        std::fs::read(&canary).expect("read canary"),
        b"canary content"
    );
}

#[test]
fn set_display_name_updates_and_persists_existing_entry() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    let dev = sample_device(0x10, TrustTier::SameAccount, 100);
    let dev_id = dev.device_id();
    registry.record(dev).expect("record device");

    let new_name = DisplayName::new("renamed-laptop").expect("valid display name");
    let changed = registry
        .set_display_name(&dev_id, Some(new_name.clone()))
        .expect("set display name succeeds");
    assert!(changed);
    assert_eq!(
        registry.get(&dev_id).expect("get").display_name(),
        Some(&new_name)
    );

    let reloaded = KnownDevices::load(&file_path).expect("reload");
    assert_eq!(
        reloaded.get(&dev_id).expect("get reloaded").display_name(),
        Some(&new_name)
    );

    let cleared = registry
        .set_display_name(&dev_id, None)
        .expect("clear display name succeeds");
    assert!(cleared);
    assert_eq!(registry.get(&dev_id).expect("get").display_name(), None);

    let reloaded_cleared = KnownDevices::load(&file_path).expect("reload after clear");
    assert_eq!(
        reloaded_cleared
            .get(&dev_id)
            .expect("get reloaded cleared")
            .display_name(),
        None
    );
}

#[test]
fn set_display_name_noop_when_name_unchanged() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    let dev = sample_device(0x10, TrustTier::SameAccount, 100);
    let dev_id = dev.device_id();
    let original_name = dev.display_name().cloned();
    registry.record(dev).expect("record device");

    let disk_bytes_before = std::fs::read(&file_path).expect("read file");
    let changed = registry
        .set_display_name(&dev_id, original_name)
        .expect("set same display name succeeds");
    assert!(!changed);

    let disk_bytes_after = std::fs::read(&file_path).expect("read file");
    assert_eq!(disk_bytes_before, disk_bytes_after);
}

#[test]
fn set_display_name_unknown_device_returns_ok_false_and_writes_nothing() {
    let test_dir = TestDir::new();
    let file_path = test_dir.path().join("known-devices.json");
    let mut registry = KnownDevices::load(&file_path).expect("load empty");

    let unknown_id = DeviceId::from_identity_digest(&[0x99; 32]);
    let name = Some(DisplayName::new("unknown-device").expect("valid display name"));

    let changed = registry
        .set_display_name(&unknown_id, name)
        .expect("set display name for unknown device succeeds");
    assert!(!changed);
    assert!(!file_path.exists());
}

//! Supervisor-authored tests for DCR-124's move of the Device Key open
//! into the shell-free crate. Critical Module, CLAUDE.md section 6: the
//! rung a key is opened on decides which key a device has, and a device
//! that opens the wrong rung mints a second Device Key while failing no
//! build, no test and no handshake. Written before the implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tradr_app::identity::{
    DEVICE_KEY_SLOT, describe_backing, open_device_identity, storage_level_name,
};
use tradr_core::{Backing, SecretStore, SecretStoreError, SoftwareReason, StorageLevel};
use tradr_identity::OsRng;

/// A rung answering from memory, so a test can assert what a rung was
/// never asked to hold as well as what it holds.
struct Rung {
    level: StorageLevel,
    slots: Mutex<HashMap<String, Vec<u8>>>,
    fails: bool,
    loads: AtomicUsize,
}

impl Rung {
    fn empty(level: StorageLevel) -> Arc<Self> {
        Arc::new(Self {
            level,
            slots: Mutex::new(HashMap::new()),
            fails: false,
            loads: AtomicUsize::new(0),
        })
    }

    fn failing(level: StorageLevel) -> Arc<Self> {
        Arc::new(Self {
            level,
            slots: Mutex::new(HashMap::new()),
            fails: true,
            loads: AtomicUsize::new(0),
        })
    }

    fn held(&self, slot: &str) -> Option<Vec<u8>> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(slot)
            .cloned()
    }

    fn loads(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }
}

impl SecretStore for Rung {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        if self.fails {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the rung was reachable and did not answer",
            ))));
        }
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(slot.to_owned(), secret.to_vec());
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if self.fails {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the rung was reachable and did not answer",
            ))));
        }
        Ok(self.held(slot))
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        self.level
    }
}

fn ladder(rungs: &[&Arc<Rung>]) -> Vec<Arc<dyn SecretStore + Send + Sync>> {
    rungs
        .iter()
        .map(|r| Arc::clone(r) as Arc<dyn SecretStore + Send + Sync>)
        .collect()
}

#[test]
fn an_empty_ladder_generates_the_key_on_the_highest_rung() {
    let high = Rung::empty(StorageLevel::SecretService);
    let low = Rung::empty(StorageLevel::File);

    let identity = open_device_identity(&ladder(&[&high, &low]), &OsRng)
        .expect("an empty ladder of two reachable rungs opens");

    assert!(high.held(DEVICE_KEY_SLOT).is_some());
    assert!(low.held(DEVICE_KEY_SLOT).is_none());
    assert_eq!(identity.storage_level(), StorageLevel::SecretService);
}

#[test]
fn the_key_is_opened_on_the_rung_already_holding_it() {
    let low = Rung::empty(StorageLevel::File);
    let seeded = open_device_identity(&ladder(&[&low]), &OsRng).expect("a one-rung ladder opens");
    let seeded_id = seeded.public_identity().device_id().to_string();

    let high = Rung::empty(StorageLevel::SecretService);
    let identity = open_device_identity(&ladder(&[&high, &low]), &OsRng)
        .expect("a ladder whose lower rung holds the key opens");

    assert_eq!(
        identity.public_identity().device_id().to_string(),
        seeded_id
    );
    assert_eq!(identity.storage_level(), StorageLevel::File);
    // The search descended rather than writing a second key above the one
    // it found, which is what "one rung per device" means in one line.
    assert!(high.held(DEVICE_KEY_SLOT).is_none());
}

#[test]
fn the_secret_store_handed_back_is_the_rung_the_key_was_found_on() {
    let low = Rung::empty(StorageLevel::File);
    open_device_identity(&ladder(&[&low]), &OsRng).expect("a one-rung ladder opens");
    let high = Rung::empty(StorageLevel::SecretService);

    let identity = open_device_identity(&ladder(&[&high, &low]), &OsRng)
        .expect("a ladder whose lower rung holds the key opens");
    identity
        .secret_store()
        .store("link-secret", b"a secret written beside the Device Key")
        .expect("the returned rung accepts a write");

    assert_eq!(
        low.held("link-secret").as_deref(),
        Some(b"a secret written beside the Device Key".as_slice())
    );
    assert!(high.held("link-secret").is_none());
}

#[test]
fn a_rung_that_cannot_be_read_stops_the_search_rather_than_minting_a_key() {
    let high = Rung::failing(StorageLevel::SecretService);
    let low = Rung::empty(StorageLevel::File);

    let outcome = open_device_identity(&ladder(&[&high, &low]), &OsRng);

    let message = match outcome {
        Ok(_) => panic!("a rung that cannot be read must not be read as empty"),
        Err(e) => e,
    };
    assert!(
        message.contains("Secret Service"),
        "the failure names the rung that failed: {message}"
    );
    assert!(low.held(DEVICE_KEY_SLOT).is_none());
    // Reading past the failure is the mutation this counts: the lower rung
    // is never consulted once a rung above it has failed to answer.
    assert_eq!(low.loads(), 0);
}

#[test]
fn backing_names_the_rung_the_key_was_opened_on() {
    let high = Rung::empty(StorageLevel::SecretService);
    let on_secret_service =
        open_device_identity(&ladder(&[&high]), &OsRng).expect("the ladder opens");
    assert_eq!(
        on_secret_service.backing(),
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    );

    let low = Rung::empty(StorageLevel::File);
    let on_file = open_device_identity(&ladder(&[&low]), &OsRng).expect("the ladder opens");
    assert_eq!(
        on_file.backing(),
        Backing::Software(SoftwareReason::NoSecretService)
    );
}

#[test]
fn a_software_backing_is_described_with_the_reason_it_carries() {
    let low = Rung::empty(StorageLevel::File);
    let identity = open_device_identity(&ladder(&[&low]), &OsRng).expect("the ladder opens");

    let (backing, reason) = describe_backing(identity.backing());

    assert_eq!(backing, "software");
    assert_eq!(
        reason.as_deref(),
        Some("no Secret Service session available")
    );
}

#[test]
fn hardware_backing_is_described_without_a_reason() {
    let (backing, reason) = describe_backing(Backing::Hardware);

    assert_eq!(backing, "hardware");
    assert_eq!(reason, None);
}

#[test]
fn an_empty_ladder_is_refused() {
    let outcome = open_device_identity(&[], &OsRng);

    assert!(outcome.is_err(), "a ladder with no rungs opens nothing");
}

#[test]
fn reopening_a_ladder_answers_with_the_same_device_id() {
    let low = Rung::empty(StorageLevel::File);

    let first = open_device_identity(&ladder(&[&low]), &OsRng).expect("the ladder opens");
    let second = open_device_identity(&ladder(&[&low]), &OsRng).expect("the ladder reopens");

    assert_eq!(
        first.public_identity().device_id().to_string(),
        second.public_identity().device_id().to_string()
    );
}

#[test]
fn each_rung_of_the_ladder_has_its_own_name() {
    assert_eq!(
        storage_level_name(StorageLevel::SecretService),
        "secret service"
    );
    assert_eq!(storage_level_name(StorageLevel::File), "file");
}

//! Supervisor-authored tests for WI-M0-007b. CLAUDE.md section 6 names
//! two failures this guards: a `backing()` that overstates itself makes
//! docs/05's hardware promise false while failing nowhere, and a device
//! that silently replaces a key it could not read loses its identity and
//! every link to it, presenting as a brand new device.

use std::cell::RefCell;

use tradr_core::{
    Backing, KeyStore, Rng, RngError, SecretStore, SecretStoreError, SoftwareReason, StorageLevel,
};
use tradr_identity::SoftwareKeyStore;

const SLOT: &str = "device-key";

/// A store that keeps one value in memory and counts what was done to it.
struct FakeStore {
    level: StorageLevel,
    held: RefCell<Option<Vec<u8>>>,
    stores: RefCell<u32>,
    fail_load: bool,
    fail_store: bool,
}

impl FakeStore {
    fn empty(level: StorageLevel) -> Self {
        Self {
            level,
            held: RefCell::new(None),
            stores: RefCell::new(0),
            fail_load: false,
            fail_store: false,
        }
    }

    fn holding(level: StorageLevel, value: Vec<u8>) -> Self {
        let store = Self::empty(level);
        *store.held.borrow_mut() = Some(value);
        store
    }

    // Fails only on load, and holds a value. The dangerous mutation is
    // treating an unreadable store as an empty one: that generates a key
    // and writes it over whatever was there, which a store failing on
    // both operations would hide behind the second failure.
    fn failing_to_load() -> Self {
        Self {
            fail_load: true,
            held: RefCell::new(Some(b"something was here".to_vec())),
            ..Self::empty(StorageLevel::File)
        }
    }
}

impl SecretStore for FakeStore {
    fn store(&self, _slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        if self.fail_store {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "no store",
            ))));
        }
        *self.stores.borrow_mut() += 1;
        *self.held.borrow_mut() = Some(secret.to_vec());
        Ok(())
    }

    fn load(&self, _slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        if self.fail_load {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "no store",
            ))));
        }
        Ok(self.held.borrow().clone())
    }

    fn level(&self) -> StorageLevel {
        self.level
    }
}

/// Each draw differs from the last. A source filling every buffer with
/// one byte would make a device's identity and agreement keys the same
/// scalar, and nothing that swapped the two would ever be noticed.
struct CountingRng(std::cell::Cell<u8>);

impl CountingRng {
    fn from(seed: u8) -> Self {
        Self(std::cell::Cell::new(seed))
    }
}

impl Rng for CountingRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(self.0.get());
        self.0.set(self.0.get().wrapping_add(1));
        Ok(())
    }
}

fn open(store: &FakeStore, seed: u8) -> Result<SoftwareKeyStore, tradr_core::KeyStoreError> {
    SoftwareKeyStore::open(store, SLOT, &CountingRng::from(seed))
}

// --- An identity that survives a restart ---

#[test]
fn the_first_open_generates_a_key_and_writes_it_once() {
    let store = FakeStore::empty(StorageLevel::SecretService);

    open(&store, 7).expect("a fresh device generates a key");

    assert_eq!(*store.stores.borrow(), 1);
    assert!(store.held.borrow().is_some());
}

#[test]
fn a_second_open_returns_the_same_identity_and_writes_nothing() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    let first = open(&store, 7).expect("first open");
    let before = *store.stores.borrow();

    let second = open(&store, 200).expect("second open");

    assert_eq!(
        first.public_identity().expect("first identity"),
        second.public_identity().expect("second identity")
    );
    assert_eq!(*store.stores.borrow(), before);
}

// The seed differs between the two opens above on purpose. If the second
// open regenerated instead of loading, the identity would differ and
// nothing else in the suite would notice.
#[test]
fn a_different_rng_does_not_change_a_key_that_was_already_stored() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    let stored = open(&store, 7).expect("first open");

    let reopened = open(&store, 99).expect("second open");

    assert_eq!(
        stored.public_identity().expect("stored"),
        reopened.public_identity().expect("reopened")
    );
}

// --- A key that cannot be read is never quietly replaced ---

#[test]
fn a_stored_value_that_does_not_parse_is_an_error_and_not_a_new_key() {
    let store = FakeStore::holding(StorageLevel::SecretService, b"not a key".to_vec());

    assert!(open(&store, 7).is_err());
    assert_eq!(*store.stores.borrow(), 0);
    assert_eq!(store.held.borrow().as_deref(), Some(&b"not a key"[..]));
}

#[test]
fn a_stored_value_of_an_unknown_version_is_an_error() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    open(&store, 7).expect("write one");
    let mut tampered = store.held.borrow().clone().expect("a stored value");
    tampered[0] = tampered[0].wrapping_add(1);
    let reopened = FakeStore::holding(StorageLevel::SecretService, tampered);

    assert!(open(&reopened, 7).is_err());
    assert_eq!(*reopened.stores.borrow(), 0);
}

#[test]
fn a_truncated_stored_value_is_an_error() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    open(&store, 7).expect("write one");
    let short = store.held.borrow().clone().expect("a stored value")[..8].to_vec();
    let reopened = FakeStore::holding(StorageLevel::SecretService, short);

    assert!(open(&reopened, 7).is_err());
}

#[test]
fn a_store_that_cannot_be_read_is_an_error_and_never_overwritten() {
    let store = FakeStore::failing_to_load();

    assert!(open(&store, 7).is_err());

    assert_eq!(*store.stores.borrow(), 0);
    assert_eq!(
        store.held.borrow().as_deref(),
        Some(&b"something was here"[..])
    );
}

// --- What backing() is allowed to say ---

// Linux has no secure element. Storing a key in a keyring makes it
// durable, not protected: the material comes back into this process to
// be used, which is the whole difference from StrongBox or a TPM.
#[test]
fn no_linux_storage_level_ever_reports_hardware() {
    for level in [
        StorageLevel::SecretService,
        StorageLevel::KernelKeyring,
        StorageLevel::File,
    ] {
        let store = FakeStore::empty(level);
        let keys = open(&store, 7).expect("open");

        assert_ne!(
            keys.backing(),
            Backing::Hardware,
            "{level:?} claimed hardware"
        );
    }
}

#[test]
fn reaching_the_secret_service_is_reported_as_the_platform_having_no_secure_element() {
    let store = FakeStore::empty(StorageLevel::SecretService);

    assert_eq!(
        open(&store, 7).expect("open").backing(),
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    );
}

// Falling past the Secret Service is a different sentence in Settings
// from reaching it, and docs/05 requires a headless box to be told.
#[test]
fn falling_past_the_secret_service_is_reported_as_such() {
    for level in [StorageLevel::KernelKeyring, StorageLevel::File] {
        let store = FakeStore::empty(level);

        assert_eq!(
            open(&store, 7).expect("open").backing(),
            Backing::Software(SoftwareReason::NoSecretService),
            "{level:?}"
        );
    }
}

#[test]
fn backing_follows_the_store_that_was_used_and_not_the_one_that_was_wanted() {
    let secret_service = open(&FakeStore::empty(StorageLevel::SecretService), 7).expect("open");
    let file = open(&FakeStore::empty(StorageLevel::File), 7).expect("open");

    assert_ne!(secret_service.backing(), file.backing());
}

// --- The stored form ---

#[test]
fn a_stored_key_is_versioned_and_carries_both_keys() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    open(&store, 7).expect("open");
    let held = store.held.borrow().clone().expect("a stored value");

    assert_eq!(held[0], 1, "the first byte is the format version");
    assert_eq!(held.len(), 1 + 32 + 32, "a version byte and two scalars");
}

#[test]
fn signing_works_the_same_before_and_after_a_reopen() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    let first = open(&store, 7).expect("first open");
    let second = open(&store, 7).expect("second open");
    let message = b"the same message";

    assert_eq!(
        first
            .sign(tradr_core::DomainTag::KeyBind, message)
            .expect("first signature"),
        second
            .sign(tradr_core::DomainTag::KeyBind, message)
            .expect("second signature")
    );
}

// The two scalars are written in a fixed order and read back in the same
// one. A device whose identity key came back as its agreement key would
// sign with the wrong key and agree with the wrong key, and every field
// of `PublicIdentity` would still be well formed.
#[test]
fn the_two_keys_keep_their_roles_across_a_reopen() {
    let store = FakeStore::empty(StorageLevel::SecretService);
    let first = open(&store, 7).expect("first open");
    let identity = first.public_identity().expect("first identity");

    let second = open(&store, 7).expect("second open");
    let reopened = second.public_identity().expect("second identity");

    assert_ne!(
        identity.identity_pub(),
        identity.agreement_pub(),
        "the fixture must give two different keys or this proves nothing"
    );
    assert_eq!(identity.identity_pub(), reopened.identity_pub());
    assert_eq!(identity.agreement_pub(), reopened.agreement_pub());
}

//! Supervisor-authored tests for the Account Broadcast Key registry,
//! written before the implementation. A Critical Module (CLAUDE.md
//! section 6): a rotation whose bytes did not change leaves a revoked
//! device matching every EID the account broadcasts, and neither that
//! nor a key read back for another account reaches any gate or log.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use tradr_core::{
    ACCOUNT_BROADCAST_KEY_LEN, AccountBroadcastKey, Rng, RngError, SecretStore, SecretStoreError,
    StorageLevel, UnixTime,
};
use tradr_identity::{
    ACCOUNT_BROADCAST_KEY_SLOT, AccountId, BroadcastKeyRegistry, BroadcastKeyRegistryError,
};

const NOW: i64 = 1_756_684_800;
const LATER: i64 = 1_756_688_400;

// Each test gets a path of its own so nothing depends on execution order
// (rule E2), following the Link registry's own tests.
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("tradr-abk-{}-{n}.json", std::process::id()));
    let _remove = std::fs::remove_file(&path);
    path
}

// A path inside a directory that does not exist yet, so `load` reads it
// as the first run a missing file is, and `block` below is what makes a
// write fail afterwards.
fn blocked_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tradr-abk-blocked-{}-{n}", std::process::id()));
    let _remove_dir = std::fs::remove_dir_all(&dir);
    let _remove_file = std::fs::remove_file(&dir);
    dir.join("account-broadcast-key.json")
}

// Puts a regular file where `path`'s parent directory would go, so the
// registry's own write fails without touching any permission bit.
fn block(path: &std::path::Path) {
    let dir = path.parent().expect("a blocked path has a parent");
    std::fs::write(dir, b"not a directory").expect("the blocker is writable");
}

fn account(sub: &str) -> AccountId {
    AccountId::new("https://accounts.google.com", sub)
}

fn at(secs: i64) -> UnixTime {
    UnixTime::from_secs(secs)
}

// The bytes `StreamRng`'s nth call produces, stated here so a test can
// name the value it expects rather than compare two calls of the fake.
fn stream(call: u8) -> [u8; ACCOUNT_BROADCAST_KEY_LEN] {
    std::array::from_fn(|i| {
        call.wrapping_mul(0x40)
            .wrapping_add(i as u8)
            .wrapping_add(1)
    })
}

// An `Rng` producing a different, pinned block on every call, so a
// rotation that failed to draw fresh bytes is visible as a repeat.
#[derive(Default)]
struct StreamRng {
    calls: Cell<u8>,
    fail: bool,
}

impl StreamRng {
    fn failing() -> Self {
        Self {
            calls: Cell::new(0),
            fail: true,
        }
    }

    fn calls(&self) -> u8 {
        self.calls.get()
    }
}

impl Rng for StreamRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        if self.fail {
            return Err(RngError::Source(Box::new(std::io::Error::other(
                "the entropy source refused",
            ))));
        }
        let call = self.calls.get();
        self.calls.set(call.wrapping_add(1));
        let block = stream(call);
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = block[i % ACCOUNT_BROADCAST_KEY_LEN];
        }
        Ok(())
    }
}

// A `SecretStore` holding its slots in memory: no keyring, no D-Bus and
// no filesystem (rule B5). It counts what it was asked to do and can be
// told to fail from a given call onwards, since what several tests below
// measure is which half moved first and what a failure put back.
#[derive(Default)]
struct Vault {
    slots: RefCell<BTreeMap<String, Vec<u8>>>,
    stores: Cell<usize>,
    removes: Cell<usize>,
    fail_store_from: Option<usize>,
    fail_remove: bool,
    fail_load: bool,
}

impl Vault {
    fn failing_to_store() -> Self {
        Self {
            fail_store_from: Some(1),
            ..Self::default()
        }
    }

    fn failing_to_store_from(call: usize) -> Self {
        Self {
            fail_store_from: Some(call),
            ..Self::default()
        }
    }

    fn failing_to_remove() -> Self {
        Self {
            fail_remove: true,
            ..Self::default()
        }
    }

    fn failing_to_load() -> Self {
        Self {
            fail_load: true,
            ..Self::default()
        }
    }

    fn held(&self, slot: &str) -> Option<Vec<u8>> {
        self.slots.borrow().get(slot).cloned()
    }

    fn plant(&self, slot: &str, bytes: &[u8]) {
        self.slots
            .borrow_mut()
            .insert(slot.to_string(), bytes.to_vec());
    }

    fn stores(&self) -> usize {
        self.stores.get()
    }

    fn removes(&self) -> usize {
        self.removes.get()
    }
}

impl SecretStore for Vault {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let call = self.stores.get() + 1;
        if self.fail_store_from.is_some_and(|from| call >= from) {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the vault refused to write",
            ))));
        }
        self.stores.set(call);
        self.plant(slot, secret);
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        if self.fail_load {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the vault refused to read",
            ))));
        }
        Ok(self.held(slot))
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        if self.fail_remove {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the vault refused to discard",
            ))));
        }
        self.removes.set(self.removes.get() + 1);
        self.slots.borrow_mut().remove(slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

fn load(path: &std::path::Path, sub: &str) -> BroadcastKeyRegistry {
    BroadcastKeyRegistry::load(path, &account(sub)).expect("this registry loads")
}

// --- The slot, and a first run ---

#[test]
fn the_slot_is_one_constant_name_and_not_derived_from_the_account() {
    assert_eq!(ACCOUNT_BROADCAST_KEY_SLOT, "account-broadcast-key");
}

#[test]
fn a_missing_file_is_a_registry_holding_no_key_and_not_an_error() {
    let path = scratch_path();
    let vault = Vault::default();

    let registry = load(&path, "alice");

    assert_eq!(registry.created_at(), None);
    assert!(
        registry
            .key(&vault)
            .expect("an absent record reads clean")
            .is_none(),
        "a first run reported a key it never generated"
    );
}

#[test]
fn a_registry_remembers_the_account_it_was_opened_for() {
    let path = scratch_path();

    let registry = load(&path, "alice");

    assert_eq!(registry.account(), &account("alice"));
}

#[test]
fn a_file_that_is_not_the_json_this_module_writes_is_malformed_and_never_an_empty_registry() {
    let path = scratch_path();
    std::fs::write(&path, b"{ not json").expect("the scratch path is writable");

    let err =
        BroadcastKeyRegistry::load(&path, &account("alice")).expect_err("a broken file is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Malformed(_)),
        "a broken file loaded as something other than malformed: {err:?}"
    );
}

// --- Generation: where the bytes come from ---

#[test]
fn generate_returns_the_bytes_the_rng_produced_and_stores_exactly_those() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = StreamRng::default();
    let mut registry = load(&path, "alice");

    let key = registry
        .generate(&rng, at(NOW), &vault)
        .expect("generation succeeds");

    assert_eq!(key.as_bytes(), &stream(0));
    assert_eq!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).as_deref(),
        Some(stream(0).as_slice())
    );
}

// The account is not an input to generation. Deriving the key from it --
// which is what the bootstrap secret already is, and public -- would make
// these two differ.
#[test]
fn two_accounts_drawing_the_same_bytes_get_the_same_key() {
    let alice_path = scratch_path();
    let bob_path = scratch_path();
    let vault = Vault::default();
    let mut alice = load(&alice_path, "alice");
    let mut bob = load(&bob_path, "bob");

    let alice_key = alice
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("alice generates");
    let bob_key = bob
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("bob generates");

    assert_eq!(alice_key.as_bytes(), bob_key.as_bytes());
}

#[test]
fn generate_draws_exactly_one_block_of_thirty_two_bytes() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = StreamRng::default();
    let mut registry = load(&path, "alice");

    registry
        .generate(&rng, at(NOW), &vault)
        .expect("generation succeeds");

    assert_eq!(rng.calls(), 1);
}

#[test]
fn generate_records_the_time_it_was_given_and_never_reads_a_clock_of_its_own() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");

    registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("generation succeeds");

    assert_eq!(registry.created_at(), Some(at(NOW)));
}

#[test]
fn a_generated_key_survives_a_reload_with_its_creation_time() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    let generated = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("generation succeeds");

    let reopened = load(&path, "alice");

    assert_eq!(reopened.created_at(), Some(at(NOW)));
    assert_eq!(
        reopened
            .key(&vault)
            .expect("the slot reads")
            .expect("the slot holds the key")
            .as_bytes(),
        generated.as_bytes()
    );
}

#[test]
fn an_rng_that_refuses_writes_neither_half() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");

    let err = registry
        .generate(&StreamRng::failing(), at(NOW), &vault)
        .expect_err("a refused draw is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Rng(_)),
        "a refused draw reported something else: {err:?}"
    );
    assert_eq!(vault.stores(), 0);
    assert_eq!(registry.created_at(), None);
    assert!(!path.exists(), "a refused draw left a record behind");
}

// --- Rotation: the failure nothing downstream can see ---

// A rotation that reused the previous bytes leaves the revoked device
// matching every EID the account broadcasts, and docs/05's revocation
// table becomes false with no test, gate or handshake noticing.
#[test]
fn a_second_generate_replaces_the_bytes_rather_than_returning_the_first_ones() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = StreamRng::default();
    let mut registry = load(&path, "alice");
    let first = registry
        .generate(&rng, at(NOW), &vault)
        .expect("the first generation succeeds");

    let second = registry
        .generate(&rng, at(LATER), &vault)
        .expect("the second generation succeeds");

    assert_ne!(
        first.as_bytes(),
        second.as_bytes(),
        "the rotation handed back the key it was supposed to replace"
    );
    assert_eq!(second.as_bytes(), &stream(1));
    assert_eq!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).as_deref(),
        Some(stream(1).as_slice()),
        "the slot still holds the rotated-away key"
    );
}

#[test]
fn a_rotation_replaces_the_creation_time_too() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = StreamRng::default();
    let mut registry = load(&path, "alice");
    registry
        .generate(&rng, at(NOW), &vault)
        .expect("the first generation succeeds");

    registry
        .generate(&rng, at(LATER), &vault)
        .expect("the second generation succeeds");

    assert_eq!(registry.created_at(), Some(at(LATER)));
    assert_eq!(load(&path, "alice").created_at(), Some(at(LATER)));
}

// --- Adopting the peer's key, which is what the collision rule calls ---

#[test]
fn adopt_stores_the_key_and_the_creation_time_it_was_handed() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    let theirs = AccountBroadcastKey::from_bytes(&[0x5A; ACCOUNT_BROADCAST_KEY_LEN])
        .expect("32 bytes is a key");

    registry
        .adopt(&theirs, at(NOW), &vault)
        .expect("adoption succeeds");

    assert_eq!(registry.created_at(), Some(at(NOW)));
    assert_eq!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).as_deref(),
        Some([0x5A; ACCOUNT_BROADCAST_KEY_LEN].as_slice())
    );
}

#[test]
fn adopting_over_a_generated_key_replaces_both_halves() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    registry
        .generate(&StreamRng::default(), at(LATER), &vault)
        .expect("generation succeeds");
    let theirs = AccountBroadcastKey::from_bytes(&[0x5A; ACCOUNT_BROADCAST_KEY_LEN])
        .expect("32 bytes is a key");

    registry
        .adopt(&theirs, at(NOW), &vault)
        .expect("adoption succeeds");

    assert_eq!(registry.created_at(), Some(at(NOW)));
    assert_eq!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).as_deref(),
        Some([0x5A; ACCOUNT_BROADCAST_KEY_LEN].as_slice())
    );
}

// --- The account binding ---

#[test]
fn a_record_naming_another_account_is_refused_and_never_read_as_this_account_s_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut alice = load(&path, "alice");
    alice
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("alice generates");

    let err = BroadcastKeyRegistry::load(&path, &account("bob"))
        .expect_err("bob may not open alice's record");

    assert!(
        matches!(err, BroadcastKeyRegistryError::WrongAccount),
        "another account's record loaded as something else: {err:?}"
    );
}

#[test]
fn the_issuer_is_part_of_the_binding_and_not_only_the_subject() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = BroadcastKeyRegistry::load(&path, &AccountId::new("https://a.example", "1"))
        .expect("a first run loads");
    registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("generation succeeds");

    let err = BroadcastKeyRegistry::load(&path, &AccountId::new("https://b.example", "1"))
        .expect_err("the same subject at another issuer is another account");

    assert!(
        matches!(err, BroadcastKeyRegistryError::WrongAccount),
        "the issuer was not compared: {err:?}"
    );
}

#[test]
fn clear_discards_both_halves_and_is_what_repairs_a_wrong_account() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut alice = load(&path, "alice");
    alice
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("alice generates");

    BroadcastKeyRegistry::clear(&path, &vault).expect("clearing succeeds");

    assert!(vault.held(ACCOUNT_BROADCAST_KEY_SLOT).is_none());
    let bob = load(&path, "bob");
    assert_eq!(bob.created_at(), None);
    assert!(bob.key(&vault).expect("the slot reads").is_none());
}

#[test]
fn clearing_a_registry_that_holds_nothing_is_a_success() {
    let path = scratch_path();
    let vault = Vault::default();

    BroadcastKeyRegistry::clear(&path, &vault).expect("clearing nothing succeeds");

    assert!(!path.exists());
}

#[test]
fn clear_discards_the_secret_before_the_record() {
    let path = scratch_path();
    let vault = Vault::failing_to_remove();
    vault.plant(
        ACCOUNT_BROADCAST_KEY_SLOT,
        &[0x11; ACCOUNT_BROADCAST_KEY_LEN],
    );
    std::fs::write(
        &path,
        br#"{"account_iss":"https://accounts.google.com","account_sub":"alice","created_at":1756684800}"#,
    )
    .expect("the scratch path is writable");

    let err = BroadcastKeyRegistry::clear(&path, &vault).expect_err("a refused discard is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Secret(_)),
        "a refused discard reported something else: {err:?}"
    );
    assert!(
        path.exists(),
        "the record was removed while its secret was still held"
    );
}

// --- What a read distinguishes ---

#[test]
fn a_record_whose_slot_is_empty_is_an_error_and_not_an_absent_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("generation succeeds");
    vault
        .remove(ACCOUNT_BROADCAST_KEY_SLOT)
        .expect("the vault discards");

    let err = registry
        .key(&vault)
        .expect_err("a record without its secret is a half-written state");

    assert!(
        matches!(err, BroadcastKeyRegistryError::SecretMissing),
        "an emptied slot read as something else: {err:?}"
    );
}

#[test]
fn a_stored_value_of_the_wrong_length_is_malformed_and_never_read_as_absent() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("generation succeeds");
    vault.plant(ACCOUNT_BROADCAST_KEY_SLOT, &[0x11; 31]);

    let err = registry
        .key(&vault)
        .expect_err("31 bytes is not an account broadcast key");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Malformed(_)),
        "a wrong-length value read as something else: {err:?}"
    );
}

#[test]
fn a_secret_store_that_cannot_be_reached_is_an_error_and_never_an_absent_key() {
    let path = scratch_path();
    let writable = Vault::default();
    let mut registry = load(&path, "alice");
    registry
        .generate(&StreamRng::default(), at(NOW), &writable)
        .expect("generation succeeds");
    let unreachable = Vault::failing_to_load();

    let err = registry
        .key(&unreachable)
        .expect_err("an unreachable store is an error");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Secret(_)),
        "an unreachable store read as something else: {err:?}"
    );
}

// --- The order the two halves move in ---

#[test]
fn a_refused_store_leaves_no_record_behind() {
    let path = scratch_path();
    let vault = Vault::failing_to_store();
    let mut registry = load(&path, "alice");

    let err = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect_err("a refused store is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Secret(_)),
        "a refused store reported something else: {err:?}"
    );
    assert!(
        !path.exists(),
        "the record was written for a secret that was never stored"
    );
    assert_eq!(registry.created_at(), None);
}

#[test]
fn a_generation_whose_record_cannot_be_written_takes_its_new_secret_back_down() {
    let path = blocked_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    block(&path);

    let err = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect_err("a record that cannot be written is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Io(_)),
        "an unwritable record reported something else: {err:?}"
    );
    assert!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).is_none(),
        "the new secret outlived the record write that failed"
    );
    assert_eq!(registry.created_at(), None);
}

// The rollback restores rather than empties: emptying would turn a failed
// rotation into a lost ABK and put the device back on bootstrap
// advertising while its record still claimed a key.
#[test]
fn a_rotation_whose_record_cannot_be_written_puts_the_previous_secret_back() {
    let path = blocked_path();
    let vault = Vault::default();
    vault.plant(
        ACCOUNT_BROADCAST_KEY_SLOT,
        &[0x11; ACCOUNT_BROADCAST_KEY_LEN],
    );
    let mut registry = load(&path, "alice");
    block(&path);

    let err = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect_err("a record that cannot be written is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Io(_)),
        "an unwritable record reported something else: {err:?}"
    );
    assert_eq!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).as_deref(),
        Some([0x11; ACCOUNT_BROADCAST_KEY_LEN].as_slice()),
        "the previous key was not put back"
    );
}

#[test]
fn an_adoption_whose_record_cannot_be_written_puts_the_previous_secret_back() {
    let path = blocked_path();
    let vault = Vault::default();
    vault.plant(
        ACCOUNT_BROADCAST_KEY_SLOT,
        &[0x11; ACCOUNT_BROADCAST_KEY_LEN],
    );
    let mut registry = load(&path, "alice");
    block(&path);
    let theirs = AccountBroadcastKey::from_bytes(&[0x5A; ACCOUNT_BROADCAST_KEY_LEN])
        .expect("32 bytes is a key");

    let _err = registry
        .adopt(&theirs, at(NOW), &vault)
        .expect_err("a record that cannot be written is refused");

    assert_eq!(
        vault.held(ACCOUNT_BROADCAST_KEY_SLOT).as_deref(),
        Some([0x11; ACCOUNT_BROADCAST_KEY_LEN].as_slice()),
        "the previous key was not put back"
    );
}

// Rule F6: the second failure is reported beside the first, never
// instead of it.
#[test]
fn a_restore_that_itself_fails_is_reported_beside_the_write_that_caused_it() {
    let path = blocked_path();
    let vault = Vault::failing_to_store_from(2);
    vault.plant(
        ACCOUNT_BROADCAST_KEY_SLOT,
        &[0x11; ACCOUNT_BROADCAST_KEY_LEN],
    );
    let mut registry = load(&path, "alice");
    block(&path);

    let err = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect_err("a record that cannot be written is refused");

    let BroadcastKeyRegistryError::SecretRollbackFailed { persist, restore } = err else {
        panic!("a failed rollback was reported as something else: {err:?}");
    };
    assert!(
        matches!(*persist, BroadcastKeyRegistryError::Io(_)),
        "the failure that caused the rollback was discarded: {persist:?}"
    );
    let rendered = format!("{restore}");
    assert!(
        rendered.contains("the vault refused to write"),
        "the rollback's own failure was not carried: {rendered}"
    );
}

#[test]
fn a_discard_that_itself_fails_is_reported_beside_the_write_that_caused_it() {
    let path = blocked_path();
    let vault = Vault::failing_to_remove();
    let mut registry = load(&path, "alice");
    block(&path);

    let err = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect_err("a record that cannot be written is refused");

    let BroadcastKeyRegistryError::SecretRollbackFailed { persist, restore } = err else {
        panic!("a failed rollback was reported as something else: {err:?}");
    };
    assert!(
        matches!(*persist, BroadcastKeyRegistryError::Io(_)),
        "the failure that caused the rollback was discarded: {persist:?}"
    );
    let rendered = format!("{restore}");
    assert!(
        rendered.contains("the vault refused to discard"),
        "the rollback's own failure was not carried: {rendered}"
    );
}

#[test]
fn a_failed_generation_leaves_the_registry_reporting_what_is_actually_held() {
    let path = blocked_path();
    let vault = Vault::default();
    vault.plant(
        ACCOUNT_BROADCAST_KEY_SLOT,
        &[0x11; ACCOUNT_BROADCAST_KEY_LEN],
    );
    let mut registry = load(&path, "alice");
    block(&path);

    let _err = registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect_err("a record that cannot be written is refused");

    assert_eq!(
        registry.created_at(),
        None,
        "the registry adopted a creation time for a record it never wrote"
    );
    assert_eq!(vault.removes(), 0, "the rollback emptied the slot");
}

// The record's field names are what docs/11 writes down, and they are
// what a second reader of this file -- a repair, a migration -- would go
// by. Nothing else pins them.
#[test]
fn the_record_carries_the_three_fields_docs_11_names_and_never_the_key_itself() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path, "alice");
    registry
        .generate(&StreamRng::default(), at(NOW), &vault)
        .expect("generation succeeds");

    let written = std::fs::read_to_string(&path).expect("the record was written");

    assert!(written.contains("\"account_iss\""), "{written}");
    assert!(written.contains("\"account_sub\""), "{written}");
    assert!(written.contains("\"created_at\""), "{written}");
    assert!(
        written.contains("1756684800"),
        "the creation time is not seconds since the epoch: {written}"
    );
    let as_hex: String = stream(0).iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !written.contains(&as_hex),
        "the record holds the key material: {written}"
    );
    assert!(
        !written.contains('['),
        "the record holds an array, which only the key bytes could be: {written}"
    );
}

// An unreadable path is not an absent record. Read as one, a device whose
// data directory is broken looks exactly like a first run: it generates a
// key, fails to write it, and reports having none -- the same answer it
// would give if it had never had one.
#[test]
fn a_path_that_cannot_be_read_at_all_is_an_error_and_never_an_empty_registry() {
    let path = blocked_path();
    block(&path);

    let err = BroadcastKeyRegistry::load(&path, &account("alice"))
        .expect_err("an unreadable path is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Io(_)),
        "an unreadable path loaded as something else: {err:?}"
    );
}

#[test]
fn a_record_that_cannot_be_removed_fails_the_clear_rather_than_passing_it() {
    let path = blocked_path();
    block(&path);
    let vault = Vault::default();

    let err = BroadcastKeyRegistry::clear(&path, &vault)
        .expect_err("a record that cannot be removed is refused");

    assert!(
        matches!(err, BroadcastKeyRegistryError::Io(_)),
        "an unremovable record reported something else: {err:?}"
    );
    assert_eq!(
        vault.removes(),
        1,
        "the secret was not discarded before the record was attempted"
    );
}

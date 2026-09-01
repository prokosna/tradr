//! Supervisor-authored tests for the Secret Service rung. Every one is
//! `#[ignore]`d: they need a real Secret Service on the session bus, which
//! is the one barrier no hermetic test reaches. Run with
//! `cargo test -p tradr-secrets --test secret_service -- --ignored`.

#![cfg(target_os = "linux")]

use tradr_core::{SecretStore, StorageLevel};
use tradr_secrets::SecretServiceStore;

// Every test owns a slot nothing else writes: these run against one real
// collection shared by the whole process, where a shared slot makes
// concurrent tests overwrite each other (rule E2). The names are fixed
// rather than random so repeated runs reuse them instead of piling up
// items in whoever's login keyring runs them.
fn slot(name: &str) -> String {
    format!("tradr-test-{name}")
}

const KEY: &[u8] = b"a stored device key";

fn open() -> SecretServiceStore {
    SecretServiceStore::open().expect("a Secret Service should answer on the session bus")
}

#[test]
#[ignore]
fn a_stored_value_comes_back_byte_identical() {
    let store = open();
    let slot = slot("roundtrip");

    store.store(&slot, KEY).expect("storing should succeed");
    let loaded = store.load(&slot).expect("loading should succeed");

    assert_eq!(loaded.as_deref(), Some(KEY));
}

// The distinction the whole ladder rests on. A Secret Service that is
// reachable and simply holds nothing must answer `Ok(None)`, or a device
// whose key is on a lower rung never gets to look for it.
#[test]
#[ignore]
fn a_slot_that_was_never_stored_is_empty_rather_than_an_error() {
    let store = open();

    let loaded = store
        .load(&slot("never-written"))
        .expect("an absent slot is not an error");

    assert_eq!(loaded, None);
}

#[test]
#[ignore]
fn a_second_store_replaces_the_first() {
    let store = open();
    let slot = slot("replace");

    store.store(&slot, KEY).expect("first store");
    store.store(&slot, b"shorter").expect("second store");
    let loaded = store.load(&slot).expect("loading should succeed");

    assert_eq!(loaded.as_deref(), Some(&b"shorter"[..]));

    // Two items sharing a lookup attribute would make `load` ambiguous,
    // and which one it answered with would depend on the daemon.
    store.store(&slot, KEY).expect("third store");
    assert_eq!(store.load(&slot).expect("reload").as_deref(), Some(KEY));
}

#[test]
#[ignore]
fn a_zero_byte_value_round_trips_as_a_value() {
    let store = open();
    let slot = slot("empty");

    store.store(&slot, b"").expect("storing should succeed");

    assert_eq!(
        store.load(&slot).expect("loading").as_deref(),
        Some(&b""[..])
    );
}

#[test]
#[ignore]
fn two_slots_do_not_collide() {
    let store = open();
    let first = slot("collide-first");
    let second = slot("collide-second");

    store.store(&first, b"one").expect("first");
    store.store(&second, b"two").expect("second");

    assert_eq!(
        store.load(&first).expect("load first").as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(
        store.load(&second).expect("load second").as_deref(),
        Some(&b"two"[..])
    );
}

#[test]
#[ignore]
fn level_is_the_secret_service_rung() {
    assert_eq!(open().level(), StorageLevel::SecretService);
}

// The rung has to be usable as what the ladder walks, not only as a
// concrete type.
#[test]
#[ignore]
fn it_is_usable_as_a_trait_object() {
    let store = open();
    let as_trait: &dyn SecretStore = &store;

    assert_eq!(as_trait.level(), StorageLevel::SecretService);
}

#[test]
#[ignore]
fn a_removed_slot_reads_back_empty() {
    let store = open();
    let slot = slot("remove");
    store.store(&slot, KEY).expect("storing should succeed");

    store
        .remove(&slot)
        .expect("removing a stored slot succeeds");

    assert_eq!(store.load(&slot).expect("loading should succeed"), None);
}

// DCR-070: the same absence `load` answers with `Ok(None)`, answered the
// same way, so a retry after a half-finished removal still succeeds.
#[test]
#[ignore]
fn removing_a_slot_that_was_never_stored_is_a_success() {
    let store = open();

    store
        .remove(&slot("remove-never-written"))
        .expect("an absent slot is not an error to remove");
}

#[test]
#[ignore]
fn removing_one_slot_leaves_another_alone() {
    let store = open();
    let gone = slot("remove-gone");
    let kept = slot("remove-kept");
    store.store(&gone, KEY).expect("first store");
    store.store(&kept, b"kept").expect("second store");

    store.remove(&gone).expect("the first slot removes");

    assert_eq!(store.load(&gone).expect("load gone"), None);
    assert_eq!(
        store.load(&kept).expect("load kept").as_deref(),
        Some(&b"kept"[..])
    );
}

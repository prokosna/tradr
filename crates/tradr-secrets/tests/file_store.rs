//! Supervisor-authored tests for the `0600` file rung, the last resort of
//! docs/05's ladder. Critical Module adjacent: a slot this store cannot
//! read must never present as a slot that is empty, or the caller mints a
//! second Device Key over a key that is still there.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use tradr_core::{SecretStore, StorageLevel};
use tradr_secrets::FileStore;

const SLOT: &str = "device-key";
const KEY: &[u8] = b"a stored device key";

// Each test owns a directory nothing else touches, so ordering cannot
// matter (rule E2). The directory is deliberately not created here: some
// tests are about the store creating it.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tradr-file-store-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[cfg(unix)]
fn mode_of(path: &PathBuf) -> u32 {
    fs::metadata(path)
        .expect("the path should exist")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn a_missing_file_is_an_empty_slot() {
    let dir = scratch("missing");
    let store = FileStore::new(dir.clone());

    let loaded = store.load(SLOT).expect("an absent file is not an error");

    assert_eq!(loaded, None);
}

#[test]
fn a_stored_value_comes_back_byte_identical() {
    let dir = scratch("roundtrip");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, KEY).expect("storing should succeed");
    let loaded = store.load(SLOT).expect("loading should succeed");

    assert_eq!(loaded.as_deref(), Some(KEY));
}

// A key readable by another account on the machine is a key that has left
// the device, which is the one promise this rung still makes.
#[test]
#[cfg(unix)]
fn the_stored_file_is_readable_only_by_its_owner() {
    let dir = scratch("mode");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, KEY).expect("storing should succeed");

    assert_eq!(mode_of(&dir.join(SLOT)), 0o600);
}

#[test]
#[cfg(unix)]
fn the_directory_is_created_and_is_reachable_only_by_its_owner() {
    let dir = scratch("dirmode");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, KEY).expect("storing should succeed");

    assert!(dir.is_dir(), "the store should have created its directory");
    assert_eq!(mode_of(&dir), 0o700);
}

#[test]
fn a_second_store_replaces_the_first_rather_than_appending() {
    let dir = scratch("replace");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, KEY).expect("first store");
    store.store(SLOT, b"shorter").expect("second store");
    let loaded = store.load(SLOT).expect("loading should succeed");

    assert_eq!(loaded.as_deref(), Some(&b"shorter"[..]));
}

#[test]
#[cfg(unix)]
fn a_replaced_file_is_still_readable_only_by_its_owner() {
    let dir = scratch("replacemode");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, KEY).expect("first store");
    store.store(SLOT, b"shorter").expect("second store");

    assert_eq!(mode_of(&dir.join(SLOT)), 0o600);
}

// The whole reason this rung is written carefully. An unreadable file and
// an absent one are one line apart in every filesystem API and mean
// opposite things to a caller deciding whether to generate a key.
#[test]
#[cfg(unix)]
fn a_file_that_cannot_be_read_is_an_error_and_not_an_empty_slot() {
    let dir = scratch("unreadable");
    let store = FileStore::new(dir.clone());
    store.store(SLOT, KEY).expect("storing should succeed");
    fs::set_permissions(dir.join(SLOT), fs::Permissions::from_mode(0o000))
        .expect("the mode should be settable");

    let outcome = store.load(SLOT);

    let _ = fs::set_permissions(dir.join(SLOT), fs::Permissions::from_mode(0o600));
    assert!(
        outcome.is_err(),
        "an unreadable slot came back as {outcome:?} rather than an error"
    );
}

#[test]
fn a_zero_byte_secret_round_trips_as_a_value() {
    let dir = scratch("empty");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, b"").expect("storing should succeed");
    let loaded = store.load(SLOT).expect("loading should succeed");

    assert_eq!(loaded.as_deref(), Some(&b""[..]));
}

#[test]
fn two_slots_do_not_collide() {
    let dir = scratch("twoslots");
    let store = FileStore::new(dir.clone());

    store.store("first", b"one").expect("first store");
    store.store("second", b"two").expect("second store");

    assert_eq!(
        store.load("first").expect("load first").as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(
        store.load("second").expect("load second").as_deref(),
        Some(&b"two"[..])
    );
}

#[test]
fn storing_leaves_nothing_behind_but_the_slot() {
    let dir = scratch("notemp");
    let store = FileStore::new(dir.clone());

    store.store(SLOT, KEY).expect("first store");
    store.store(SLOT, b"again").expect("second store");

    let names: Vec<String> = fs::read_dir(&dir)
        .expect("the directory should exist")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [SLOT], "a temporary file was left in the directory");
}

#[test]
fn level_is_the_file_rung() {
    let dir = scratch("level");

    assert_eq!(FileStore::new(dir).level(), StorageLevel::File);
}

// A slot names a file, so a slot that names a path escapes the directory
// this store was given. Every caller today passes a constant, which is
// exactly when a check like this is cheap to add and impossible to add
// later.
#[test]
fn a_slot_that_climbs_out_of_the_directory_is_refused() {
    let dir = scratch("climb");
    let store = FileStore::new(dir.clone());

    assert!(store.store("../escaped", KEY).is_err());
    assert!(store.load("../escaped").is_err());
}

#[test]
fn a_slot_containing_a_separator_is_refused() {
    let dir = scratch("separator");
    let store = FileStore::new(dir.clone());

    assert!(store.store("nested/key", KEY).is_err());
    assert!(store.load("nested/key").is_err());
}

#[test]
fn an_absolute_slot_is_refused() {
    let dir = scratch("absolute");
    let store = FileStore::new(dir.clone());

    assert!(store.store("/etc/passwd", KEY).is_err());
    assert!(store.load("/etc/passwd").is_err());
}

#[test]
fn an_empty_slot_name_is_refused() {
    let dir = scratch("emptyname");
    let store = FileStore::new(dir.clone());

    assert!(store.store("", KEY).is_err());
    assert!(store.load("",).is_err());
}

// The store's directory is nested inside this test's own scratch
// directory, so the place a `..` lands in belongs to this test too.
// Asserting against a shared parent such as the system temporary
// directory lets one stray file fail the test forever, whatever the
// implementation does.
#[test]
fn a_refused_slot_creates_nothing_at_all() {
    let enclosing = scratch("refusedcreates");
    let dir = enclosing.join("store");
    let store = FileStore::new(dir.clone());

    let _ = store.store("../escaped", KEY);

    assert!(
        !enclosing.join("escaped").exists(),
        "a refused slot wrote outside the directory it was given"
    );
}

// `OpenOptions::mode` and `DirBuilder::mode` are the mode argument to
// `open(2)` and `mkdir(2)`, which the kernel consults only when the call
// actually creates something. A path that is already there keeps whatever
// mode it has, so a store that only ever creates its own paths keeps the
// 0600 promise by luck rather than by enforcing it.
#[test]
#[cfg(unix)]
fn a_directory_that_already_exists_too_widely_is_narrowed() {
    let dir = scratch("widedir");
    fs::create_dir_all(&dir).expect("the directory should be creatable");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("mode should be settable");

    FileStore::new(dir.clone())
        .store(SLOT, KEY)
        .expect("storing should succeed");

    assert_eq!(mode_of(&dir), 0o700);
}

#[test]
#[cfg(unix)]
fn a_file_that_already_exists_too_widely_is_narrowed() {
    let dir = scratch("widefile");
    fs::create_dir_all(&dir).expect("the directory should be creatable");
    fs::write(dir.join(SLOT), b"an older key").expect("the file should be writable");
    fs::set_permissions(dir.join(SLOT), fs::Permissions::from_mode(0o644))
        .expect("mode should be settable");

    FileStore::new(dir.clone())
        .store(SLOT, KEY)
        .expect("storing should succeed");

    assert_eq!(mode_of(&dir.join(SLOT)), 0o600);
}

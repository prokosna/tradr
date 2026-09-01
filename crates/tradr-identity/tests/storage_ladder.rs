//! Supervisor-authored tests for DCR-031's search over the storage
//! ladder. Critical Module, CLAUDE.md section 6: a search that declares
//! an occupied ladder empty makes its caller mint a second Device Key,
//! and a device with a second Device Key has lost its identity and every
//! link to it while failing no build, no test and no handshake.

use std::cell::{Cell, RefCell};

use tradr_core::{SecretStore, SecretStoreError, StorageLevel};
use tradr_identity::{LadderError, select_rung};

/// A rung answering from memory that records what it was asked, so a test
/// can assert what was never read as well as what was.
struct Rung {
    level: StorageLevel,
    held: Option<Vec<u8>>,
    fails: bool,
    loads: Cell<usize>,
    stores: Cell<usize>,
    slots: RefCell<Vec<String>>,
}

impl Rung {
    fn empty(level: StorageLevel) -> Self {
        Self {
            level,
            held: None,
            fails: false,
            loads: Cell::new(0),
            stores: Cell::new(0),
            slots: RefCell::new(Vec::new()),
        }
    }

    fn holding(level: StorageLevel, value: &[u8]) -> Self {
        Self {
            held: Some(value.to_vec()),
            ..Self::empty(level)
        }
    }

    fn failing(level: StorageLevel) -> Self {
        Self {
            fails: true,
            ..Self::empty(level)
        }
    }

    fn loads(&self) -> usize {
        self.loads.get()
    }
}

impl SecretStore for Rung {
    fn store(&self, _slot: &str, _secret: &[u8]) -> Result<(), SecretStoreError> {
        self.stores.set(self.stores.get() + 1);
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        self.loads.set(self.loads.get() + 1);
        self.slots.borrow_mut().push(slot.to_owned());
        if self.fails {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the rung was reachable and did not answer",
            ))));
        }
        Ok(self.held.clone())
    }

    fn remove(&self, _slot: &str) -> Result<(), SecretStoreError> {
        // select_rung never removes, so nothing here is worth counting.
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        self.level
    }
}

fn ladder<const N: usize>(rungs: [&Rung; N]) -> Vec<&dyn SecretStore> {
    rungs.iter().map(|r| *r as &dyn SecretStore).collect()
}

const SLOT: &str = "device-key";
const KEY: &[u8] = b"a stored device key";

#[test]
fn an_empty_ladder_is_an_error() {
    let outcome = select_rung(&[] as &[&dyn SecretStore], SLOT);

    assert!(matches!(outcome, Err(LadderError::NoRungs)));
}

#[test]
fn a_key_on_the_only_rung_selects_that_rung() {
    let only = Rung::holding(StorageLevel::File, KEY);

    let chosen = select_rung(&ladder([&only]), SLOT).expect("one rung holds the key");

    assert_eq!(chosen.level(), StorageLevel::File);
}

// The whole reason DCR-031 exists. A device that fell back to a file on
// its first launch must find that key the day a Secret Service is
// running, or it mints a new identity and every peer forgets it.
#[test]
fn a_key_on_the_lowest_rung_is_found_though_a_higher_rung_is_available() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let keyring = Rung::empty(StorageLevel::SecretService);
    let file = Rung::holding(StorageLevel::File, KEY);

    let chosen = select_rung(&ladder([&secret_service, &keyring, &file]), SLOT)
        .expect("the lowest rung holds the key");

    assert_eq!(chosen.level(), StorageLevel::File);
    assert_eq!(secret_service.loads(), 1);
    assert_eq!(keyring.loads(), 1);
    assert_eq!(file.loads(), 1);
}

// Separates selecting the rung that answered from selecting the first
// rung. Both pass every test where the key sits on the highest rung, and
// getting it wrong makes `backing()` name storage the key is not in.
#[test]
fn the_rung_selected_is_the_rung_holding_the_key() {
    let first = Rung::empty(StorageLevel::SecretService);
    let holder = Rung::holding(StorageLevel::SecretService, KEY);
    let lowest = Rung::empty(StorageLevel::File);

    let chosen =
        select_rung(&ladder([&first, &holder, &lowest]), SLOT).expect("the middle holds it");

    // Identity by counter rather than by level: the two upper rungs share
    // a level deliberately, so returning the first instead of the one that
    // answered cannot hide behind them being different kinds of storage.
    let (before_first, before_holder) = (first.loads(), holder.loads());
    let _ = chosen.load(SLOT);
    assert_eq!(holder.loads(), before_holder + 1);
    assert_eq!(first.loads(), before_first);
    assert_eq!(lowest.loads(), 0);
}

#[test]
fn a_key_on_the_highest_rung_leaves_the_lower_rungs_unread() {
    let secret_service = Rung::holding(StorageLevel::SecretService, KEY);
    let keyring = Rung::empty(StorageLevel::SecretService);
    let file = Rung::empty(StorageLevel::File);

    let chosen = select_rung(&ladder([&secret_service, &keyring, &file]), SLOT)
        .expect("the highest rung holds the key");

    assert_eq!(chosen.level(), StorageLevel::SecretService);
    assert_eq!(keyring.loads(), 0);
    assert_eq!(file.loads(), 0);
}

#[test]
fn two_rungs_holding_keys_select_the_higher() {
    let secret_service = Rung::holding(StorageLevel::SecretService, KEY);
    let file = Rung::holding(StorageLevel::File, b"a different key");

    let chosen = select_rung(&ladder([&secret_service, &file]), SLOT).expect("both hold a key");

    assert_eq!(chosen.level(), StorageLevel::SecretService);
}

// A fresh device writes as high as it can reach. Selecting the last rung
// instead leaves a brand-new key in a file with a Secret Service running.
#[test]
fn an_empty_ladder_of_three_selects_the_highest_for_writing() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let keyring = Rung::empty(StorageLevel::SecretService);
    let file = Rung::empty(StorageLevel::File);

    let chosen = select_rung(&ladder([&secret_service, &keyring, &file]), SLOT)
        .expect("nothing holds a key");

    assert_eq!(chosen.level(), StorageLevel::SecretService);
}

#[test]
fn an_empty_ladder_of_three_reads_every_rung() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let keyring = Rung::empty(StorageLevel::SecretService);
    let file = Rung::empty(StorageLevel::File);

    let _ = select_rung(&ladder([&secret_service, &keyring, &file]), SLOT);

    assert_eq!(secret_service.loads(), 1);
    assert_eq!(keyring.loads(), 1);
    assert_eq!(file.loads(), 1);
}

// An empty value is a stored value. A rung answering with zero bytes has
// answered, and reading that as an absence descends past a key that is
// there -- corrupt, but there, and generating over it is still identity
// loss.
#[test]
fn a_zero_byte_value_is_a_key_and_not_an_absence() {
    let secret_service = Rung::holding(StorageLevel::SecretService, b"");
    let file = Rung::holding(StorageLevel::File, KEY);

    let chosen =
        select_rung(&ladder([&secret_service, &file]), SLOT).expect("the top rung answered");

    assert_eq!(chosen.level(), StorageLevel::SecretService);
    assert_eq!(file.loads(), 0);
}

#[test]
fn a_failing_highest_rung_is_an_error_and_not_a_descent() {
    let secret_service = Rung::failing(StorageLevel::SecretService);
    let keyring = Rung::empty(StorageLevel::SecretService);
    let file = Rung::empty(StorageLevel::File);

    let outcome = select_rung(&ladder([&secret_service, &keyring, &file]), SLOT);

    assert!(
        matches!(outcome, Err(LadderError::RungFailed { .. })),
        "a rung that failed must not be read as an empty rung"
    );
}

// The sharpest case, and the one a plausible implementation gets wrong
// in the name of availability: the key really is on the file rung, so
// descending would work. It is refused because the rung that failed
// might have held a different key, and nothing can tell from here.
#[test]
fn a_failing_rung_is_an_error_even_when_a_lower_rung_holds_the_key() {
    let secret_service = Rung::failing(StorageLevel::SecretService);
    let file = Rung::holding(StorageLevel::File, KEY);

    let outcome = select_rung(&ladder([&secret_service, &file]), SLOT);

    assert!(
        matches!(outcome, Err(LadderError::RungFailed { .. })),
        "descending past a failed rung was refused by DCR-031"
    );
}

#[test]
fn a_failing_rung_names_the_level_that_failed() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let file = Rung::failing(StorageLevel::File);

    let outcome = select_rung(&ladder([&secret_service, &file]), SLOT);

    match outcome {
        Err(LadderError::RungFailed { level, .. }) => {
            assert_eq!(level, StorageLevel::File);
        }
        Err(other) => panic!("expected the failing rung to be named, got {other:?}"),
        Ok(rung) => panic!("expected an error, got the rung at {:?}", rung.level()),
    }
}

#[test]
fn a_failing_middle_rung_stops_before_the_lowest_is_read() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let keyring = Rung::failing(StorageLevel::SecretService);
    let file = Rung::holding(StorageLevel::File, KEY);

    let _ = select_rung(&ladder([&secret_service, &keyring, &file]), SLOT);

    assert_eq!(file.loads(), 0);
}

#[test]
fn a_failing_rung_below_the_answer_is_never_reached() {
    let secret_service = Rung::holding(StorageLevel::SecretService, KEY);
    let file = Rung::failing(StorageLevel::File);

    let chosen =
        select_rung(&ladder([&secret_service, &file]), SLOT).expect("the top rung answered first");

    assert_eq!(chosen.level(), StorageLevel::SecretService);
    assert_eq!(file.loads(), 0);
}

#[test]
fn selection_writes_to_no_rung() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let file = Rung::empty(StorageLevel::File);

    let _ = select_rung(&ladder([&secret_service, &file]), SLOT);

    assert_eq!(secret_service.stores.get(), 0);
    assert_eq!(file.stores.get(), 0);
}

#[test]
fn every_rung_is_asked_for_the_slot_it_was_given() {
    let secret_service = Rung::empty(StorageLevel::SecretService);
    let file = Rung::empty(StorageLevel::File);

    let _ = select_rung(&ladder([&secret_service, &file]), "another-slot");

    assert_eq!(secret_service.slots.borrow().as_slice(), ["another-slot"]);
    assert_eq!(file.slots.borrow().as_slice(), ["another-slot"]);
}

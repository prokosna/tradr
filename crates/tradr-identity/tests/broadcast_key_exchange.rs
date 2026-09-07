//! Supervisor-authored tests for the Account Broadcast Key exchange, written
//! before the implementation. A Critical Module (CLAUDE.md section 6): an
//! offer sent on a channel below `SameAccount` hands another account this
//! account's EIDs, and a draw persisted before the order has run leaves a
//! device holding a key the account never adopted. Neither reaches a gate.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use tradr_core::{
    ACCOUNT_BROADCAST_KEY_LEN, AccountBroadcastKey, BroadcastKeyOffer, FIRST_KEY_GENERATION, Rng,
    RngError, SecretStore, SecretStoreError, StorageLevel, TrustTier, UnixTime,
};
use tradr_identity::broadcast_exchange::{ExchangeError, ExchangeOutcome, open};
use tradr_identity::{
    ACCOUNT_BROADCAST_KEY_SLOT, AccountId, BroadcastKeyRegistry, BroadcastKeyRegistryError,
};

const NOW: i64 = 1_756_684_800;
const LATER: i64 = 1_756_688_400;

// Each test gets a path of its own so nothing depends on execution order
// (rule E2), following the registry's own tests.
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("tradr-abx-{}-{n}.json", std::process::id()));
    let _remove = std::fs::remove_file(&path);
    path
}

// A path inside a directory that does not exist yet, so `load` reads it as
// the first run a missing file is, and `block` is what makes a later write
// fail without touching a permission bit.
fn blocked_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tradr-abx-blocked-{}-{n}", std::process::id()));
    let _remove_dir = std::fs::remove_dir_all(&dir);
    let _remove_file = std::fs::remove_file(&dir);
    dir.join("account-broadcast-key.json")
}

fn block(path: &Path) {
    let dir = path.parent().expect("a blocked path has a parent");
    std::fs::write(dir, b"not a directory").expect("the blocker is writable");
}

// Blocks a record that already exists, which `block` cannot: its directory is
// there by the time a key has been planted. A directory standing where the
// record goes fails the rename on every platform, where a regular file
// standing in for the parent would be read as `NotFound` on Windows.
fn block_existing_record(path: &Path) {
    std::fs::remove_file(path).expect("the record exists");
    std::fs::create_dir(path).expect("the scratch path is writable");
}

fn account(sub: &str) -> AccountId {
    AccountId::new("https://accounts.google.com", sub)
}

fn at(secs: i64) -> UnixTime {
    UnixTime::from_secs(secs)
}

fn filled(fill: u8) -> AccountBroadcastKey {
    AccountBroadcastKey::from_bytes(&[fill; ACCOUNT_BROADCAST_KEY_LEN]).expect("32 bytes is a key")
}

// The key, the generation it belongs to and when it was made travel
// together, so no test can pair one device's bytes with another's time.
fn key_offer(fill: u8, generation: u32, created_at: i64) -> BroadcastKeyOffer {
    BroadcastKeyOffer::new(filled(fill), generation, at(created_at)).expect("a well-formed offer")
}

// An `Rng` writing one pinned byte, so a drawn key is a value a test can
// name rather than a value it can only compare against a second call.
struct PinnedRng {
    fill: u8,
    calls: Cell<u8>,
    fail: bool,
}

impl PinnedRng {
    fn new(fill: u8) -> Self {
        Self {
            fill,
            calls: Cell::new(0),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            fill: 0,
            calls: Cell::new(0),
            fail: true,
        }
    }

    fn calls(&self) -> u8 {
        self.calls.get()
    }
}

impl Rng for PinnedRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        if self.fail {
            return Err(RngError::Source(Box::new(std::io::Error::other(
                "the entropy source refused",
            ))));
        }
        self.calls.set(self.calls.get().wrapping_add(1));
        buf.fill(self.fill);
        Ok(())
    }
}

// A `SecretStore` holding its slots in memory: no keyring, no D-Bus and no
// filesystem (rule B5). It counts writes, because what several tests below
// measure is that an exchange wrote at most once.
#[derive(Default)]
struct Vault {
    slots: RefCell<BTreeMap<String, Vec<u8>>>,
    stores: Cell<usize>,
}

impl Vault {
    fn held(&self) -> Option<Vec<u8>> {
        self.slots.borrow().get(ACCOUNT_BROADCAST_KEY_SLOT).cloned()
    }

    fn stores(&self) -> usize {
        self.stores.get()
    }
}

impl SecretStore for Vault {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        self.stores.set(self.stores.get() + 1);
        self.slots
            .borrow_mut()
            .insert(slot.to_string(), secret.to_vec());
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self.slots.borrow().get(slot).cloned())
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        self.slots.borrow_mut().remove(slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

fn load(path: &Path) -> BroadcastKeyRegistry {
    BroadcastKeyRegistry::load(path, &account("alice")).expect("this registry loads")
}

// Puts a device into the state of already holding a key, through the same
// `adopt` a real adoption uses, so no test reaches around the registry to
// arrange a state the registry itself could not produce.
fn holding(path: &Path, vault: &Vault, offer: &BroadcastKeyOffer) -> BroadcastKeyRegistry {
    let mut registry = load(path);
    registry
        .adopt(offer, vault)
        .expect("planting a key succeeds");
    registry
}

fn held_bytes(vault: &Vault) -> Vec<u8> {
    vault.held().expect("the slot holds a key")
}

// --- The tier gate: this device's own verdict, and never the peer's ---

#[test]
fn a_linked_channel_is_refused_and_nothing_is_drawn_for_it() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);
    let registry = load(&path);

    let err = open(TrustTier::Linked, &registry, &vault, &rng, at(NOW))
        .expect_err("a linked channel never carries the account broadcast key");

    assert!(
        matches!(
            err,
            ExchangeError::TierNotSameAccount {
                granted: TrustTier::Linked
            }
        ),
        "a linked channel was refused for the wrong reason: {err}"
    );
    assert_eq!(rng.calls(), 0, "a refused exchange drew entropy");
    assert!(vault.held().is_none(), "a refused exchange wrote a key");
}

#[test]
fn a_nearby_ephemeral_channel_is_refused() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);
    let registry = load(&path);

    let err = open(TrustTier::NearbyEphemeral, &registry, &vault, &rng, at(NOW))
        .expect_err("an unknown peer never carries the account broadcast key");

    assert!(
        matches!(
            err,
            ExchangeError::TierNotSameAccount {
                granted: TrustTier::NearbyEphemeral
            }
        ),
        "a nearby-ephemeral channel was refused for the wrong reason: {err}"
    );
}

#[test]
fn a_rejected_channel_is_refused() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);
    let registry = load(&path);

    let err = open(TrustTier::Rejected, &registry, &vault, &rng, at(NOW))
        .expect_err("a rejected peer never carries the account broadcast key");

    assert!(
        matches!(
            err,
            ExchangeError::TierNotSameAccount {
                granted: TrustTier::Rejected
            }
        ),
        "a rejected channel was refused for the wrong reason: {err}"
    );
}

#[test]
fn a_same_account_channel_opens_and_offers_a_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);
    let registry = load(&path);

    let (_state, ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW))
        .expect("a same-account channel carries the exchange");

    assert_eq!(ours.key().as_bytes(), filled(0x11).as_bytes());
}

// --- What `open` offers, and what it has not yet written ---

#[test]
fn a_device_holding_a_key_offers_that_key_and_draws_nothing() {
    let path = scratch_path();
    let vault = Vault::default();
    let registry = holding(&path, &vault, &key_offer(0x33, 4, NOW));
    let rng = PinnedRng::new(0x11);

    let (_state, ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    assert_eq!(
        ours.key().as_bytes(),
        filled(0x33).as_bytes(),
        "a device offered bytes other than the key it holds"
    );
    assert_eq!(ours.generation(), 4);
    assert_eq!(ours.created_at(), at(NOW));
    assert_eq!(rng.calls(), 0, "a device holding a key drew a new one");
}

#[test]
fn a_device_holding_no_key_draws_one_at_the_first_generation() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);
    let registry = load(&path);

    let (_state, ours) =
        open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW)).expect("the exchange opens");

    assert_eq!(ours.key().as_bytes(), filled(0x11).as_bytes());
    assert_eq!(ours.generation(), FIRST_KEY_GENERATION);
    assert_eq!(ours.created_at(), at(NOW));
    assert_eq!(rng.calls(), 1, "a draw read the entropy source twice");
}

#[test]
fn a_draw_is_not_persisted_before_the_order_has_run() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);
    let registry = load(&path);

    let (_state, _ours) =
        open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW)).expect("the exchange opens");

    assert!(
        vault.held().is_none(),
        "a drawn key reached the secret store before the peer's offer arrived"
    );
    assert!(
        !path.exists(),
        "a drawn key reached the record before the peer's offer arrived"
    );
}

// --- Silence ends the exchange and is never an adoption ---

#[test]
fn silence_after_a_draw_leaves_the_device_holding_no_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let rng = PinnedRng::new(0x11);

    {
        let registry = load(&path);
        let (_state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW))
            .expect("the exchange opens");
    }

    assert!(vault.held().is_none(), "silence persisted a drawn key");
    assert!(!path.exists(), "silence wrote a record");
    assert!(
        load(&path).generation().is_none(),
        "silence left the device claiming a key"
    );
}

#[test]
fn silence_leaves_a_stored_key_exactly_as_it_was() {
    let path = scratch_path();
    let vault = Vault::default();
    let registry = holding(&path, &vault, &key_offer(0x33, 4, NOW));
    let rng = PinnedRng::new(0x11);
    let writes_before = vault.stores();

    {
        let (_state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
            .expect("the exchange opens");
    }

    assert_eq!(held_bytes(&vault), filled(0x33).as_bytes().to_vec());
    assert_eq!(vault.stores(), writes_before, "silence wrote a key");
    let reloaded = load(&path);
    assert_eq!(reloaded.generation(), Some(4));
    assert_eq!(reloaded.created_at(), Some(at(NOW)));
}

// --- The three outcomes ---

#[test]
fn a_stored_key_that_wins_is_kept_and_nothing_is_written() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = holding(&path, &vault, &key_offer(0x33, 4, NOW));
    let rng = PinnedRng::new(0x11);
    let writes_before = vault.stores();
    let (state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    let outcome = state
        .on_peer_offer(key_offer(0x22, 2, NOW), &mut registry, &vault)
        .expect("a losing peer offer is not an error");

    assert_eq!(outcome, ExchangeOutcome::Kept);
    assert_eq!(
        vault.stores(),
        writes_before,
        "a kept key was written again"
    );
    assert_eq!(held_bytes(&vault), filled(0x33).as_bytes().to_vec());
    assert_eq!(registry.generation(), Some(4));
}

#[test]
fn a_drawn_key_that_wins_is_generated_and_both_halves_are_written() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path);
    let rng = PinnedRng::new(0x11);
    let (state, _ours) =
        open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW)).expect("the exchange opens");

    let outcome = state
        .on_peer_offer(
            key_offer(0x22, FIRST_KEY_GENERATION, LATER),
            &mut registry,
            &vault,
        )
        .expect("a losing peer offer is not an error");

    assert_eq!(outcome, ExchangeOutcome::Generated);
    assert_eq!(vault.stores(), 1, "a generation wrote more than once");
    assert_eq!(held_bytes(&vault), filled(0x11).as_bytes().to_vec());
    let reloaded = load(&path);
    assert_eq!(reloaded.generation(), Some(FIRST_KEY_GENERATION));
    assert_eq!(reloaded.created_at(), Some(at(NOW)));
}

#[test]
fn a_peer_key_beating_a_draw_is_adopted_with_the_peers_own_generation() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path);
    let rng = PinnedRng::new(0x11);
    let (state, _ours) =
        open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW)).expect("the exchange opens");

    let outcome = state
        .on_peer_offer(key_offer(0x22, 7, LATER), &mut registry, &vault)
        .expect("adopting a winning peer key succeeds");

    assert_eq!(outcome, ExchangeOutcome::Adopted);
    assert_eq!(vault.stores(), 1, "an adoption wrote more than once");
    assert_eq!(held_bytes(&vault), filled(0x22).as_bytes().to_vec());
    let reloaded = load(&path);
    assert_eq!(
        reloaded.generation(),
        Some(7),
        "an adopted key was recorded under a generation of this device's own"
    );
    assert_eq!(reloaded.created_at(), Some(at(LATER)));
}

#[test]
fn a_peer_key_beating_a_stored_key_replaces_both_halves() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = holding(&path, &vault, &key_offer(0x33, 4, NOW));
    let rng = PinnedRng::new(0x11);
    let writes_before = vault.stores();
    let (state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    let outcome = state
        .on_peer_offer(key_offer(0x22, 5, NOW), &mut registry, &vault)
        .expect("adopting a winning peer key succeeds");

    assert_eq!(outcome, ExchangeOutcome::Adopted);
    assert_eq!(vault.stores(), writes_before + 1);
    assert_eq!(held_bytes(&vault), filled(0x22).as_bytes().to_vec());
    let reloaded = load(&path);
    assert_eq!(reloaded.generation(), Some(5));
    assert_eq!(reloaded.created_at(), Some(at(NOW)));
}

// --- The order DCR-090 settled, seen from the driver rather than the rule ---

#[test]
fn a_rotation_reaches_a_device_that_missed_it() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = holding(&path, &vault, &key_offer(0x33, 1, NOW));
    let rng = PinnedRng::new(0x11);
    let (state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    let outcome = state
        .on_peer_offer(key_offer(0x22, 2, LATER), &mut registry, &vault)
        .expect("adopting a rotation succeeds");

    assert_eq!(
        outcome,
        ExchangeOutcome::Adopted,
        "a rotation lost to the key it existed to replace"
    );
    assert_eq!(held_bytes(&vault), filled(0x22).as_bytes().to_vec());
}

#[test]
fn a_newly_joined_devices_draw_does_not_displace_an_established_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = holding(&path, &vault, &key_offer(0x33, FIRST_KEY_GENERATION, NOW));
    let rng = PinnedRng::new(0x11);
    let (state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    let outcome = state
        .on_peer_offer(
            key_offer(0x22, FIRST_KEY_GENERATION, LATER),
            &mut registry,
            &vault,
        )
        .expect("a newer draw is not an error");

    assert_eq!(
        outcome,
        ExchangeOutcome::Kept,
        "a device that had just joined replaced the account's key"
    );
    assert_eq!(held_bytes(&vault), filled(0x33).as_bytes().to_vec());
}

#[test]
fn a_newly_joined_device_adopts_the_established_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = load(&path);
    let rng = PinnedRng::new(0x11);
    let (state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    let outcome = state
        .on_peer_offer(
            key_offer(0x22, FIRST_KEY_GENERATION, NOW),
            &mut registry,
            &vault,
        )
        .expect("adopting the account's key succeeds");

    assert_eq!(outcome, ExchangeOutcome::Adopted);
    assert_eq!(held_bytes(&vault), filled(0x22).as_bytes().to_vec());
}

// --- Convergence: the property, and never an encoding of who won ---

// Runs one side of a meeting to completion and reports what it ended up
// holding, so a convergence test asserts that both sides hold one key
// rather than that each reached a particular outcome.
fn meet(
    path: &Path,
    vault: &Vault,
    planted: Option<BroadcastKeyOffer>,
    fill: u8,
    now: i64,
    peer: BroadcastKeyOffer,
) -> (Vec<u8>, Option<u32>, Option<UnixTime>) {
    let mut registry = match planted {
        Some(offer) => holding(path, vault, &offer),
        None => load(path),
    };
    let rng = PinnedRng::new(fill);
    let (state, _ours) =
        open(TrustTier::SameAccount, &registry, vault, &rng, at(now)).expect("the exchange opens");
    state
        .on_peer_offer(peer, &mut registry, vault)
        .expect("a meeting completes");
    let reloaded = load(path);
    (
        held_bytes(vault),
        reloaded.generation(),
        reloaded.created_at(),
    )
}

#[test]
fn two_devices_that_both_draw_end_up_holding_the_same_key() {
    let alice_path = scratch_path();
    let bob_path = scratch_path();
    let alice_vault = Vault::default();
    let bob_vault = Vault::default();

    let alice = meet(
        &alice_path,
        &alice_vault,
        None,
        0x11,
        NOW,
        key_offer(0x22, FIRST_KEY_GENERATION, NOW),
    );
    let bob = meet(
        &bob_path,
        &bob_vault,
        None,
        0x22,
        NOW,
        key_offer(0x11, FIRST_KEY_GENERATION, NOW),
    );

    assert_eq!(alice, bob, "two devices that met hold different keys");
}

#[test]
fn a_meeting_between_an_established_device_and_a_new_one_converges() {
    let alice_path = scratch_path();
    let bob_path = scratch_path();
    let alice_vault = Vault::default();
    let bob_vault = Vault::default();
    let established = key_offer(0x33, FIRST_KEY_GENERATION, NOW);

    let alice = meet(
        &alice_path,
        &alice_vault,
        Some(established),
        0x11,
        LATER,
        key_offer(0x11, FIRST_KEY_GENERATION, LATER),
    );
    let bob = meet(
        &bob_path,
        &bob_vault,
        None,
        0x11,
        LATER,
        key_offer(0x33, FIRST_KEY_GENERATION, NOW),
    );

    assert_eq!(
        alice, bob,
        "the new device and the established one diverged"
    );
    assert_eq!(alice.0, filled(0x33).as_bytes().to_vec());
}

#[test]
fn a_meeting_across_a_rotation_converges_on_the_rotation() {
    let alice_path = scratch_path();
    let bob_path = scratch_path();
    let alice_vault = Vault::default();
    let bob_vault = Vault::default();

    let alice = meet(
        &alice_path,
        &alice_vault,
        Some(key_offer(0x33, 1, NOW)),
        0x11,
        LATER,
        key_offer(0x22, 2, LATER),
    );
    let bob = meet(
        &bob_path,
        &bob_vault,
        Some(key_offer(0x22, 2, LATER)),
        0x11,
        LATER,
        key_offer(0x33, 1, NOW),
    );

    assert_eq!(alice, bob, "a rotation left the two sides disagreeing");
    assert_eq!(alice.0, filled(0x22).as_bytes().to_vec());
}

// --- What the exchange refuses, and what a failure leaves behind ---

#[test]
fn a_record_whose_slot_is_empty_refuses_the_exchange_and_draws_nothing() {
    let path = scratch_path();
    let vault = Vault::default();
    let registry = holding(&path, &vault, &key_offer(0x33, 4, NOW));
    vault
        .remove(ACCOUNT_BROADCAST_KEY_SLOT)
        .expect("the vault empties");
    let rng = PinnedRng::new(0x11);

    let err = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect_err("a record with no key behind it is not a first run");

    assert!(
        matches!(
            err,
            ExchangeError::Registry(BroadcastKeyRegistryError::SecretMissing)
        ),
        "a half-written key was refused for the wrong reason: {err}"
    );
    assert_eq!(
        rng.calls(),
        0,
        "a failed generation was read as a first run"
    );
}

#[test]
fn an_entropy_failure_refuses_the_exchange_and_writes_nothing() {
    let path = scratch_path();
    let vault = Vault::default();
    let registry = load(&path);
    let rng = PinnedRng::failing();

    let err = open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW))
        .expect_err("a draw that cannot be made is not an exchange");

    assert!(
        matches!(
            err,
            ExchangeError::Registry(BroadcastKeyRegistryError::Rng(_))
        ),
        "an entropy failure was reported as something else: {err}"
    );
    assert!(vault.held().is_none(), "a failed draw wrote a key");
}

#[test]
fn an_adoption_whose_record_cannot_be_written_restores_the_previous_key() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = holding(&path, &vault, &key_offer(0x33, 4, NOW));
    block_existing_record(&path);
    let rng = PinnedRng::new(0x11);
    let (state, _ours) = open(TrustTier::SameAccount, &registry, &vault, &rng, at(LATER))
        .expect("the exchange opens");

    let err = state
        .on_peer_offer(key_offer(0x22, 9, LATER), &mut registry, &vault)
        .expect_err("a record that cannot be written fails the adoption");

    assert!(
        matches!(err, ExchangeError::Registry(_)),
        "a failed adoption was reported as something else: {err}"
    );
    assert_eq!(
        held_bytes(&vault),
        filled(0x33).as_bytes().to_vec(),
        "a failed adoption left the previous key discarded"
    );
    let _cleanup = std::fs::remove_dir_all(&path);
}

#[test]
fn a_generation_whose_record_cannot_be_written_leaves_no_key_behind() {
    let path = blocked_path();
    let vault = Vault::default();
    let mut registry = load(&path);
    block(&path);
    let rng = PinnedRng::new(0x11);
    let (state, _ours) =
        open(TrustTier::SameAccount, &registry, &vault, &rng, at(NOW)).expect("the exchange opens");

    let err = state
        .on_peer_offer(
            key_offer(0x22, FIRST_KEY_GENERATION, LATER),
            &mut registry,
            &vault,
        )
        .expect_err("a record that cannot be written fails the generation");

    assert!(
        matches!(err, ExchangeError::Registry(_)),
        "a failed generation was reported as something else: {err}"
    );
    assert!(
        vault.held().is_none(),
        "a failed generation left a key nothing records"
    );
    let _cleanup = std::fs::remove_file(path.parent().expect("a blocked path has a parent"));
}

//! Supervisor-authored tests for the Link derivations and the Link
//! registry, written before the implementation. A Critical Module
//! (CLAUDE.md section 6): `linked_accounts` is what docs/05 step 6 reads,
//! so a registry naming an account nobody linked hands `TrustTier::Linked`
//! to a stranger, and every signature that stranger makes is valid.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use tradr_core::{
    DeviceId, HalfSecret, LinkId, LinkSecret, PublicIdentity, PublicKeyPoint, SecretStore,
    SecretStoreError, StorageLevel, TrustTier, UnixTime,
};
use tradr_identity::{
    AccountId, AttestationError, AttestationPolicy, Link, LinkRegistry, LinkRegistryError,
    NonceBinding, ProviderProfile, SignatureAlgorithm, VerifiedClaims, attestation_nonce, classify,
    derive_link_id, derive_link_secret, device_fingerprint, link_secret_slot,
};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

// Each test gets a path of its own so nothing depends on execution order
// (rule E2), following `tradr-discovery`'s static peer tests.
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("tradr-links-{}-{n}.json", std::process::id()));
    let _remove = std::fs::remove_file(&path);
    path
}

// A path inside a directory that does not exist yet, so a test can plant
// something in the directory's place and make the registry's own write
// fail without touching any permission bit.
fn scratch_path_in_new_dir() -> (PathBuf, PathBuf) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tradr-links-dir-{}-{n}", std::process::id()));
    let _remove_dir = std::fs::remove_dir_all(&dir);
    let _remove_file = std::fs::remove_file(&dir);
    let path = dir.join("links.json");
    (dir, path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// The two halves the known-answer vectors below were computed over.
fn half_a() -> HalfSecret {
    let bytes: [u8; 16] = std::array::from_fn(|i| i as u8);
    HalfSecret::from_bytes(&bytes).expect("16 bytes is a half secret")
}

fn half_b() -> HalfSecret {
    let bytes: [u8; 16] = std::array::from_fn(|i| (i + 16) as u8);
    HalfSecret::from_bytes(&bytes).expect("16 bytes is a half secret")
}

// An uncompressed point filled with a fixed pattern. Nothing here does
// curve arithmetic, so the bytes need only be the right length.
fn point(first: u8) -> PublicKeyPoint {
    let mut bytes = [0x04u8; 65];
    for (i, byte) in bytes.iter_mut().enumerate().skip(1) {
        *byte = first.wrapping_add(i as u8).wrapping_sub(1);
    }
    PublicKeyPoint::from_bytes(&bytes).expect("65 bytes is a point")
}

fn link_id(byte: u8) -> LinkId {
    LinkId::from_bytes(&[byte; 16]).expect("16 bytes is a link id")
}

// A Link Secret nothing derived, standing in for one the exchange would
// have derived. Every Link below is built from one of these, because
// `add` refuses a secret that does not derive the Link's own id.
fn secret(byte: u8) -> LinkSecret {
    LinkSecret::from_bytes(&[byte; 32]).expect("32 bytes is a link secret")
}

fn a_link(secret: &LinkSecret, sub: &str) -> Link {
    Link::new(
        derive_link_id(secret),
        account(sub),
        UnixTime::from_secs(NOW),
    )
}

fn account(sub: &str) -> AccountId {
    AccountId::new("https://accounts.google.com", sub)
}

// A `SecretStore` holding its slots in memory: no keyring, no D-Bus and
// no filesystem, so the registry's two halves can be driven apart (rule
// B5). It counts what it was asked to do and can be told to fail one
// operation, since what these tests measure is which half moved first.
#[derive(Default)]
struct Vault {
    slots: RefCell<BTreeMap<String, Vec<u8>>>,
    stores: Cell<usize>,
    removes: Cell<usize>,
    fail_store: bool,
    fail_remove: bool,
}

impl Vault {
    fn failing_to_store() -> Self {
        Self {
            fail_store: true,
            ..Self::default()
        }
    }

    fn failing_to_remove() -> Self {
        Self {
            fail_remove: true,
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
        if self.fail_store {
            return Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                "the vault refused to write",
            ))));
        }
        self.stores.set(self.stores.get() + 1);
        self.plant(slot, secret);
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
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

// --- The derivations: what DCR-066 and docs/05 fixed, pinned by value ---

#[test]
fn the_link_secret_is_blake3_derive_key_over_the_two_halves_in_role_order() {
    let secret = derive_link_secret(&half_a(), &half_b());

    assert_eq!(
        hex(secret.as_bytes()),
        "a328adf0b78a794d25c1486355eadc97c5fa055f25d32ae3ec4737cee665643b"
    );
}

#[test]
fn swapping_the_two_halves_derives_a_different_link_secret() {
    // DCR-066: the order is by role and never by value, so sorting the
    // halves would let one side try both orders against a target.
    let swapped = derive_link_secret(&half_b(), &half_a());

    assert_eq!(
        hex(swapped.as_bytes()),
        "88dd0e457c461791685f94b5e1782e42900ded61744e93bec9fd0fd5207f6cff"
    );
}

#[test]
fn the_link_id_is_the_leading_sixteen_bytes_of_blake3_over_the_link_secret() {
    let secret = derive_link_secret(&half_a(), &half_b());

    assert_eq!(
        derive_link_id(&secret).to_string(),
        "bcf855c730aea218c9a46a6328b4a386"
    );
}

#[test]
fn two_all_zero_halves_still_derive_the_documented_value() {
    let zero = HalfSecret::from_bytes(&[0u8; 16]).expect("16 bytes is a half secret");

    let secret = derive_link_secret(&zero, &zero);

    assert_eq!(
        hex(secret.as_bytes()),
        "b8542738a494835510166bc4c48607cbce07ebba3286902e45f89fe0ed2a3e2d"
    );
    assert_eq!(
        derive_link_id(&secret).to_string(),
        "637c9b1d5fb84465cadb6d10317d4c0f"
    );
}

#[test]
fn the_fingerprint_is_blake3_over_the_tag_and_both_keys_in_that_order() {
    // docs/05: BLAKE3("tradr-fp-v1" || identity_pub || agreement_pub).
    let fingerprint = device_fingerprint(&point(0x01), &point(0x41));

    assert_eq!(
        fingerprint.to_string(),
        "rice flower online hire glide only issue excuse crisp bless various beauty"
    );
}

#[test]
fn swapping_the_two_keys_renders_a_different_fingerprint() {
    let swapped = device_fingerprint(&point(0x41), &point(0x01));

    assert_eq!(
        swapped.to_string(),
        "wealth bright custom odor place century soccer isolate rural spare matter peasant"
    );
}

// --- linked_accounts: the value docs/05 step 6 reads ---

#[test]
fn a_registry_with_no_file_is_empty_and_links_nobody() {
    let path = scratch_path();

    let registry = LinkRegistry::load(&path).expect("a missing file loads as an empty registry");

    assert!(registry.links().is_empty());
    assert!(registry.linked_accounts().is_empty());
}

#[test]
fn linked_accounts_names_exactly_the_account_that_was_linked() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    assert_eq!(registry.linked_accounts(), vec![account("bob-subject")]);
}

#[test]
fn a_matching_sub_under_a_different_issuer_is_not_a_linked_account() {
    // ADR-0010: `sub` is unique only within an issuer, so the pair is what
    // identity means and never `sub` alone.
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let elsewhere = AccountId::new("https://login.example.test", "bob-subject");
    assert!(!registry.linked_accounts().contains(&elsewhere));
}

#[test]
fn two_links_to_different_accounts_both_appear() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    registry
        .add(
            a_link(&secret(0x02), "carol-subject"),
            &secret(0x02),
            &vault,
        )
        .expect("a second account is accepted");

    let accounts = registry.linked_accounts();
    assert!(accounts.contains(&account("bob-subject")));
    assert!(accounts.contains(&account("carol-subject")));
    assert_eq!(accounts.len(), 2);
}

// --- Removal, which is what M6's completion criterion measures ---

#[test]
fn removal_takes_the_account_out_of_linked_accounts_at_once() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    registry
        .remove(&derive_link_id(&secret(0x01)), &vault)
        .expect("a known link removes");

    assert!(registry.linked_accounts().is_empty());
    assert!(registry.links().is_empty());
    assert!(registry.link(&derive_link_id(&secret(0x01))).is_none());
}

#[test]
fn a_removal_survives_a_reload_from_disk() {
    let path = scratch_path();
    let vault = Vault::default();
    {
        let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
        registry
            .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
            .expect("a first link is accepted");
        registry
            .remove(&derive_link_id(&secret(0x01)), &vault)
            .expect("a known link removes");
    }

    let reloaded = LinkRegistry::load(&path).expect("the written file loads");

    assert!(reloaded.linked_accounts().is_empty());
}

#[test]
fn removing_a_link_this_registry_does_not_hold_is_refused_and_changes_nothing() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let result = registry.remove(&link_id(0xff), &vault);

    assert!(matches!(result, Err(LinkRegistryError::UnknownLink)));
    assert_eq!(registry.linked_accounts(), vec![account("bob-subject")]);
    assert_eq!(vault.removes(), 0);
}

// --- The Link Secret, and the order the two halves move in (DCR-070) ---

#[test]
fn adding_a_link_stores_its_secret_under_the_slot_the_link_id_names() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let slot = link_secret_slot(&derive_link_id(&secret(0x01)));
    assert_eq!(slot, format!("link-{}", derive_link_id(&secret(0x01))));
    assert_eq!(
        vault.held(&slot).as_deref(),
        Some(&secret(0x01).as_bytes()[..])
    );
}

#[test]
fn the_stored_link_secret_comes_back_byte_identical() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x05), "bob-subject"), &secret(0x05), &vault)
        .expect("a first link is accepted");

    let loaded = registry
        .link_secret(&derive_link_id(&secret(0x05)), &vault)
        .expect("a stored secret loads");

    // Compared through `as_bytes`, because `LinkSecret` declines
    // `PartialEq` on purpose and a test is not a reason to give it one.
    assert_eq!(
        loaded.map(|held| hex(held.as_bytes())),
        Some(hex(secret(0x05).as_bytes()))
    );
}

#[test]
fn a_link_secret_this_registry_holds_no_link_for_is_refused() {
    let path = scratch_path();
    let vault = Vault::default();
    let registry = LinkRegistry::load(&path).expect("a missing file loads");

    let result = registry.link_secret(&link_id(0xff), &vault);

    assert!(matches!(result, Err(LinkRegistryError::UnknownLink)));
}

#[test]
fn a_stored_secret_of_the_wrong_length_is_malformed_rather_than_ignored() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x06), "bob-subject"), &secret(0x06), &vault)
        .expect("a first link is accepted");
    vault.plant(&link_secret_slot(&derive_link_id(&secret(0x06))), b"short");

    let result = registry.link_secret(&derive_link_id(&secret(0x06)), &vault);

    assert!(matches!(result, Err(LinkRegistryError::Malformed(_))));
}

#[test]
fn removing_a_link_discards_its_secret() {
    // docs/11, "Removing a link": the sentence that was true as design and
    // false as code until the registry performed both halves itself.
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    let slot = link_secret_slot(&derive_link_id(&secret(0x01)));

    registry
        .remove(&derive_link_id(&secret(0x01)), &vault)
        .expect("a known link removes");

    assert_eq!(vault.held(&slot), None);
}

#[test]
fn removing_one_link_leaves_another_links_secret_alone() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    registry
        .add(
            a_link(&secret(0x02), "carol-subject"),
            &secret(0x02),
            &vault,
        )
        .expect("a second account is accepted");

    registry
        .remove(&derive_link_id(&secret(0x01)), &vault)
        .expect("a known link removes");

    let kept = link_secret_slot(&derive_link_id(&secret(0x02)));
    assert_eq!(
        vault.held(&kept).as_deref(),
        Some(&secret(0x02).as_bytes()[..])
    );
}

#[test]
fn a_secret_that_does_not_derive_the_links_own_id_is_refused_and_changes_nothing() {
    // DCR-070: the slot is addressed by the `link_id`, so a mismatched
    // pair would put the secret under a name nothing could find it by.
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let result = registry.add(a_link(&secret(0x01), "bob-subject"), &secret(0x02), &vault);

    assert!(matches!(result, Err(LinkRegistryError::SecretMismatch)));
    assert!(registry.links().is_empty());
    assert_eq!(vault.stores(), 0);
    assert!(!path.exists());
}

#[test]
fn a_secret_store_that_cannot_write_refuses_the_add_and_writes_no_record() {
    // The secret moves first, so a store that fails leaves nothing at all:
    // no record, and therefore no Link that can never acquire a secret.
    let path = scratch_path();
    let vault = Vault::failing_to_store();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let result = registry.add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault);

    assert!(matches!(result, Err(LinkRegistryError::Secret(_))));
    assert!(registry.links().is_empty());
    assert!(!path.exists());
}

#[test]
fn a_secret_store_that_cannot_discard_refuses_the_removal_and_keeps_the_record() {
    // The sharpest ordering test: were the record written first, the
    // account would already be out of `linked_accounts` by the time the
    // discard failed, and the slot would be unreachable forever.
    let path = scratch_path();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(
            a_link(&secret(0x01), "bob-subject"),
            &secret(0x01),
            &Vault::default(),
        )
        .expect("a first link is accepted");

    let result = registry.remove(&derive_link_id(&secret(0x01)), &Vault::failing_to_remove());

    assert!(matches!(result, Err(LinkRegistryError::Secret(_))));
    assert_eq!(registry.linked_accounts(), vec![account("bob-subject")]);

    let reloaded = LinkRegistry::load(&path).expect("the written file loads");
    assert_eq!(reloaded.links().len(), 1);
}

#[test]
fn an_add_whose_record_cannot_be_written_takes_its_secret_back_down() {
    // DCR-070: a refused `add` leaves nothing behind, so the rollback runs
    // and the slot it just wrote is empty again. The first add is what
    // makes the second one fail on the record write itself rather than on
    // the directory beneath it, which is what this name claims.
    let (dir, path) = scratch_path_in_new_dir();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    std::fs::remove_file(&path).expect("the registry file is removable");
    std::fs::create_dir(&path).expect("a directory can take the file's place");

    let result = registry.add(
        a_link(&secret(0x02), "carol-subject"),
        &secret(0x02),
        &vault,
    );

    assert!(matches!(result, Err(LinkRegistryError::Io(_))));
    assert_eq!(
        vault.held(&link_secret_slot(&derive_link_id(&secret(0x02)))),
        None
    );
    assert_eq!(registry.links().len(), 1);

    let _cleanup = std::fs::remove_dir_all(&dir);
}

// Rule F6, and the only reason `SecretRollbackFailed` exists: a rollback
// that itself fails must be reported beside the failure that caused it,
// never discarded so that only the first is reported.
#[test]
fn a_rollback_that_also_fails_carries_both_errors_and_says_so() {
    let (dir, path) = scratch_path_in_new_dir();
    let vault = Vault::failing_to_remove();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    std::fs::remove_file(&path).expect("the registry file is removable");
    std::fs::create_dir(&path).expect("a directory can take the file's place");

    let result = registry.add(
        a_link(&secret(0x02), "carol-subject"),
        &secret(0x02),
        &vault,
    );

    let Err(error) = result else {
        panic!("a record write onto a directory should not succeed");
    };
    assert!(matches!(
        error,
        LinkRegistryError::SecretRollbackFailed { .. }
    ));

    // Both halves reach the message, so neither is carried and then lost.
    let rendered = error.to_string();
    assert!(rendered.contains("link registry i/o error"), "{rendered}");
    assert!(
        rendered.contains("the vault refused to discard"),
        "{rendered}"
    );

    // The orphaned secret is the state this variant exists to report.
    let orphan = link_secret_slot(&derive_link_id(&secret(0x02)));
    assert!(vault.held(&orphan).is_some());
    assert_eq!(registry.links().len(), 1);

    let _cleanup = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_removal_whose_record_cannot_be_written_reports_it_and_keeps_the_link_addressable() {
    // The accepted intermediate state DCR-070 names: the secret is gone,
    // the record still names the slot, and the repair is the same call
    // again, which an idempotent `remove` accepts.
    let (dir, path) = scratch_path_in_new_dir();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    std::fs::remove_file(&path).expect("the registry file is removable");
    std::fs::create_dir(&path).expect("a directory can take the file's place");
    let result = registry.remove(&derive_link_id(&secret(0x01)), &vault);

    assert!(matches!(result, Err(LinkRegistryError::Io(_))));
    assert_eq!(
        vault.held(&link_secret_slot(&derive_link_id(&secret(0x01)))),
        None
    );
    assert!(registry.link(&derive_link_id(&secret(0x01))).is_some());

    let _cleanup = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_record_whose_secret_is_gone_reads_as_empty_rather_than_an_error() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    vault
        .remove(&link_secret_slot(&derive_link_id(&secret(0x01))))
        .expect("the vault discards");

    let loaded = registry.link_secret(&derive_link_id(&secret(0x01)), &vault);

    assert!(matches!(loaded, Ok(None)));
}

#[test]
fn a_refused_duplicate_never_reaches_the_secret_store() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let result = registry.add(a_link(&secret(0x02), "bob-subject"), &secret(0x02), &vault);

    assert!(matches!(
        result,
        Err(LinkRegistryError::AccountAlreadyLinked)
    ));
    assert_eq!(vault.stores(), 1);
}

// --- Persistence: the shape DCR-069 fixed, and the round trip ---

#[test]
fn every_field_of_a_link_survives_a_reload_from_disk() {
    let path = scratch_path();
    let vault = Vault::default();
    let stored = a_link(&secret(0x07), "bob-subject")
        .with_label("Bob")
        .with_fingerprint_verified(true);
    {
        let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
        registry
            .add(stored.clone(), &secret(0x07), &vault)
            .expect("a first link is accepted");
    }

    let reloaded = LinkRegistry::load(&path).expect("the written file loads");

    assert_eq!(reloaded.link(&derive_link_id(&secret(0x07))), Some(&stored));
}

#[test]
fn a_link_with_no_label_reloads_without_one() {
    let path = scratch_path();
    let vault = Vault::default();
    let stored = a_link(&secret(0x08), "bob-subject");
    {
        let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
        registry
            .add(stored.clone(), &secret(0x08), &vault)
            .expect("a first link is accepted");
    }

    let reloaded = LinkRegistry::load(&path).expect("the written file loads");

    assert_eq!(reloaded.link(&derive_link_id(&secret(0x08))), Some(&stored));
    assert_eq!(
        reloaded
            .link(&derive_link_id(&secret(0x08)))
            .and_then(|link| link.peer_label()),
        None
    );
}

#[test]
fn the_file_carries_the_six_fields_dcr_069_names_and_a_numeric_created_at() {
    let path = scratch_path();
    let vault = Vault::default();
    {
        let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
        registry
            .add(
                a_link(&secret(0x09), "bob-subject").with_label("Bob"),
                &secret(0x09),
                &vault,
            )
            .expect("a first link is accepted");
    }

    let raw = std::fs::read(&path).expect("add wrote the registry file");
    let parsed: serde_json::Value = serde_json::from_slice(&raw).expect("the file is json");
    let record = &parsed["links"][0];

    assert_eq!(record["link_id"], derive_link_id(&secret(0x09)).to_string());
    assert_eq!(record["peer_iss"], "https://accounts.google.com");
    assert_eq!(record["peer_sub"], "bob-subject");
    assert_eq!(record["peer_label"], "Bob");
    assert_eq!(record["created_at"], serde_json::json!(NOW));
    assert_eq!(record["fingerprint_verified"], serde_json::json!(false));
}

#[test]
fn the_file_never_carries_the_link_secret() {
    // docs/11: the Link Secret is in the OS key store and never in this
    // file, which is what makes `links.json` a file a reader may see.
    let path = scratch_path();
    let vault = Vault::default();
    {
        let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
        registry
            .add(a_link(&secret(0x0b), "bob-subject"), &secret(0x0b), &vault)
            .expect("a first link is accepted");
    }

    let raw = std::fs::read(&path).expect("add wrote the registry file");

    assert!(!raw.windows(32).any(|w| w == secret(0x0b).as_bytes()));
    assert!(!String::from_utf8_lossy(&raw).contains(&hex(secret(0x0b).as_bytes())));
}

#[test]
fn marking_a_fingerprint_verified_survives_a_reload() {
    let path = scratch_path();
    let vault = Vault::default();
    {
        let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
        registry
            .add(a_link(&secret(0x0a), "bob-subject"), &secret(0x0a), &vault)
            .expect("a first link is accepted");
        registry
            .set_fingerprint_verified(&derive_link_id(&secret(0x0a)), true)
            .expect("a known link is markable");
    }

    let reloaded = LinkRegistry::load(&path).expect("the written file loads");

    assert_eq!(
        reloaded
            .link(&derive_link_id(&secret(0x0a)))
            .map(Link::fingerprint_verified),
        Some(true)
    );
}

#[test]
fn marking_a_link_this_registry_does_not_hold_is_refused() {
    let path = scratch_path();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let result = registry.set_fingerprint_verified(&link_id(0xff), true);

    assert!(matches!(result, Err(LinkRegistryError::UnknownLink)));
}

// --- What the registry refuses ---

#[test]
fn a_second_link_to_an_already_linked_account_is_refused_and_changes_nothing() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let result = registry.add(a_link(&secret(0x02), "bob-subject"), &secret(0x02), &vault);

    assert!(matches!(
        result,
        Err(LinkRegistryError::AccountAlreadyLinked)
    ));
    assert_eq!(registry.links().len(), 1);
    assert!(registry.link(&derive_link_id(&secret(0x02))).is_none());
}

#[test]
fn a_duplicate_link_id_is_refused_and_changes_nothing() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let same_id = Link::new(
        derive_link_id(&secret(0x01)),
        account("carol-subject"),
        UnixTime::from_secs(NOW),
    );
    let result = registry.add(same_id, &secret(0x01), &vault);

    assert!(matches!(result, Err(LinkRegistryError::DuplicateLinkId)));
    assert_eq!(registry.links().len(), 1);
    assert!(
        !registry
            .linked_accounts()
            .contains(&account("carol-subject"))
    );
}

#[test]
fn a_refused_add_leaves_the_file_alone() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    let refused = registry.add(a_link(&secret(0x02), "bob-subject"), &secret(0x02), &vault);
    assert!(refused.is_err());

    let reloaded = LinkRegistry::load(&path).expect("the written file loads");
    assert_eq!(reloaded.links().len(), 1);
}

#[test]
fn a_file_that_is_not_json_is_refused_rather_than_read_as_empty() {
    // DCR-069: an emptied Link registry withdraws Linked from every peer
    // at once, and reads to the user as every link having been removed.
    let path = scratch_path();
    std::fs::write(&path, b"this is not json").expect("the scratch file is writable");

    let result = LinkRegistry::load(&path);

    assert!(matches!(result, Err(LinkRegistryError::Malformed(_))));
}

#[test]
fn a_record_whose_link_id_is_not_hex_is_refused_rather_than_skipped() {
    let path = scratch_path();
    std::fs::write(
        &path,
        br#"{"links":[{"link_id":"not-hex","peer_iss":"https://accounts.google.com",
             "peer_sub":"bob-subject","peer_label":null,"created_at":1800000000,
             "fingerprint_verified":false}]}"#,
    )
    .expect("the scratch file is writable");

    let result = LinkRegistry::load(&path);

    assert!(matches!(result, Err(LinkRegistryError::Malformed(_))));
}

#[test]
fn a_file_naming_one_account_twice_is_refused() {
    let path = scratch_path();
    std::fs::write(
        &path,
        br#"{"links":[
             {"link_id":"01010101010101010101010101010101",
              "peer_iss":"https://accounts.google.com","peer_sub":"bob-subject",
              "peer_label":null,"created_at":1800000000,"fingerprint_verified":false},
             {"link_id":"02020202020202020202020202020202",
              "peer_iss":"https://accounts.google.com","peer_sub":"bob-subject",
              "peer_label":null,"created_at":1800000000,"fingerprint_verified":false}]}"#,
    )
    .expect("the scratch file is writable");

    let result = LinkRegistry::load(&path);

    assert!(matches!(result, Err(LinkRegistryError::Malformed(_))));
}

#[test]
fn a_file_naming_one_link_id_twice_is_refused() {
    let path = scratch_path();
    std::fs::write(
        &path,
        br#"{"links":[
             {"link_id":"01010101010101010101010101010101",
              "peer_iss":"https://accounts.google.com","peer_sub":"bob-subject",
              "peer_label":null,"created_at":1800000000,"fingerprint_verified":false},
             {"link_id":"01010101010101010101010101010101",
              "peer_iss":"https://accounts.google.com","peer_sub":"carol-subject",
              "peer_label":null,"created_at":1800000000,"fingerprint_verified":false}]}"#,
    )
    .expect("the scratch file is writable");

    let result = LinkRegistry::load(&path);

    assert!(matches!(result, Err(LinkRegistryError::Malformed(_))));
}

// --- The join: the registry is what decides step 6, end to end ---

fn google_profile() -> ProviderProfile {
    ProviderProfile {
        client_id: "test-client".to_string(),
        client_secret: None,
        authorization_uri: "https://accounts.google.com/o/oauth2/auth".to_string(),
        token_uri: "https://oauth2.googleapis.com/token".to_string(),
        issuer: "https://accounts.google.com".to_string(),
        client_ids: vec!["desktop-client.apps.googleusercontent.com".to_string()],
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
        jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
    }
}

// The two keys every classification below binds its nonce to. The
// `DeviceId` decorates: `classify` is handed the keys directly and the key
// join lives in `verify_attestation`, one layer above.
fn peer_identity() -> PublicIdentity {
    PublicIdentity::new(
        point(0x11),
        point(0x22),
        DeviceId::from_bytes(&[0x33; 16]).expect("16 bytes is a Device ID"),
    )
}

// Runs docs/05's steps 1 and 3 through 6 for a peer on `sub`, against
// whatever `linked_accounts` the registry currently reports.
fn tier_for(registry: &LinkRegistry, sub: &str) -> Result<TrustTier, AttestationError> {
    let identity = point(0x11);
    let agreement = point(0x22);
    let profiles = vec![google_profile()];
    let own = account("our-own-subject");
    let linked = registry.linked_accounts();
    let policy = AttestationPolicy {
        profiles: &profiles,
        own_account: &own,
        linked_accounts: &linked,
        staleness_limit_secs: (30 * DAY) as u64,
        future_skew_limit_secs: 300,
        ephemeral_receive: false,
    };
    let claims = VerifiedClaims {
        iss: "https://accounts.google.com".to_string(),
        sub: sub.to_string(),
        aud: "desktop-client.apps.googleusercontent.com".to_string(),
        iat: UnixTime::from_secs(NOW),
        nonce: attestation_nonce(NonceBinding::Verbatim, &peer_identity()),
    };
    classify(
        &policy,
        &claims,
        &identity,
        &agreement,
        UnixTime::from_secs(NOW),
    )
}

#[test]
fn a_linked_account_classifies_as_linked_through_the_registry() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    assert_eq!(tier_for(&registry, "bob-subject"), Ok(TrustTier::Linked));
}

#[test]
fn an_account_this_registry_never_linked_is_refused() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");

    assert!(tier_for(&registry, "mallory-subject").is_err());
}

#[test]
fn removing_a_link_refuses_that_account_on_the_very_next_classification() {
    // M6's completion criterion: removal takes effect immediately, with
    // no reload and no restart between the two calls below.
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("a first link is accepted");
    assert_eq!(tier_for(&registry, "bob-subject"), Ok(TrustTier::Linked));

    registry
        .remove(&derive_link_id(&secret(0x01)), &vault)
        .expect("a known link removes");

    assert!(tier_for(&registry, "bob-subject").is_err());
}

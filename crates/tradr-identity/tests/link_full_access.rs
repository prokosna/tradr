use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use tradr_core::{LinkId, LinkSecret, SecretStore, SecretStoreError, StorageLevel, UnixTime};
use tradr_identity::{AccountId, Link, LinkRegistry, LinkRegistryError, derive_link_id};

const NOW: i64 = 1_800_000_000;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("tradr-links-fa-{}-{n}.json", std::process::id()));
    if path.exists() {
        drop(std::fs::remove_file(&path));
    }
    path
}

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

#[derive(Default)]
struct Vault {
    slots: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl SecretStore for Vault {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
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

#[test]
fn a_new_link_has_full_access_false() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let link = a_link(&secret(0x01), "bob-subject");
    assert!(!link.full_access());

    registry
        .add(link, &secret(0x01), &vault)
        .expect("a first link is accepted");

    let held = registry
        .link(&derive_link_id(&secret(0x01)))
        .expect("link exists");
    assert!(!held.full_access());
    assert!(registry.full_access_accounts().is_empty());
}

#[test]
fn setting_full_access_to_true_persists_and_names_only_that_account() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let id1 = derive_link_id(&secret(0x01));
    let id2 = derive_link_id(&secret(0x02));
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("first link accepted");
    registry
        .add(
            a_link(&secret(0x02), "carol-subject"),
            &secret(0x02),
            &vault,
        )
        .expect("second link accepted");

    registry
        .set_full_access(&id1, true)
        .expect("set_full_access succeeds");

    assert!(registry.link(&id1).expect("id1 exists").full_access());
    assert!(!registry.link(&id2).expect("id2 exists").full_access());
    assert_eq!(
        registry.full_access_accounts(),
        vec![account("bob-subject")]
    );

    let reloaded = LinkRegistry::load(&path).expect("reloaded file loads");
    assert!(reloaded.link(&id1).expect("id1 exists").full_access());
    assert!(!reloaded.link(&id2).expect("id2 exists").full_access());
    assert_eq!(
        reloaded.full_access_accounts(),
        vec![account("bob-subject")]
    );
}

#[test]
fn setting_full_access_back_to_false_persists_too() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let id = derive_link_id(&secret(0x01));
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("link accepted");

    registry
        .set_full_access(&id, true)
        .expect("granted full access");
    assert!(registry.link(&id).expect("id exists").full_access());

    registry
        .set_full_access(&id, false)
        .expect("revoked full access");
    assert!(!registry.link(&id).expect("id exists").full_access());
    assert!(registry.full_access_accounts().is_empty());

    let reloaded = LinkRegistry::load(&path).expect("reloaded file loads");
    assert!(!reloaded.link(&id).expect("id exists").full_access());
    assert!(reloaded.full_access_accounts().is_empty());
}

#[test]
fn setting_full_access_for_an_unknown_id_is_refused_and_the_file_is_unchanged() {
    let path = scratch_path();
    let vault = Vault::default();
    let mut registry = LinkRegistry::load(&path).expect("a missing file loads");

    let id = derive_link_id(&secret(0x01));
    registry
        .add(a_link(&secret(0x01), "bob-subject"), &secret(0x01), &vault)
        .expect("link accepted");

    let before_bytes = std::fs::read(&path).expect("file exists");

    let unknown = LinkId::from_bytes(&[0xff; 16]).expect("16 bytes is link id");
    let result = registry.set_full_access(&unknown, true);

    assert!(matches!(result, Err(LinkRegistryError::UnknownLink)));
    assert!(!registry.link(&id).expect("id exists").full_access());

    let after_bytes = std::fs::read(&path).expect("file exists");
    assert_eq!(before_bytes, after_bytes);

    let reloaded = LinkRegistry::load(&path).expect("reloaded file loads");
    assert!(!reloaded.link(&id).expect("id exists").full_access());
    assert!(reloaded.full_access_accounts().is_empty());
}

#[test]
fn links_file_written_without_full_access_field_loads_with_full_access_false() {
    let path = scratch_path();
    let json = r#"{"links":[{"link_id":"01010101010101010101010101010101","peer_iss":"https://accounts.google.com","peer_sub":"bob-subject","peer_label":"Bob","created_at":1800000000,"fingerprint_verified":true}]}"#;
    std::fs::write(&path, json).expect("file written");

    let registry = LinkRegistry::load(&path).expect("file loads");
    assert_eq!(registry.links().len(), 1);
    let link = &registry.links()[0];
    assert!(!link.full_access());
    assert!(registry.full_access_accounts().is_empty());
}

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tauri_plugin_tradr::broadcast_secrets::{DeviceBroadcastSecrets, OwnAccount};
use tradr_core::{LinkSecret, SecretStore, SecretStoreError, StorageLevel, UnixTime};
use tradr_discovery::{BroadcastSecret, BroadcastSecrets};
use tradr_identity::{
    ACCOUNT_BROADCAST_KEY_SLOT, AccountId, Link, LinkRegistry, derive_link_id, link_secret_slot,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch_path(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("{prefix}-{}-{n}.json", std::process::id()));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("failed to clean scratch file at {}: {e}", path.display()),
    }
    path
}

fn account(sub: &str) -> AccountId {
    AccountId::new("https://accounts.google.com", sub)
}

fn link_secret(fill: u8) -> LinkSecret {
    LinkSecret::from_bytes(&[fill; 32]).expect("32 bytes builds a link secret")
}

fn make_link(secret: &LinkSecret, sub: &str) -> Link {
    Link::new(
        derive_link_id(secret),
        account(sub),
        UnixTime::from_secs(1_756_684_800),
    )
}

struct FakeOwnAccount {
    account: Mutex<Option<AccountId>>,
}

impl FakeOwnAccount {
    fn new(account: Option<AccountId>) -> Self {
        Self {
            account: Mutex::new(account),
        }
    }

    fn set(&self, account: Option<AccountId>) {
        *self.account.lock().unwrap_or_else(|p| p.into_inner()) = account;
    }
}

impl OwnAccount for FakeOwnAccount {
    fn own_account(&self) -> Option<AccountId> {
        self.account
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[derive(Default)]
struct MemoryStore {
    slots: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MemoryStore {
    fn get(&self, slot: &str) -> Option<Vec<u8>> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(name, _)| name == slot)
            .map(|(_, val)| val.clone())
    }
}

impl SecretStore for MemoryStore {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.retain(|(name, _)| name != slot);
        slots.push((slot.to_string(), secret.to_vec()));
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self.get(slot))
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(name, _)| name != slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

fn plant_abk(
    path: &std::path::Path,
    account: &AccountId,
    secret_bytes: &[u8; 32],
    store: &MemoryStore,
) {
    let json = serde_json::json!({
        "account_iss": account.iss(),
        "account_sub": account.sub(),
        "generation": 1,
        "created_at": 1_756_684_800
    });
    std::fs::write(path, json.to_string().as_bytes()).expect("abk record is writable");
    store
        .store(ACCOUNT_BROADCAST_KEY_SLOT, secret_bytes)
        .expect("abk store succeeds");
}

#[test]
fn signed_in_device_with_no_abk_and_no_links_yields_one_bootstrap_secret() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-empty");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-none");

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
    let secrets = provider.secrets();

    assert_eq!(secrets.len(), 1);
    let expected = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(secrets[0].as_bytes(), expected.as_bytes());
}

#[test]
fn device_not_signed_in_yields_no_abk_and_no_bootstrap_and_yields_links() {
    let own = Arc::new(FakeOwnAccount::new(None));
    let link_path = scratch_path("tradr-links-unsigned");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());

    let sec1 = link_secret(0x11);
    let link1 = make_link(&sec1, "bob");
    reg.add(link1, &sec1, store.as_ref())
        .expect("add link1 succeeds");

    let sec2 = link_secret(0x22);
    let link2 = make_link(&sec2, "carol");
    reg.add(link2, &sec2, store.as_ref())
        .expect("add link2 succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let abk_path = scratch_path("tradr-abk-unsigned");

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
    let secrets = provider.secrets();

    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].as_bytes(), sec1.as_bytes());
    assert_eq!(secrets[1].as_bytes(), sec2.as_bytes());
}

#[test]
fn device_holding_abk_two_links_and_account_yields_four_secrets_in_order() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-all");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-all");

    let abk_bytes = [0x42u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes, &store);

    let sec1 = link_secret(0x11);
    let link1 = make_link(&sec1, "bob");
    reg.add(link1, &sec1, store.as_ref())
        .expect("add link1 succeeds");

    let sec2 = link_secret(0x22);
    let link2 = make_link(&sec2, "carol");
    reg.add(link2, &sec2, store.as_ref())
        .expect("add link2 succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
    let secrets = provider.secrets();

    assert_eq!(secrets.len(), 4);
    assert_eq!(secrets[0].as_bytes(), &abk_bytes);
    assert_eq!(secrets[1].as_bytes(), sec1.as_bytes());
    assert_eq!(secrets[2].as_bytes(), sec2.as_bytes());
    let expected_bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(secrets[3].as_bytes(), expected_bootstrap.as_bytes());
}

#[test]
fn asymmetry_bootstrap_secret_yields_even_when_abk_is_present() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-asym");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-asym");

    let abk_bytes = [0x99u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes, &store);

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
    let secrets = provider.secrets();

    let bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].as_bytes(), &abk_bytes);
    assert_eq!(
        secrets[1].as_bytes(),
        bootstrap.as_bytes(),
        "bootstrap secret must remain in the matching set even after an ABK exists"
    );
}

#[test]
fn read_per_call_not_captured() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-dyn");
    let reg = LinkRegistry::load(&link_path).expect("registry loads");
    let link_reg = Arc::new(Mutex::new(reg));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-dyn");

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg.clone()), store.clone(), abk_path);

    let first = provider.secrets();
    assert_eq!(first.len(), 1);

    let sec = link_secret(0x33);
    let link = make_link(&sec, "dave");
    link_reg
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .add(link.clone(), &sec, store.as_ref())
        .expect("add succeeds");

    let second = provider.secrets();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].as_bytes(), sec.as_bytes());
    assert_eq!(second[1].as_bytes(), first[0].as_bytes());

    link_reg
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&link.link_id(), store.as_ref())
        .expect("remove succeeds");

    let third = provider.secrets();
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].as_bytes(), first[0].as_bytes());
}

#[test]
fn record_naming_another_account_refused_by_load_yields_no_abk() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-mismatch");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-mismatch");

    let abk_bytes = [0x55u8; 32];
    plant_abk(&abk_path, &account("other"), &abk_bytes, &store);

    let sec = link_secret(0x77);
    let link = make_link(&sec, "bob");
    reg.add(link, &sec, store.as_ref()).expect("add succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
    let secrets = provider.secrets();

    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].as_bytes(), sec.as_bytes());
    let expected_bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(secrets[1].as_bytes(), expected_bootstrap.as_bytes());
}

#[test]
fn link_whose_secret_slot_is_empty_yields_other_secrets_and_not_that_one() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-empty-slot");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-empty-slot");

    let abk_bytes = [0x88u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes, &store);

    let sec1 = link_secret(0x11);
    let link1 = make_link(&sec1, "bob");
    reg.add(link1, &sec1, store.as_ref())
        .expect("add link1 succeeds");

    let sec2 = link_secret(0x22);
    let link2 = make_link(&sec2, "carol");
    reg.add(link2.clone(), &sec2, store.as_ref())
        .expect("add link2 succeeds");

    store
        .remove(&link_secret_slot(&link2.link_id()))
        .expect("removal succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
    let secrets = provider.secrets();

    assert_eq!(secrets.len(), 3);
    assert_eq!(secrets[0].as_bytes(), &abk_bytes);
    assert_eq!(secrets[1].as_bytes(), sec1.as_bytes());
    let expected_bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(secrets[2].as_bytes(), expected_bootstrap.as_bytes());
}

#[test]
fn link_registry_err_leaves_links_out_and_yields_abk_and_bootstrap() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-err");

    let abk_bytes = [0x77u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes, &store);

    let provider = DeviceBroadcastSecrets::new(
        own,
        Err("failed to load registry".to_string()),
        store,
        abk_path,
    );
    let secrets = provider.secrets();

    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].as_bytes(), &abk_bytes);
    let expected_bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(secrets[1].as_bytes(), expected_bootstrap.as_bytes());
}

#[test]
fn sign_in_transition_between_calls_yields_bootstrap_and_abk() {
    let own = Arc::new(FakeOwnAccount::new(None));
    let link_path = scratch_path("tradr-links-signin-transition");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-signin-transition");

    let abk_bytes = [0x42u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes, &store);

    let provider = DeviceBroadcastSecrets::new(own.clone(), Ok(link_reg), store, abk_path);

    let first = provider.secrets();
    assert_eq!(first.len(), 0);

    own.set(Some(account("alice")));

    let second = provider.secrets();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].as_bytes(), &abk_bytes);
    let expected_bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(second[1].as_bytes(), expected_bootstrap.as_bytes());
}

#[test]
fn abk_planted_between_calls_yields_abk_on_second_call() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-abk-planted");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-planted");

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store.clone(), abk_path.clone());

    let first = provider.secrets();
    assert_eq!(first.len(), 1);
    let expected_bootstrap = BroadcastSecret::bootstrap(&account("alice").to_bytes());
    assert_eq!(first[0].as_bytes(), expected_bootstrap.as_bytes());

    let abk_bytes = [0x55u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes, &store);

    let second = provider.secrets();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].as_bytes(), &abk_bytes);
    assert_eq!(second[1].as_bytes(), expected_bootstrap.as_bytes());
}

#[test]
fn abk_bytes_replaced_in_store_between_calls_yields_new_bytes() {
    let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
    let link_path = scratch_path("tradr-links-abk-replaced");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-replaced");

    let abk_bytes_1 = [0x11u8; 32];
    plant_abk(&abk_path, &account("alice"), &abk_bytes_1, &store);

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store.clone(), abk_path);

    let first = provider.secrets();
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].as_bytes(), &abk_bytes_1);

    let abk_bytes_2 = [0x22u8; 32];
    store
        .store(ACCOUNT_BROADCAST_KEY_SLOT, &abk_bytes_2)
        .expect("store update succeeds");

    let second = provider.secrets();
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].as_bytes(), &abk_bytes_2);
}

#[test]
fn with_abk_and_two_links_advertised_is_abk_then_links_with_no_bootstrap() {
    let alice = account("alice");
    let own = Arc::new(FakeOwnAccount::new(Some(alice.clone())));
    let link_path = scratch_path("tradr-links-abk-two-links");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-two-links");

    let abk_bytes = [0x42u8; 32];
    plant_abk(&abk_path, &alice, &abk_bytes, &store);

    let sec1 = link_secret(0x11);
    let link1 = make_link(&sec1, "bob");
    reg.add(link1, &sec1, store.as_ref())
        .expect("add link1 succeeds");

    let sec2 = link_secret(0x22);
    let link2 = make_link(&sec2, "carol");
    reg.add(link2, &sec2, store.as_ref())
        .expect("add link2 succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);

    let advertised = provider.advertised();
    assert_eq!(advertised.len(), 3);
    assert_eq!(advertised[0].as_bytes(), &abk_bytes);
    assert_eq!(advertised[1].as_bytes(), sec1.as_bytes());
    assert_eq!(advertised[2].as_bytes(), sec2.as_bytes());

    let bootstrap = BroadcastSecret::bootstrap(&alice.to_bytes());
    assert!(
        !advertised
            .iter()
            .any(|s| s.as_bytes() == bootstrap.as_bytes())
    );

    let secrets = provider.secrets();
    assert_eq!(secrets.len(), 4);
    assert_eq!(secrets[0].as_bytes(), &abk_bytes);
    assert_eq!(secrets[1].as_bytes(), sec1.as_bytes());
    assert_eq!(secrets[2].as_bytes(), sec2.as_bytes());
    assert_eq!(secrets[3].as_bytes(), bootstrap.as_bytes());
}

#[test]
fn signed_in_with_no_abk_and_one_link_advertised_is_bootstrap_then_link() {
    let alice = account("alice");
    let own = Arc::new(FakeOwnAccount::new(Some(alice.clone())));
    let link_path = scratch_path("tradr-links-no-abk-one-link");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-none-one-link");

    let sec1 = link_secret(0x11);
    let link1 = make_link(&sec1, "bob");
    reg.add(link1, &sec1, store.as_ref())
        .expect("add link1 succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);

    let advertised = provider.advertised();
    assert_eq!(advertised.len(), 2);
    let bootstrap = BroadcastSecret::bootstrap(&alice.to_bytes());
    assert_eq!(advertised[0].as_bytes(), bootstrap.as_bytes());
    assert_eq!(advertised[1].as_bytes(), sec1.as_bytes());
}

#[test]
fn not_signed_in_with_one_link_advertised_is_link_secret_alone() {
    let own = Arc::new(FakeOwnAccount::new(None));
    let link_path = scratch_path("tradr-links-not-signed-one-link");
    let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-not-signed-one-link");

    let sec1 = link_secret(0x11);
    let link1 = make_link(&sec1, "bob");
    reg.add(link1, &sec1, store.as_ref())
        .expect("add link1 succeeds");

    let link_reg = Arc::new(Mutex::new(reg));
    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);

    let advertised = provider.advertised();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].as_bytes(), sec1.as_bytes());
}

#[test]
fn not_signed_in_with_no_links_advertised_is_empty() {
    let own = Arc::new(FakeOwnAccount::new(None));
    let link_path = scratch_path("tradr-links-empty-unsigned");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-empty-unsigned");

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);

    let advertised = provider.advertised();
    assert!(advertised.is_empty());
}

#[test]
fn negative_with_abk_held_no_element_of_advertised_equals_bootstrap() {
    let alice = account("alice");
    let own = Arc::new(FakeOwnAccount::new(Some(alice.clone())));
    let link_path = scratch_path("tradr-links-abk-held-neg");
    let link_reg = Arc::new(Mutex::new(
        LinkRegistry::load(&link_path).expect("registry loads"),
    ));
    let store = Arc::new(MemoryStore::default());
    let abk_path = scratch_path("tradr-abk-held-neg");

    let abk_bytes = [0x77u8; 32];
    plant_abk(&abk_path, &alice, &abk_bytes, &store);

    let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);

    let advertised = provider.advertised();
    let bootstrap = BroadcastSecret::bootstrap(&alice.to_bytes());
    assert!(!advertised.is_empty());
    assert!(
        !advertised
            .iter()
            .any(|s| s.as_bytes() == bootstrap.as_bytes())
    );
}

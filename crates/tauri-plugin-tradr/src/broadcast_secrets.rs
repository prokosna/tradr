//! Assembles the set of secrets a BLE scanner matches against (docs/03, docs/11).
//!
//! Evaluated at the moment of each match rather than captured at scan start so
//! that link additions, link removals, and sign-ins take effect immediately.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tradr_core::SecretStore;
use tradr_discovery::{BroadcastSecret, BroadcastSecrets};
use tradr_identity::{AccountId, BroadcastKeyRegistry, LinkRegistry};

use crate::sign_in::SignInState;

/// Answers this device's own account identifier for broadcast matching (docs/03),
/// read at the moment of the match and never captured.
pub trait OwnAccount: Send + Sync {
    /// Returns this device's own account if signed in.
    fn own_account(&self) -> Option<AccountId>;
}

impl OwnAccount for SignInState {
    fn own_account(&self) -> Option<AccountId> {
        SignInState::own_account(self)
    }
}

/// Provides broadcast secrets composed from the ABK, Link secrets, and bootstrap secret.
pub struct DeviceBroadcastSecrets {
    own_account: Arc<dyn OwnAccount>,
    link_registry: Result<Arc<Mutex<LinkRegistry>>, String>,
    secrets: Arc<dyn SecretStore + Send + Sync>,
    abk_path: PathBuf,
    last_report: Mutex<Option<String>>,
}

impl DeviceBroadcastSecrets {
    /// Creates a provider matching against the ABK, Link secrets, and bootstrap secret.
    pub fn new(
        own_account: Arc<dyn OwnAccount>,
        link_registry: Result<Arc<Mutex<LinkRegistry>>, String>,
        secrets: Arc<dyn SecretStore + Send + Sync>,
        abk_path: PathBuf,
    ) -> Self {
        Self {
            own_account,
            link_registry,
            secrets,
            abk_path,
            last_report: Mutex::new(None),
        }
    }

    // Separated from reporting so cause assembly is directly testable without observing stderr.
    fn assemble_secrets(&self) -> (Vec<BroadcastSecret>, Vec<String>) {
        let mut causes = Vec::new();
        let own_account = self.own_account.own_account();

        let mut abk_secret = None;
        if let Some(ref account) = own_account {
            match BroadcastKeyRegistry::load(&self.abk_path, account) {
                Ok(registry) => match registry.offer(self.secrets.as_ref()) {
                    Ok(Some(offer)) => match BroadcastSecret::from_bytes(offer.key().as_bytes()) {
                        Ok(secret) => abk_secret = Some(secret),
                        Err(e) => causes.push(format!("account broadcast key: {e}")),
                    },
                    Ok(None) => {}
                    Err(e) => causes.push(format!("account broadcast key: {e}")),
                },
                Err(e) => causes.push(format!("account broadcast key: {e}")),
            }
        }

        let mut link_secrets = Vec::new();
        match &self.link_registry {
            Ok(registry_mutex) => {
                let registry = registry_mutex
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for link in registry.links() {
                    match registry.link_secret(&link.link_id(), self.secrets.as_ref()) {
                        Ok(Some(secret)) => match BroadcastSecret::from_bytes(secret.as_bytes()) {
                            Ok(bs) => link_secrets.push(bs),
                            Err(e) => causes.push(format!("link {}: {e}", link.link_id())),
                        },
                        Ok(None) => {
                            causes.push(format!("link {}: secret slot is empty", link.link_id()));
                        }
                        Err(e) => {
                            causes.push(format!("link {}: {e}", link.link_id()));
                        }
                    }
                }
            }
            Err(err) => {
                causes.push(format!("link registry: {err}"));
            }
        }

        let mut bootstrap_secret = None;
        if let Some(ref account) = own_account {
            bootstrap_secret = Some(BroadcastSecret::bootstrap(&account.to_bytes()));
        }

        let mut result = Vec::with_capacity(
            abk_secret.is_some() as usize
                + link_secrets.len()
                + bootstrap_secret.is_some() as usize,
        );
        if let Some(abk) = abk_secret {
            result.push(abk);
        }
        result.extend(link_secrets);
        if let Some(bootstrap) = bootstrap_secret {
            result.push(bootstrap);
        }

        (result, causes)
    }

    // Latches failure reports so intermittent failures log once rather than flooding on every match.
    fn format_report(&self, causes: &[String]) -> Option<String> {
        let mut last = self
            .last_report
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if causes.is_empty() {
            if last.is_some() {
                *last = None;
                Some("broadcast secrets: previous failure cleared".to_string())
            } else {
                None
            }
        } else {
            let report_text = causes.join("; ");
            if last.as_deref() != Some(&report_text) {
                let line = format!("broadcast secrets: {report_text}");
                *last = Some(report_text);
                Some(line)
            } else {
                None
            }
        }
    }
}

impl BroadcastSecrets for DeviceBroadcastSecrets {
    fn secrets(&self) -> Vec<BroadcastSecret> {
        let (secrets, causes) = self.assemble_secrets();
        if let Some(line) = self.format_report(&causes) {
            eprintln!("{line}");
        }
        secrets
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tradr_core::{LinkSecret, SecretStore, SecretStoreError, StorageLevel, UnixTime};
    use tradr_identity::{Link, derive_link_id, link_secret_slot};

    use super::*;

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

    #[test]
    fn sign_in_state_implements_own_account() {
        let state = SignInState::empty();
        assert_eq!(state.own_account(), None);
    }

    #[test]
    fn cause_link_registry_err_reaches_cause_list() {
        let own = Arc::new(FakeOwnAccount::new(None));
        let store = Arc::new(MemoryStore::default());
        let provider = DeviceBroadcastSecrets::new(
            own,
            Err("disk failure".to_string()),
            store,
            scratch_path("unit-abk-reg-err"),
        );

        let (_, causes) = provider.assemble_secrets();
        assert_eq!(causes.len(), 1);
        assert!(causes[0].contains("link registry: disk failure"));
    }

    #[test]
    fn cause_refused_abk_record_reaches_cause_list() {
        let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
        let link_path = scratch_path("unit-link-abk-refused");
        let link_reg = Arc::new(Mutex::new(
            LinkRegistry::load(&link_path).expect("registry loads"),
        ));
        let store = Arc::new(MemoryStore::default());
        let abk_path = scratch_path("unit-abk-refused");

        let json = serde_json::json!({
            "account_iss": "https://accounts.google.com",
            "account_sub": "bob",
            "generation": 1,
            "created_at": 1_756_684_800
        });
        std::fs::write(&abk_path, json.to_string().as_bytes()).expect("write abk succeeds");

        let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
        let (_, causes) = provider.assemble_secrets();
        assert_eq!(causes.len(), 1);
        assert!(causes[0].contains("account broadcast key:"));
    }

    #[test]
    fn cause_link_secret_error_reaches_cause_list() {
        let own = Arc::new(FakeOwnAccount::new(None));
        let link_path = scratch_path("unit-link-secret-err");
        let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
        let store = Arc::new(MemoryStore::default());

        let sec = link_secret(0x11);
        let link = make_link(&sec, "bob");
        reg.add(link.clone(), &sec, store.as_ref())
            .expect("add link succeeds");
        store
            .store(&link_secret_slot(&link.link_id()), &[0x42; 16])
            .expect("store malformed secret succeeds");

        let link_reg = Arc::new(Mutex::new(reg));
        let provider = DeviceBroadcastSecrets::new(
            own,
            Ok(link_reg),
            store,
            scratch_path("unit-abk-unused-err"),
        );

        let (_, causes) = provider.assemble_secrets();
        assert_eq!(causes.len(), 1);
        assert!(causes[0].contains(&format!("link {}", link.link_id())));
    }

    #[test]
    fn cause_empty_link_secret_slot_reaches_cause_list() {
        let own = Arc::new(FakeOwnAccount::new(None));
        let link_path = scratch_path("unit-link-empty-slot");
        let mut reg = LinkRegistry::load(&link_path).expect("registry loads");
        let store = Arc::new(MemoryStore::default());

        let sec = link_secret(0x11);
        let link = make_link(&sec, "bob");
        reg.add(link.clone(), &sec, store.as_ref())
            .expect("add link succeeds");
        store
            .remove(&link_secret_slot(&link.link_id()))
            .expect("remove secret succeeds");

        let link_reg = Arc::new(Mutex::new(reg));
        let provider = DeviceBroadcastSecrets::new(
            own,
            Ok(link_reg),
            store,
            scratch_path("unit-abk-unused-empty"),
        );

        let (_, causes) = provider.assemble_secrets();
        assert_eq!(causes.len(), 1);
        assert!(causes[0].contains(&format!("link {}: secret slot is empty", link.link_id())));
    }

    #[test]
    fn format_report_latching_and_clearing() {
        let provider = DeviceBroadcastSecrets::new(
            Arc::new(FakeOwnAccount::new(None)),
            Err("unused".to_string()),
            Arc::new(MemoryStore::default()),
            PathBuf::from("/nonexistent/abk"),
        );

        let cause_a = vec!["cause A".to_string()];
        let cause_b = vec!["cause B".to_string()];

        let first = provider.format_report(&cause_a);
        assert_eq!(first, Some("broadcast secrets: cause A".to_string()));

        let second = provider.format_report(&cause_a);
        assert_eq!(second, None);

        let third = provider.format_report(&cause_b);
        assert_eq!(third, Some("broadcast secrets: cause B".to_string()));

        let fourth = provider.format_report(&[]);
        assert_eq!(
            fourth,
            Some("broadcast secrets: previous failure cleared".to_string())
        );

        let fifth = provider.format_report(&[]);
        assert_eq!(fifth, None);
    }

    #[test]
    fn secrets_consumes_failure_report_latch() {
        let own = Arc::new(FakeOwnAccount::new(None));
        let store = Arc::new(MemoryStore::default());
        let provider = DeviceBroadcastSecrets::new(
            own,
            Err("disk failure".to_string()),
            store,
            scratch_path("unit-secrets-latch"),
        );

        let secrets = provider.secrets();
        assert!(secrets.is_empty());

        let causes = vec!["link registry: disk failure".to_string()];
        assert_eq!(provider.format_report(&causes), None);
    }

    #[test]
    fn signed_in_device_with_no_abk_record_yields_bootstrap_secret_and_empty_causes() {
        let own = Arc::new(FakeOwnAccount::new(Some(account("alice"))));
        let link_path = scratch_path("unit-link-no-abk");
        let link_reg = Arc::new(Mutex::new(
            LinkRegistry::load(&link_path).expect("registry loads"),
        ));
        let store = Arc::new(MemoryStore::default());
        let abk_path = scratch_path("unit-abk-none");

        let provider = DeviceBroadcastSecrets::new(own, Ok(link_reg), store, abk_path);
        let (secrets, causes) = provider.assemble_secrets();

        assert_eq!(causes, Vec::<String>::new());
        assert_eq!(secrets.len(), 1);
        let expected = BroadcastSecret::bootstrap(&account("alice").to_bytes());
        assert_eq!(secrets[0].as_bytes(), expected.as_bytes());
    }
}

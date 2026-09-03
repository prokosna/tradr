//! WI-M6-006c: `LinkRegistryState::linked_accounts` is what docs/05 step 6
//! reads in place of the `&[]` this Work Item closes. Fixtures are written
//! as raw JSON text rather than through `LinkRegistry::add`, so a test
//! never asserts the writer against itself.

use std::path::Path;

use tauri_plugin_tradr::link_registry::LinkRegistryState;
use tradr_identity::AccountId;
use tradr_secrets::FileStore;

// A `link_id` of `LINK_ID_LEN` (16) bytes, hex-encoded, arbitrary but
// well-formed: these tests never derive it from a secret.
const LINK_ID_HEX: &str = "0123456789abcdef0123456789abcdef";
const PEER_ISS: &str = "https://accounts.google.com";
const PEER_SUB: &str = "linked-peer-subject";

fn links_json_with_one_link() -> String {
    format!(
        r#"{{"links":[{{"link_id":"{LINK_ID_HEX}","peer_iss":"{PEER_ISS}","peer_sub":"{PEER_SUB}","peer_label":null,"created_at":1700000000,"fingerprint_verified":false}}]}}"#
    )
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("a fresh temp directory accepts the write");
}

#[test]
fn a_registry_holding_one_link_reports_exactly_that_account() {
    let dir = tempfile::tempdir().expect("a temp directory");
    let path = dir.path().join("links.json");
    write(&path, &links_json_with_one_link());

    let state = LinkRegistryState::load(&path);
    let accounts = state
        .linked_accounts()
        .expect("a well-formed registry reports its accounts");

    assert_eq!(accounts, vec![AccountId::new(PEER_ISS, PEER_SUB)]);
}

#[test]
fn a_link_removed_is_gone_from_the_very_next_call() {
    let dir = tempfile::tempdir().expect("a temp directory");
    let path = dir.path().join("links.json");
    write(&path, &links_json_with_one_link());
    let secrets = FileStore::new(dir.path().join("secrets"));

    let state = LinkRegistryState::load(&path);
    let registry = state.registry().expect("the fixture above is well-formed");

    // Read before the removal, so a cache populated here would still be
    // holding the account it must forget: this is what separates a fresh
    // read from a stale one.
    let before = state
        .linked_accounts()
        .expect("the fixture above is well-formed");
    assert_eq!(before, vec![AccountId::new(PEER_ISS, PEER_SUB)]);

    let link_id = LINK_ID_HEX.parse().expect("a valid link id hex string");
    registry
        .lock()
        .expect("the registry mutex is never poisoned")
        .remove(&link_id, &secrets)
        .expect("the only link this registry holds can be removed");

    let after = state
        .linked_accounts()
        .expect("a registry with no links is not an error");
    assert!(
        after.is_empty(),
        "a removed link must not still classify as Linked, got {after:?}"
    );
}

#[test]
fn a_missing_links_json_is_an_empty_registry_not_an_error() {
    let dir = tempfile::tempdir().expect("a temp directory");
    let path = dir.path().join("links.json");

    let state = LinkRegistryState::load(&path);
    let accounts = state
        .linked_accounts()
        .expect("a first run with no file yet must not be an error");

    assert!(accounts.is_empty());
}

#[test]
fn a_malformed_links_json_is_an_error_naming_the_file_never_an_empty_list() {
    let dir = tempfile::tempdir().expect("a temp directory");
    let path = dir.path().join("links.json");
    write(&path, "not valid json at all");

    let state = LinkRegistryState::load(&path);
    let outcome = state.linked_accounts();

    let message = outcome.expect_err(
        "a malformed registry read as an empty list would silently withdraw TrustTier::Linked",
    );
    assert!(
        message.contains("links.json"),
        "the message must name the file, got {message}"
    );
}

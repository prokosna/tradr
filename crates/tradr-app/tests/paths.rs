//! Supervisor-authored tests for DCR-124's one application data directory.
//! Critical Module, CLAUDE.md section 6: the directory decides which Device
//! Key a front end opens, and a front end that resolves a different one
//! mints a second Device Key on one machine while failing no build, no test
//! and no handshake. Written before the implementation.

use std::path::{Path, PathBuf};

use tradr_app::paths::{APP_IDENTIFIER, app_data_dir, device_keys_dir};

// Where the Tauri app's identifier is declared, relative to this crate.
const TAURI_CONF: &str = "../../apps/tradr/src-tauri/tauri.conf.json";

fn tauri_identifier() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(TAURI_CONF);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    let conf: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("could not parse tauri.conf.json: {e}"));
    conf.get("identifier")
        .and_then(|v| v.as_str())
        .expect("tauri.conf.json declares no identifier")
        .to_string()
}

#[test]
fn the_identifier_is_the_one_the_tauri_app_is_built_with() {
    assert_eq!(
        APP_IDENTIFIER,
        tauri_identifier(),
        "the two front ends would read different directories, and so hold different Device Keys"
    );
}

#[test]
fn the_application_data_directory_is_the_platform_data_root_named_for_the_identifier() {
    let root = dirs::data_dir().expect("this platform has a data directory");
    assert_eq!(app_data_dir().expect("resolves"), root.join(APP_IDENTIFIER));
}

#[test]
fn the_application_data_directory_is_not_the_platform_data_root_itself() {
    let root = dirs::data_dir().expect("this platform has a data directory");
    assert_ne!(app_data_dir().expect("resolves"), root);
}

#[test]
fn the_application_data_directory_ends_in_the_identifier() {
    let dir = app_data_dir().expect("resolves");
    assert_eq!(
        dir.file_name().and_then(|n| n.to_str()),
        Some(APP_IDENTIFIER)
    );
}

#[test]
fn the_device_keys_directory_is_keys_under_the_directory_it_is_given() {
    assert_eq!(
        device_keys_dir(Path::new("/somewhere/com.tradr.app")),
        PathBuf::from("/somewhere/com.tradr.app/keys")
    );
}

#[test]
fn the_device_keys_directory_is_not_the_directory_it_is_given() {
    let given = Path::new("/somewhere/com.tradr.app");
    assert_ne!(device_keys_dir(given), given.to_path_buf());
}

#[test]
fn the_device_keys_directory_is_the_path_the_shell_opened_the_key_from() {
    // The GUI opened its Device Key from app_data_dir()/keys before this
    // function existed, so the two must name one path or the CLI mints a key.
    let dir = app_data_dir().expect("resolves");
    assert_eq!(device_keys_dir(&dir), dir.join("keys"));
}

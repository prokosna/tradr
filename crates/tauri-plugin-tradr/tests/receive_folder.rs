//! Integration tests for receive folder resolution and probing (WI-M8-069a).

use std::path::PathBuf;

use tauri_plugin_tradr::receive_folder::{
    choose_receive_dir, probe_receive_dir, shared_download_dir,
};

#[test]
fn shared_download_dir_primary_user() {
    let app_specific: PathBuf = [
        "storage",
        "emulated",
        "0",
        "Android",
        "data",
        "com.tradr.app",
        "files",
        "Download",
    ]
    .iter()
    .collect();
    let expected: PathBuf = ["storage", "emulated", "0", "Download", "Tradr"]
        .iter()
        .collect();
    assert_eq!(shared_download_dir(&app_specific), Some(expected));
}

#[test]
fn shared_download_dir_secondary_user() {
    let app_specific: PathBuf = [
        "storage",
        "emulated",
        "10",
        "Android",
        "data",
        "com.tradr.app",
        "files",
        "Download",
    ]
    .iter()
    .collect();
    let expected: PathBuf = ["storage", "emulated", "10", "Download", "Tradr"]
        .iter()
        .collect();
    assert_eq!(shared_download_dir(&app_specific), Some(expected));
}

#[test]
fn shared_download_dir_without_android_component() {
    let app_specific: PathBuf = [
        "storage",
        "emulated",
        "0",
        "other",
        "data",
        "com.tradr.app",
        "files",
        "Download",
    ]
    .iter()
    .collect();
    assert_eq!(shared_download_dir(&app_specific), None);
}

#[test]
fn shared_download_dir_android_not_followed_by_data() {
    let app_specific: PathBuf = [
        "storage",
        "emulated",
        "0",
        "Android",
        "media",
        "com.tradr.app",
        "files",
        "Download",
    ]
    .iter()
    .collect();
    assert_eq!(shared_download_dir(&app_specific), None);
}

#[test]
fn shared_download_dir_empty_storage_root() {
    let app_specific: PathBuf = ["Android", "data", "com.tradr.app", "files", "Download"]
        .iter()
        .collect();
    assert_eq!(shared_download_dir(&app_specific), None);
}

#[test]
fn probe_receive_dir_creates_and_leaves_empty_directory() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let target = tmp.path().join("a").join("b");
    assert!(!target.exists());

    probe_receive_dir(&target).expect("probe succeeds");
    assert!(target.is_dir());

    let mut entries = std::fs::read_dir(&target).expect("read dir");
    assert!(entries.next().is_none());
}

#[test]
fn probe_receive_dir_fails_when_parent_is_file() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let file_path = tmp.path().join("regular_file");
    std::fs::write(&file_path, b"data").expect("write file");
    let target = file_path.join("child");

    assert!(probe_receive_dir(&target).is_err());
}

#[test]
fn choose_receive_dir_selects_shared_download_dir() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let app_specific = tmp
        .path()
        .join("Android")
        .join("data")
        .join("pkg")
        .join("files")
        .join("Download");
    let expected = tmp.path().join("Download").join("Tradr");

    let chosen = choose_receive_dir(app_specific);
    assert_eq!(chosen, expected);
    assert!(chosen.is_dir());
}

#[test]
fn choose_receive_dir_falls_back_when_probe_fails() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let blocking_file = tmp.path().join("Download");
    std::fs::write(&blocking_file, b"blocking").expect("write file");

    let app_specific = tmp
        .path()
        .join("Android")
        .join("data")
        .join("pkg")
        .join("files")
        .join("Download");

    let chosen = choose_receive_dir(app_specific.clone());
    assert_eq!(chosen, app_specific);
}

#[test]
fn choose_receive_dir_returns_unchanged_without_android_data() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let app_specific = tmp.path().join("custom").join("download");

    let chosen = choose_receive_dir(app_specific.clone());
    assert_eq!(chosen, app_specific);
}

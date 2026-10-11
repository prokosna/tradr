//! Tests for locating received files and checking offered actions (docs/12, ADR-0026).

use tauri_plugin_tradr::received_actions::{ReceivedActionError, locate_received, offered_actions};
use tradr_app::received_history::{NewReceived, ReceivedHistory, ReceivedHow};
use tradr_core::RootId;
use tradr_vfs::NativeVfs;

#[test]
fn recorded_row_whose_file_exists_is_located_at_canonical_root_joined_with_path() {
    let hist_dir = tempfile::tempdir().expect("tempdir");
    let root_dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(hist_dir.path());
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, root_dir.path().to_path_buf(), false)
        .expect("register root");

    let file_path = root_dir.path().join("report.pdf");
    std::fs::write(&file_path, b"test content").expect("write file");

    history
        .record(vec![NewReceived {
            path: "report.pdf".to_string(),
            device_id: "dev1".to_string(),
            device_name: None,
            received_at: 1_700_000_000,
            how: ReceivedHow::Sent,
        }])
        .expect("record");

    let located = locate_received(&history, &vfs, root, 1).expect("locate");
    let expected = root_dir
        .path()
        .canonicalize()
        .expect("canonical")
        .join("report.pdf");
    assert_eq!(located, expected);
}

#[test]
fn unknown_id_returns_unknown_row() {
    let hist_dir = tempfile::tempdir().expect("tempdir");
    let root_dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(hist_dir.path());
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, root_dir.path().to_path_buf(), false)
        .expect("register root");

    history
        .record(vec![NewReceived {
            path: "report.pdf".to_string(),
            device_id: "dev1".to_string(),
            device_name: None,
            received_at: 1_700_000_000,
            how: ReceivedHow::Sent,
        }])
        .expect("record");

    let err = locate_received(&history, &vfs, root, 999).expect_err("unknown id");
    assert_eq!(err, ReceivedActionError::UnknownRow);
    assert_eq!(err.to_string(), "This row is no longer in the list.");
}

#[test]
fn deleted_file_returns_gone_with_exact_sentence() {
    let hist_dir = tempfile::tempdir().expect("tempdir");
    let root_dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(hist_dir.path());
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, root_dir.path().to_path_buf(), false)
        .expect("register root");

    let file_path = root_dir.path().join("deleted.txt");
    std::fs::write(&file_path, b"to be deleted").expect("write file");

    history
        .record(vec![NewReceived {
            path: "deleted.txt".to_string(),
            device_id: "dev1".to_string(),
            device_name: None,
            received_at: 1_700_000_000,
            how: ReceivedHow::Sent,
        }])
        .expect("record");

    std::fs::remove_file(&file_path).expect("remove file");

    let err = locate_received(&history, &vfs, root, 1).expect_err("deleted file");
    assert_eq!(err, ReceivedActionError::Gone);
    assert_eq!(
        err.to_string(),
        "This file is no longer where it was saved."
    );
}

#[test]
fn row_whose_path_names_a_directory_is_failed() {
    let hist_dir = tempfile::tempdir().expect("tempdir");
    let root_dir = tempfile::tempdir().expect("tempdir");
    let history = ReceivedHistory::new(hist_dir.path());
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, root_dir.path().to_path_buf(), false)
        .expect("register root");

    let dir_path = root_dir.path().join("subdir");
    std::fs::create_dir(&dir_path).expect("create dir");

    history
        .record(vec![NewReceived {
            path: "subdir".to_string(),
            device_id: "dev1".to_string(),
            device_name: None,
            received_at: 1_700_000_000,
            how: ReceivedHow::Sent,
        }])
        .expect("record");

    let err = locate_received(&history, &vfs, root, 1).expect_err("directory path");
    assert!(matches!(err, ReceivedActionError::Failed(_)));
}

#[test]
fn row_whose_stored_path_is_not_valid_rel_path_is_failed() {
    let hist_dir = tempfile::tempdir().expect("tempdir");
    let root_dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, root_dir.path().to_path_buf(), false)
        .expect("register root");

    let invalid_json = serde_json::json!([
        {
            "id": 1,
            "path": "../x",
            "device_id": "dev1",
            "device_name": null,
            "received_at": 1_700_000_000,
            "how": "sent"
        }
    ]);
    std::fs::write(
        hist_dir.path().join("received.json"),
        invalid_json.to_string(),
    )
    .expect("write received.json");

    let history = ReceivedHistory::new(hist_dir.path());
    let err = locate_received(&history, &vfs, root, 1).expect_err("invalid rel path");
    assert!(matches!(err, ReceivedActionError::Failed(_)));
}

#[test]
fn unreadable_received_json_is_failed() {
    let hist_dir = tempfile::tempdir().expect("tempdir");
    let root_dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, root_dir.path().to_path_buf(), false)
        .expect("register root");

    std::fs::write(
        hist_dir.path().join("received.json"),
        b"not valid json content",
    )
    .expect("write bad json");

    let history = ReceivedHistory::new(hist_dir.path());
    let err = locate_received(&history, &vfs, root, 1).expect_err("unreadable json");
    assert!(matches!(err, ReceivedActionError::Failed(_)));
}

#[test]
fn offered_actions_is_open_and_reveal_on_this_host() {
    assert_eq!(offered_actions(), &["open", "reveal"]);
}

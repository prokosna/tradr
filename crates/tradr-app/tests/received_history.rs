use std::sync::Arc;
use std::thread;

use tradr_app::received_history::{
    NewReceived, ReceivedHistory, ReceivedHistoryError, ReceivedHow, ReceivedRow,
};

#[test]
fn missing_file_reads_as_empty() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history = ReceivedHistory::new(dir.path());

    let rows = history.rows().expect("read rows");
    assert!(rows.is_empty());
}

#[test]
fn two_record_calls_read_back_newest_first() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history = ReceivedHistory::new(dir.path());

    history
        .record(vec![
            NewReceived {
                path: "first.txt".to_string(),
                device_id: "dev-1".to_string(),
                device_name: Some("Phone".to_string()),
                received_at: 100,
                how: ReceivedHow::Sent,
            },
            NewReceived {
                path: "second.txt".to_string(),
                device_id: "dev-2".to_string(),
                device_name: None,
                received_at: 101,
                how: ReceivedHow::Downloaded,
            },
        ])
        .expect("record first batch");

    history
        .record(vec![
            NewReceived {
                path: "third.txt".to_string(),
                device_id: "dev-3".to_string(),
                device_name: Some("Tablet".to_string()),
                received_at: 102,
                how: ReceivedHow::Sent,
            },
            NewReceived {
                path: "fourth.txt".to_string(),
                device_id: "dev-4".to_string(),
                device_name: Some("Desktop".to_string()),
                received_at: 103,
                how: ReceivedHow::Downloaded,
            },
        ])
        .expect("record second batch");

    let rows = history.rows().expect("read rows");
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows,
        vec![
            ReceivedRow {
                id: 4,
                path: "fourth.txt".to_string(),
                device_id: "dev-4".to_string(),
                device_name: Some("Desktop".to_string()),
                received_at: 103,
                how: ReceivedHow::Downloaded,
            },
            ReceivedRow {
                id: 3,
                path: "third.txt".to_string(),
                device_id: "dev-3".to_string(),
                device_name: Some("Tablet".to_string()),
                received_at: 102,
                how: ReceivedHow::Sent,
            },
            ReceivedRow {
                id: 2,
                path: "second.txt".to_string(),
                device_id: "dev-2".to_string(),
                device_name: None,
                received_at: 101,
                how: ReceivedHow::Downloaded,
            },
            ReceivedRow {
                id: 1,
                path: "first.txt".to_string(),
                device_id: "dev-1".to_string(),
                device_name: Some("Phone".to_string()),
                received_at: 100,
                how: ReceivedHow::Sent,
            },
        ]
    );
}

#[test]
fn second_history_instance_continues_sequence() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history1 = ReceivedHistory::new(dir.path());

    history1
        .record(vec![NewReceived {
            path: "alpha.txt".to_string(),
            device_id: "dev-a".to_string(),
            device_name: None,
            received_at: 50,
            how: ReceivedHow::Sent,
        }])
        .expect("first instance record");

    let history2 = ReceivedHistory::new(dir.path());
    let initial_rows = history2.rows().expect("second instance read");
    assert_eq!(initial_rows.len(), 1);
    assert_eq!(initial_rows[0].id, 1);

    history2
        .record(vec![NewReceived {
            path: "beta.txt".to_string(),
            device_id: "dev-b".to_string(),
            device_name: None,
            received_at: 51,
            how: ReceivedHow::Downloaded,
        }])
        .expect("second instance record");

    let rows = history2.rows().expect("second instance rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, 2);
    assert_eq!(rows[1].id, 1);
}

#[test]
fn empty_record_creates_no_file() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history = ReceivedHistory::new(dir.path());

    history.record(Vec::new()).expect("empty record succeeds");
    assert!(!dir.path().join("received.json").exists());
    assert!(history.rows().expect("read rows").is_empty());
}

#[test]
fn hand_written_file_without_device_name_loads_and_continues_at_next_id() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let target = dir.path().join("received.json");
    std::fs::write(
        &target,
        r#"[{"id":7,"path":"a.txt","device_id":"ab","received_at":5,"how":"sent"}]"#,
    )
    .expect("write hand-written json");

    let history = ReceivedHistory::new(dir.path());
    let rows = history.rows().expect("read existing rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0],
        ReceivedRow {
            id: 7,
            path: "a.txt".to_string(),
            device_id: "ab".to_string(),
            device_name: None,
            received_at: 5,
            how: ReceivedHow::Sent,
        }
    );

    history
        .record(vec![NewReceived {
            path: "b.txt".to_string(),
            device_id: "cd".to_string(),
            device_name: Some("Peer".to_string()),
            received_at: 6,
            how: ReceivedHow::Downloaded,
        }])
        .expect("record subsequent row");

    let updated_rows = history.rows().expect("read updated rows");
    assert_eq!(updated_rows.len(), 2);
    assert_eq!(updated_rows[0].id, 8);
    assert_eq!(updated_rows[1].id, 7);
}

#[test]
fn downloaded_row_contains_how_downloaded() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history = ReceivedHistory::new(dir.path());

    history
        .record(vec![NewReceived {
            path: "doc.pdf".to_string(),
            device_id: "dev-x".to_string(),
            device_name: None,
            received_at: 77,
            how: ReceivedHow::Downloaded,
        }])
        .expect("record downloaded row");

    let content =
        std::fs::read_to_string(dir.path().join("received.json")).expect("read file contents");
    assert!(content.contains("\"how\":\"downloaded\""));
}

#[test]
fn malformed_file_returns_error_and_preserves_bytes() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let target = dir.path().join("received.json");
    let malformed_bytes = b"not json";
    std::fs::write(&target, malformed_bytes).expect("write malformed content");

    let history = ReceivedHistory::new(dir.path());
    match history.rows() {
        Err(ReceivedHistoryError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }

    let record_result = history.record(vec![NewReceived {
        path: "item.txt".to_string(),
        device_id: "dev-y".to_string(),
        device_name: None,
        received_at: 88,
        how: ReceivedHow::Sent,
    }]);
    match record_result {
        Err(ReceivedHistoryError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }

    let current_bytes = std::fs::read(&target).expect("read file content after failed record");
    assert_eq!(current_bytes, malformed_bytes);
}

#[test]
fn borrowed_how_returns_malformed() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let target = dir.path().join("received.json");
    std::fs::write(
        &target,
        r#"[{"id":1,"path":"a.txt","device_id":"ab","received_at":5,"how":"borrowed"}]"#,
    )
    .expect("write invalid how variant");

    let history = ReceivedHistory::new(dir.path());
    match history.rows() {
        Err(ReceivedHistoryError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn clear_succeeds_over_malformed_and_missing_file() {
    let malformed_dir = tempfile::tempdir().expect("create temp dir");
    let target = malformed_dir.path().join("received.json");
    std::fs::write(&target, b"corrupted json payload").expect("write malformed content");

    let malformed_history = ReceivedHistory::new(malformed_dir.path());
    malformed_history.clear().expect("clear over malformed");
    assert!(malformed_history.rows().expect("read rows").is_empty());

    let missing_dir = tempfile::tempdir().expect("create temp dir");
    let missing_history = ReceivedHistory::new(missing_dir.path());
    missing_history.clear().expect("clear over missing");
    assert!(missing_history.rows().expect("read rows").is_empty());
}

#[test]
fn directory_holds_only_received_json_after_record() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history = ReceivedHistory::new(dir.path());

    history
        .record(vec![NewReceived {
            path: "solo.txt".to_string(),
            device_id: "dev-1".to_string(),
            device_name: None,
            received_at: 10,
            how: ReceivedHow::Sent,
        }])
        .expect("record entry");

    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .map(|res| {
            res.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    assert_eq!(entries, vec!["received.json".to_string()]);
}

#[test]
fn concurrent_records_leave_distinct_ids() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let history = Arc::new(ReceivedHistory::new(dir.path()));

    let mut handles = Vec::new();
    for thread_idx in 0..8 {
        let history_clone = Arc::clone(&history);
        handles.push(thread::spawn(move || {
            history_clone
                .record(vec![NewReceived {
                    path: format!("file_{thread_idx}.txt"),
                    device_id: format!("device_{thread_idx}"),
                    device_name: None,
                    received_at: 1_000 + thread_idx as u64,
                    how: ReceivedHow::Sent,
                }])
                .expect("record in thread");
        }));
    }

    for handle in handles {
        handle.join().expect("thread join");
    }

    let rows = history.rows().expect("read rows");
    assert_eq!(rows.len(), 8);

    let mut ids: Vec<u64> = rows.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

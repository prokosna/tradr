//! Integration tests for share intent payloads (WI-M2-002).

use tauri_plugin_tradr::share::{ShareIntent, SharedFilePayload};

#[test]
fn deserialize_share_intent_with_cached_file() {
    let json = r#"{
        "action": "android.intent.action.SEND",
        "mimeType": "image/jpeg",
        "extraText": null,
        "files": [
            {
                "name": "photo.jpg",
                "size": 1048576,
                "cachePath": "/data/user/0/com.tradr.app/cache/shared_incoming/share_123_photo.jpg",
                "fd": null
            }
        ]
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid share intent");
    assert_eq!(parsed.action, "android.intent.action.SEND");
    assert_eq!(parsed.mime_type.as_deref(), Some("image/jpeg"));
    assert_eq!(parsed.extra_text, None);
    assert_eq!(parsed.files.len(), 1);

    let file = &parsed.files[0];
    assert_eq!(file.name, "photo.jpg");
    assert_eq!(file.size, 1048576);
    assert_eq!(
        file.cache_path.as_deref(),
        Some("/data/user/0/com.tradr.app/cache/shared_incoming/share_123_photo.jpg")
    );
    assert_eq!(file.fd, None);
}

#[test]
fn deserialize_share_intent_with_detached_fd() {
    let json = r#"{
        "action": "com.tradr.plugin.ACTION_SHARED_FILES",
        "mimeType": "video/mp4",
        "extraText": "Check this video",
        "files": [
            {
                "name": "large_movie.mp4",
                "size": 104857600,
                "cachePath": null,
                "fd": 42
            }
        ]
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid share intent");
    assert_eq!(parsed.action, "com.tradr.plugin.ACTION_SHARED_FILES");
    assert_eq!(parsed.extra_text.as_deref(), Some("Check this video"));
    assert_eq!(parsed.files.len(), 1);

    let file = &parsed.files[0];
    assert_eq!(file.name, "large_movie.mp4");
    assert_eq!(file.size, 104857600);
    assert_eq!(file.cache_path, None);
    assert_eq!(file.fd, Some(42));
}

#[test]
fn deserialize_share_intent_with_multiple_mixed_files() {
    let json = r#"{
        "action": "android.intent.action.SEND_MULTIPLE",
        "mimeType": "*/*",
        "extraText": null,
        "files": [
            {
                "name": "doc.pdf",
                "size": 524288,
                "cachePath": "/cache/doc.pdf",
                "fd": null
            },
            {
                "name": "archive.zip",
                "size": 100000000,
                "cachePath": null,
                "fd": 7
            }
        ]
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid share intent");
    assert_eq!(parsed.files.len(), 2);
    assert_eq!(
        parsed.files[0].cache_path.as_deref(),
        Some("/cache/doc.pdf")
    );
    assert_eq!(parsed.files[0].fd, None);
    assert_eq!(parsed.files[1].cache_path, None);
    assert_eq!(parsed.files[1].fd, Some(7));
}

#[test]
fn deserialize_text_only_share_intent_defaults_empty_files() {
    let json = r#"{
        "action": "android.intent.action.SEND",
        "mimeType": "text/plain",
        "extraText": "https://example.com"
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid share intent");
    assert_eq!(parsed.extra_text.as_deref(), Some("https://example.com"));
    assert!(parsed.files.is_empty());
}

#[test]
fn serialize_round_trip_shared_file_payload() {
    let payload = SharedFilePayload {
        name: "test.dat".to_string(),
        size: 999,
        cache_path: Some("/tmp/test.dat".to_string()),
        fd: None,
    };
    let serialized = serde_json::to_string(&payload).expect("serialize");
    let deserialized: SharedFilePayload = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(payload, deserialized);
}

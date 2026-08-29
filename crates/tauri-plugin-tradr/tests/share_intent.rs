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

#[test]
fn deserialize_share_intent_with_target_device() {
    let json = r#"{
        "action": "android.intent.action.SEND",
        "mimeType": "image/png",
        "extraText": null,
        "targetDevice": "0123456789abcdef0123456789abcdef",
        "files": []
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid share intent");
    assert_eq!(
        parsed.target_device.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn serialize_round_trip_peer_shortcut() {
    use tauri_plugin_tradr::share::PeerShortcut;

    let shortcut = PeerShortcut {
        device_id: "0123456789abcdef0123456789abcdef".to_string(),
        display_name: "Pixel 9 Pro".to_string(),
        platform: Some("android".to_string()),
    };

    let serialized = serde_json::to_string(&shortcut).expect("serialize");
    let deserialized: PeerShortcut = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(shortcut, deserialized);

    let json_val: serde_json::Value = serde_json::from_str(&serialized).expect("json val");
    assert_eq!(json_val["deviceId"], "0123456789abcdef0123456789abcdef");
    assert_eq!(json_val["displayName"], "Pixel 9 Pro");
    assert_eq!(json_val["platform"], "android");
}

#[test]
fn deserialize_pick_share_root_response_with_uri() {
    use tauri_plugin_tradr::share::PickShareRootResponse;

    let json =
        r#"{"uri":"content://com.android.externalstorage.documents/tree/primary%3ADocuments"}"#;
    let parsed: PickShareRootResponse = serde_json::from_str(json).expect("valid response");
    assert_eq!(
        parsed.uri.as_deref(),
        Some("content://com.android.externalstorage.documents/tree/primary%3ADocuments")
    );
}

#[test]
fn deserialize_pick_share_root_response_when_cancelled() {
    use tauri_plugin_tradr::share::PickShareRootResponse;

    let json = r#"{"uri":null}"#;
    let parsed: PickShareRootResponse = serde_json::from_str(json).expect("valid response");
    assert_eq!(parsed.uri, None);

    let empty_json = r#"{}"#;
    let parsed_empty: PickShareRootResponse =
        serde_json::from_str(empty_json).expect("valid response");
    assert_eq!(parsed_empty.uri, None);
}

#[test]
fn serialize_round_trip_pick_share_root_response() {
    use tauri_plugin_tradr::share::PickShareRootResponse;

    let response = PickShareRootResponse {
        uri: Some("content://media/external/file/100".to_string()),
    };
    let serialized = serde_json::to_string(&response).expect("serialize");
    let deserialized: PickShareRootResponse =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(response, deserialized);
}

//! Integration tests for incoming transfer notification actions (WI-M2-007).

use tauri_plugin_tradr::commands::ShowIncomingTransferNotificationArgs;
use tauri_plugin_tradr::desktop;
use tauri_plugin_tradr::share::{
    ACTION_NOTIFICATION_ACCEPT, ACTION_NOTIFICATION_DECLINE, ShareIntent,
};

#[test]
fn deserialize_notification_accept_intent_with_transfer_id() {
    let json = r#"{
        "action": "com.tradr.plugin.ACTION_NOTIFICATION_ACCEPT",
        "transferId": "019183ab-1234-7000-8000-0123456789ab",
        "mimeType": null,
        "extraText": null,
        "targetDevice": null,
        "files": []
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid accept notification intent");
    assert_eq!(parsed.action, ACTION_NOTIFICATION_ACCEPT);
    assert_eq!(
        parsed.transfer_id.as_deref(),
        Some("019183ab-1234-7000-8000-0123456789ab")
    );
    assert_eq!(parsed.mime_type, None);
    assert_eq!(parsed.extra_text, None);
    assert_eq!(parsed.target_device, None);
    assert!(parsed.files.is_empty());
}

#[test]
fn deserialize_notification_decline_intent_with_transfer_id() {
    let json = r#"{
        "action": "com.tradr.plugin.ACTION_NOTIFICATION_DECLINE",
        "transferId": "019183ab-5678-7000-8000-0123456789cd",
        "mimeType": null,
        "extraText": null,
        "targetDevice": null,
        "files": []
    }"#;

    let parsed: ShareIntent =
        serde_json::from_str(json).expect("valid decline notification intent");
    assert_eq!(parsed.action, ACTION_NOTIFICATION_DECLINE);
    assert_eq!(
        parsed.transfer_id.as_deref(),
        Some("019183ab-5678-7000-8000-0123456789cd")
    );
    assert!(parsed.files.is_empty());
}

#[test]
fn deserialize_notification_intent_without_transfer_id_defaults_to_none() {
    let json = r#"{
        "action": "com.tradr.plugin.ACTION_NOTIFICATION_ACCEPT",
        "files": []
    }"#;

    let parsed: ShareIntent = serde_json::from_str(json).expect("valid intent");
    assert_eq!(parsed.action, ACTION_NOTIFICATION_ACCEPT);
    assert_eq!(parsed.transfer_id, None);
}

#[test]
fn serialize_round_trip_show_incoming_transfer_notification_args() {
    let args = ShowIncomingTransferNotificationArgs {
        transfer_id: Some("019183ab-1234-7000-8000-0123456789ab".to_string()),
        sender_name: Some("Pixel 9 Pro".to_string()),
    };

    let serialized = serde_json::to_string(&args).expect("serialize notification args");
    let deserialized: ShowIncomingTransferNotificationArgs =
        serde_json::from_str(&serialized).expect("deserialize notification args");
    assert_eq!(args, deserialized);

    let json_val: serde_json::Value = serde_json::from_str(&serialized).expect("parsed json value");
    assert_eq!(
        json_val["transferId"],
        "019183ab-1234-7000-8000-0123456789ab"
    );
    assert_eq!(json_val["senderName"], "Pixel 9 Pro");
}

#[tokio::test]
async fn desktop_show_incoming_transfer_notification_succeeds() {
    let res = desktop::show_incoming_transfer_notification(
        Some("019183ab-1234-7000-8000-0123456789ab".to_string()),
        Some("Test Peer".to_string()),
    )
    .await;
    assert!(res.is_ok());
}

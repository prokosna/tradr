//! Integration tests for permission command arguments and responses (WI-M2-006).

use tauri_plugin_tradr::commands::{PermissionResponse, PermissionState, RequestPermissionsArgs};
use tauri_plugin_tradr::desktop;

#[test]
fn deserialize_permission_response_from_json() {
    let json = r#"{
        "bluetoothScan": "granted",
        "bluetoothAdvertise": "prompt",
        "postNotifications": "denied",
        "foregroundServiceDataSync": "prompt-with-rationale"
    }"#;

    let parsed: PermissionResponse =
        serde_json::from_str(json).expect("permission response deserializes");
    assert_eq!(parsed.get("bluetoothScan"), Some(&PermissionState::Granted));
    assert_eq!(
        parsed.get("bluetoothAdvertise"),
        Some(&PermissionState::Prompt)
    );
    assert_eq!(
        parsed.get("postNotifications"),
        Some(&PermissionState::Denied)
    );
    assert_eq!(
        parsed.get("foregroundServiceDataSync"),
        Some(&PermissionState::PromptWithRationale)
    );
}

#[test]
fn serialize_round_trip_request_permissions_args() {
    let args = RequestPermissionsArgs {
        permissions: Some(vec![
            "bluetoothScan".to_string(),
            "bluetoothConnect".to_string(),
        ]),
    };

    let serialized = serde_json::to_string(&args).expect("serialize args");
    let deserialized: RequestPermissionsArgs =
        serde_json::from_str(&serialized).expect("deserialize args");
    assert_eq!(args.permissions, deserialized.permissions);
}

#[tokio::test]
async fn desktop_request_permissions_returns_granted_for_named_permissions() {
    let requested = vec!["bluetoothScan".to_string(), "fineLocation".to_string()];
    let res = desktop::request_permissions(Some(requested))
        .await
        .expect("desktop request permissions succeeds");
    assert_eq!(res.get("bluetoothScan"), Some(&PermissionState::Granted));
    assert_eq!(res.get("fineLocation"), Some(&PermissionState::Granted));
    assert_eq!(res.len(), 2);
}

#[tokio::test]
async fn desktop_request_permissions_returns_granted_when_unspecified() {
    let res = desktop::request_permissions(None)
        .await
        .expect("desktop request permissions succeeds");
    assert_eq!(res.get("all"), Some(&PermissionState::Granted));
}

#[tokio::test]
async fn desktop_check_permissions_returns_granted() {
    let res = desktop::check_permissions()
        .await
        .expect("desktop check permissions succeeds");
    assert_eq!(res.get("all"), Some(&PermissionState::Granted));
}

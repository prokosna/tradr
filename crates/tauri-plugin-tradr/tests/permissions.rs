//! Integration tests for permission command arguments and responses (WI-M2-006).

use tauri_plugin_tradr::commands::{PermissionResponse, PermissionState, RequestPermissionsArgs};
use tauri_plugin_tradr::desktop;

#[test]
fn deserialize_permission_response_from_json() {
    let json = r#"{
        "postNotifications": "granted",
        "nearbyWifiDevices": "prompt",
        "otherPermission": "denied",
        "foregroundServiceDataSync": "prompt-with-rationale"
    }"#;

    let parsed: PermissionResponse =
        serde_json::from_str(json).expect("permission response deserializes");
    assert_eq!(
        parsed.get("postNotifications"),
        Some(&PermissionState::Granted)
    );
    assert_eq!(
        parsed.get("nearbyWifiDevices"),
        Some(&PermissionState::Prompt)
    );
    assert_eq!(
        parsed.get("otherPermission"),
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
            "postNotifications".to_string(),
            "nearbyWifiDevices".to_string(),
        ]),
    };

    let serialized = serde_json::to_string(&args).expect("serialize args");
    let deserialized: RequestPermissionsArgs =
        serde_json::from_str(&serialized).expect("deserialize args");
    assert_eq!(args.permissions, deserialized.permissions);
}

#[tokio::test]
async fn desktop_request_permissions_returns_granted_for_named_permissions() {
    let requested = vec![
        "postNotifications".to_string(),
        "foregroundServiceDataSync".to_string(),
    ];
    let res = desktop::request_permissions(Some(requested))
        .await
        .expect("desktop request permissions succeeds");
    assert_eq!(
        res.get("postNotifications"),
        Some(&PermissionState::Granted)
    );
    assert_eq!(
        res.get("foregroundServiceDataSync"),
        Some(&PermissionState::Granted)
    );
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

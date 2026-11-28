//! The shape Kotlin's `receiveServiceStatus` resolves with.

use tauri_plugin_tradr::commands::ReceiveServiceStatus;

#[test]
fn a_refused_start_carries_its_reason() {
    let parsed: ReceiveServiceStatus = serde_json::from_str(
        r#"{"running":false,"error":"startForeground: SecurityException: denied"}"#,
    )
    .expect("Kotlin's refusal shape deserializes");
    assert_eq!(
        parsed,
        ReceiveServiceStatus {
            running: false,
            error: Some("startForeground: SecurityException: denied".to_string()),
        }
    );
}

#[test]
fn a_running_service_has_no_error() {
    let parsed: ReceiveServiceStatus = serde_json::from_str(r#"{"running":true,"error":null}"#)
        .expect("Kotlin's running shape deserializes");
    assert!(parsed.running);
    assert_eq!(parsed.error, None);
}

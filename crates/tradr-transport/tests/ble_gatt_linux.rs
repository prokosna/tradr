#![cfg(target_os = "linux")]

use std::io::ErrorKind;

use tradr_core::TransportError;
use tradr_transport::ble::gatt_error;

#[test]
fn gatt_error_maps_every_table_row_and_unlisted_fallback() {
    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotFound),
        TransportError::Unreachable
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::DoesNotExist),
        TransportError::Unreachable
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotAvailable),
        TransportError::Unreachable
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotReady),
        TransportError::Unreachable
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::ServicesUnresolved),
        TransportError::Unreachable
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::ConnectionAttemptFailed),
        TransportError::Unreachable
    );

    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotAuthorized),
        TransportError::Rejected
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotPermitted),
        TransportError::Rejected
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotSupported),
        TransportError::Rejected
    );

    assert_eq!(
        gatt_error(&bluer::ErrorKind::AuthenticationFailed),
        TransportError::AuthenticationFailed
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::AuthenticationRejected),
        TransportError::AuthenticationFailed
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::AuthenticationCanceled),
        TransportError::AuthenticationFailed
    );

    assert_eq!(
        gatt_error(&bluer::ErrorKind::AuthenticationTimeout),
        TransportError::TimedOut
    );
    assert_eq!(
        gatt_error(&bluer::ErrorKind::InProgress),
        TransportError::TimedOut
    );

    assert_eq!(
        gatt_error(&bluer::ErrorKind::NotificationSessionStopped),
        TransportError::Closed
    );

    assert_eq!(
        gatt_error(&bluer::ErrorKind::Failed),
        TransportError::Io(ErrorKind::Other)
    );
}

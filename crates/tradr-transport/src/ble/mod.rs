//! GATT constants and framing helpers for BLE transport links (docs/03, ADR-0019).

use tradr_core::{TransportError, TransportId, tradr_uuid};

/// The transport identifier for BLE GATT links.
pub const BLE_GATT_TRANSPORT_ID: TransportId = TransportId::new("ble-gatt");

/// The 16-bit slot for the Tradr GATT primary service UUID (ADR-0019).
pub const BLE_GATT_SERVICE_SLOT: u16 = 0x0002;

/// The 16-bit slot for the central-to-peripheral characteristic UUID (ADR-0019).
pub const BLE_GATT_CENTRAL_TO_PERIPHERAL_SLOT: u16 = 0x0003;

/// The 16-bit slot for the peripheral-to-central characteristic UUID (ADR-0019).
pub const BLE_GATT_PERIPHERAL_TO_CENTRAL_SLOT: u16 = 0x0004;

/// The 128-bit UUID for the Tradr GATT primary service (ADR-0019).
pub const BLE_GATT_SERVICE_UUID: [u8; 16] = tradr_uuid(BLE_GATT_SERVICE_SLOT);

/// The 128-bit UUID for writing without response from central to peripheral (ADR-0019).
pub const BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID: [u8; 16] =
    tradr_uuid(BLE_GATT_CENTRAL_TO_PERIPHERAL_SLOT);

/// The 128-bit UUID for notifications from peripheral to central (ADR-0019).
pub const BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID: [u8; 16] =
    tradr_uuid(BLE_GATT_PERIPHERAL_TO_CENTRAL_SLOT);

/// Splits a byte stream into the ATT operations one link currently carries.
pub fn operations(bytes: &[u8], mtu: usize) -> Result<Vec<&[u8]>, TransportError> {
    if mtu == 0 {
        return Err(TransportError::Io(std::io::ErrorKind::InvalidInput));
    }
    Ok(bytes.chunks(mtu).collect())
}

/// Decides what one delivery from a notify session means to a `ByteSource`.
pub fn delivery(result: std::io::Result<Vec<u8>>) -> Result<Option<Vec<u8>>, TransportError> {
    match result {
        Ok(bytes) if bytes.is_empty() => Ok(None),
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) => Err(TransportError::Io(e.kind())),
    }
}

mod accept;
pub use accept::accept_link;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{BluerCentral, GattByteSink, GattByteSource, connect, dial, gatt_error};

mod transport;
pub use transport::{BLE_GATT_DIAL_TIMEOUT, BleGattTransport, GattCentral, GattPeripheral};

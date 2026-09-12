//! Transport implementation for BLE GATT links (docs/03).

use std::sync::Arc;
use std::time::Duration;

use tradr_core::{
    BoxFuture, Candidate, Incoming, PeerExpectation, SecureChannel, Transport, TransportError,
    TransportId,
};

use super::BLE_GATT_TRANSPORT_ID;

/// Upper bound on establishing a BLE GATT connection and completing its Noise handshake.
pub const BLE_GATT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Platform seam for the dialling half of a BLE GATT link.
pub trait GattCentral: Send + Sync {
    /// Establishes the link to `address` and completes the initiator handshake over it.
    fn dial<'a>(
        &'a self,
        address: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>>;

    /// Tears down whatever link a dial to `address` established.
    fn abandon<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<(), TransportError>>;
}

/// Platform seam for the listening half of a BLE GATT link.
pub trait GattPeripheral: Send + Sync {
    /// Listens for inbound GATT connections.
    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>>;
}

/// The BLE GATT transport, composing platform-specific central and peripheral halves.
pub struct BleGattTransport {
    central: Option<Arc<dyn GattCentral>>,
    peripheral: Option<Arc<dyn GattPeripheral>>,
}

impl BleGattTransport {
    /// Constructs a BLE GATT transport from the platform halves available.
    pub fn new(
        central: Option<Arc<dyn GattCentral>>,
        peripheral: Option<Arc<dyn GattPeripheral>>,
    ) -> Self {
        Self {
            central,
            peripheral,
        }
    }
}

impl Transport for BleGattTransport {
    fn id(&self) -> TransportId {
        BLE_GATT_TRANSPORT_ID
    }

    fn connect<'a>(
        &'a self,
        candidate: &'a Candidate,
        expect: &'a PeerExpectation,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            let central = match &self.central {
                Some(central) => central,
                None => return Err(TransportError::Io(std::io::ErrorKind::Unsupported)),
            };

            let dial_result = match tokio::time::timeout(
                BLE_GATT_DIAL_TIMEOUT,
                central.dial(candidate.address()),
            )
            .await
            {
                Ok(res) => match res {
                    Ok(channel) => {
                        if let Some(expected_id) = expect.device_id() {
                            if channel.peer() != expected_id {
                                Err(TransportError::AuthenticationFailed)
                            } else {
                                Ok(channel)
                            }
                        } else {
                            Ok(channel)
                        }
                    }
                    Err(err) => Err(err),
                },
                Err(_) => Err(TransportError::TimedOut),
            };

            match dial_result {
                Ok(channel) => Ok(channel),
                Err(err) => {
                    if let Err(abandon_err) = central.abandon(candidate.address()).await {
                        eprintln!(
                            "failed to abandon ble-gatt link for address {}: {}",
                            candidate.address(),
                            abandon_err
                        );
                    }
                    Err(err)
                }
            }
        })
    }

    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        Box::pin(async move {
            match &self.peripheral {
                Some(peripheral) => peripheral.listen().await,
                None => Err(TransportError::Io(std::io::ErrorKind::Unsupported)),
            }
        })
    }
}

//! Linux BLE advertising and scanning over BlueZ and bluer (docs/03, DCR-085).

use std::collections::HashMap;
use std::pin::Pin;

use futures_util::StreamExt;
use tradr_core::BoxFuture;

use crate::advertisement::{SERVICE_DATA_LEN, TRADR_SERVICE_UUID};
use crate::ble::{BleAdvertiser, BleError, BleScanner, ScanReport};

/// Decides which `BleError` variant a BlueZ failure maps onto, confining `Unsupported` to the D4 retreat (docs/03, DCR-085).
pub fn ble_error(kind: &bluer::ErrorKind) -> BleError {
    match kind {
        bluer::ErrorKind::NotSupported => BleError::Unsupported,
        bluer::ErrorKind::NotAuthorized | bluer::ErrorKind::NotPermitted => {
            BleError::PermissionDenied
        }
        bluer::ErrorKind::NotReady
        | bluer::ErrorKind::NotAvailable
        | bluer::ErrorKind::DoesNotExist
        | bluer::ErrorKind::NotFound
        | bluer::ErrorKind::InvalidName(_) => BleError::AdapterUnavailable,
        _ => BleError::Io(std::io::ErrorKind::Other),
    }
}

/// Decides whether received service data constitutes a valid Tradr advertisement (docs/03, DCR-085).
pub fn tradr_scan_report(
    handle: &str,
    service_data: Option<&HashMap<bluer::Uuid, Vec<u8>>>,
) -> Option<ScanReport> {
    let service_data = service_data?;
    let uuid = bluer::Uuid::from_bytes(TRADR_SERVICE_UUID);
    let payload = service_data.get(&uuid)?;
    if payload.len() != SERVICE_DATA_LEN {
        return None;
    }
    ScanReport::new(handle, payload).ok()
}

/// Advertises Tradr's service data over BlueZ (docs/03, ADR-0019).
pub struct BluerAdvertiser {
    adapter: bluer::Adapter,
    handle: Option<bluer::adv::AdvertisementHandle>,
}

impl BluerAdvertiser {
    /// Opens a session on the default adapter.
    pub async fn new() -> Result<Self, BleError> {
        let session = bluer::Session::new()
            .await
            .map_err(|e| ble_error(&e.kind))?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|e| ble_error(&e.kind))?;
        if !adapter.is_powered().await.map_err(|e| ble_error(&e.kind))? {
            adapter
                .set_powered(true)
                .await
                .map_err(|e| ble_error(&e.kind))?;
        }
        Ok(Self {
            adapter,
            handle: None,
        })
    }
}

impl BleAdvertiser for BluerAdvertiser {
    fn start(
        &mut self,
        service_data: [u8; SERVICE_DATA_LEN],
    ) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            self.handle = None;
            let mut service_data_map = std::collections::BTreeMap::new();
            service_data_map.insert(
                bluer::Uuid::from_bytes(TRADR_SERVICE_UUID),
                service_data.to_vec(),
            );
            let adv = bluer::adv::Advertisement {
                advertisement_type: bluer::adv::Type::Peripheral,
                discoverable: Some(true),
                service_data: service_data_map,
                ..Default::default()
            };
            let handle = self
                .adapter
                .advertise(adv)
                .await
                .map_err(|e| ble_error(&e.kind))?;
            self.handle = Some(handle);
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            self.handle = None;
            Ok(())
        })
    }
}

/// Scans for Tradr advertisements over BlueZ (docs/03, DCR-085).
pub struct BluerScanner {
    adapter: bluer::Adapter,
    stream: Pin<Box<dyn futures_util::Stream<Item = bluer::AdapterEvent> + Send>>,
}

impl BluerScanner {
    /// Opens a session on the default adapter and starts LE discovery.
    /// The filter is deliberately not narrowed to the service UUID: BlueZ
    /// matches filter UUIDs against advertised service lists rather than
    /// service data, and BlueZ would then match nothing.
    pub async fn new() -> Result<Self, BleError> {
        let session = bluer::Session::new()
            .await
            .map_err(|e| ble_error(&e.kind))?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|e| ble_error(&e.kind))?;
        if !adapter.is_powered().await.map_err(|e| ble_error(&e.kind))? {
            adapter
                .set_powered(true)
                .await
                .map_err(|e| ble_error(&e.kind))?;
        }
        let filter = bluer::DiscoveryFilter {
            transport: bluer::DiscoveryTransport::Le,
            // Duplicate delivery prevents BleSource from prematurely aging out stationary peers.
            duplicate_data: true,
            // BlueZ filters match Service UUID lists rather than Service Data, yielding silence.
            uuids: std::collections::HashSet::new(),
            ..Default::default()
        };
        adapter
            .set_discovery_filter(filter)
            .await
            .map_err(|e| ble_error(&e.kind))?;
        let stream = adapter
            .discover_devices_with_changes()
            .await
            .map_err(|e| ble_error(&e.kind))?;
        Ok(Self {
            adapter,
            stream: Box::pin(stream),
        })
    }
}

impl BleScanner for BluerScanner {
    fn next_report(&mut self) -> BoxFuture<'_, Result<ScanReport, BleError>> {
        Box::pin(async move {
            loop {
                let event = match self.stream.next().await {
                    Some(event) => event,
                    None => return Err(BleError::Closed),
                };

                match event {
                    bluer::AdapterEvent::DeviceAdded(addr) => {
                        let dev = match self.adapter.device(addr) {
                            Ok(dev) => dev,
                            Err(_) => continue,
                        };
                        let service_data = match dev.service_data().await {
                            Ok(sd) => sd,
                            Err(_) => continue,
                        };
                        let handle = addr.to_string();
                        if let Some(report) = tradr_scan_report(&handle, service_data.as_ref()) {
                            return Ok(report);
                        }
                    }
                    bluer::AdapterEvent::DeviceRemoved(_)
                    | bluer::AdapterEvent::PropertyChanged(_) => {
                        // Lost is evaluated on BleSource's monotonic clock when reports arrive (docs/03).
                    }
                }
            }
        })
    }
}

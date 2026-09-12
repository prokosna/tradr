#![forbid(unsafe_code)]
//! Background BLE discovery runner applying events into shared peer state (docs/03, DCR-107).

use std::sync::Arc;

use tradr_core::{BoxFuture, Clock, DiscoveryEvent, DiscoverySource, PeerList};
use tradr_discovery::{BLE_SOURCE_ID, BleError, BleScanner, BleSource, BroadcastSecrets};

/// Pure function formatting the single log line reported when an event is applied.
pub fn event_line(event: &DiscoveryEvent) -> String {
    match event {
        DiscoveryEvent::Observed(obs) => {
            format!("ble discovery: arrival handle={}", obs.id().key().as_str())
        }
        DiscoveryEvent::Lost(id) => {
            format!("ble discovery: departure handle={}", id.key().as_str())
        }
        _ => "ble discovery: unknown discovery event".to_string(),
    }
}

/// Owns the dependencies needed to drive BLE discovery and merge events into the peer list.
pub struct BleDiscovery {
    secrets: Box<dyn BroadcastSecrets>,
    clock: Box<dyn Clock + Send + Sync>,
    peers: Arc<tokio::sync::Mutex<PeerList>>,
}

impl BleDiscovery {
    /// Creates a new BLE discovery runner.
    pub fn new(
        secrets: Box<dyn BroadcastSecrets>,
        clock: Box<dyn Clock + Send + Sync>,
        peers: Arc<tokio::sync::Mutex<PeerList>>,
    ) -> Self {
        Self {
            secrets,
            clock,
            peers,
        }
    }

    /// Drives the discovery loop until the scanner closes or an error occurs.
    pub async fn run(self, scanner: Result<Box<dyn BleScanner>, BleError>) {
        let scanner = match scanner {
            Ok(s) => s,
            Err(cause) => {
                eprintln!("ble discovery: scanner unavailable: {cause}");
                return;
            }
        };

        let mut source = BleSource::new(scanner, self.secrets, self.clock);
        loop {
            let event = match source.next_event().await {
                Ok(event) => event,
                Err(cause) => {
                    eprintln!("ble discovery: source error: {cause}");
                    return;
                }
            };

            let line = event_line(&event);
            {
                let mut peers = self.peers.lock().await;
                if let Err(cause) = peers.apply(BLE_SOURCE_ID, event) {
                    eprintln!("ble discovery: failed to apply event: {cause}");
                    return;
                }
            }
            println!("{line}");
        }
    }
}

/// Spawns the background BLE discovery task on Tauri's async runtime.
pub fn spawn_ble_discovery(
    discovery: BleDiscovery,
    open: BoxFuture<'static, Result<Box<dyn BleScanner>, BleError>>,
) {
    tauri::async_runtime::spawn(async move {
        let scanner = open.await;
        discovery.run(scanner).await;
    });
}

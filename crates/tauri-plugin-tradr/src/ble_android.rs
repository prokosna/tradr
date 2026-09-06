#![forbid(unsafe_code)]
//! Android BLE advertising and scanning glue (docs/03, DCR-086).
//! Mappings and report queue carry no cfg so host cargo test validates them.

use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tradr_discovery::{BleError, SERVICE_DATA_LEN, ScanReport};

#[cfg(target_os = "android")]
use tauri::{Runtime, ipc::Channel, plugin::PluginHandle};
#[cfg(target_os = "android")]
use tradr_core::BoxFuture;

/// What a Kotlin BLE command resolves with (docs/03, DCR-086).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum BleOutcome {
    /// Command completed successfully.
    Ok,
    /// Hardware feature or role is not supported on this device.
    Unsupported,
    /// Permission required for BLE operation was denied.
    PermissionDenied,
    /// Bluetooth adapter is disabled or unavailable.
    AdapterUnavailable,
    /// Advertising failed on Android's AdvertiseCallback.
    AdvertiseFailed {
        /// Android AdvertiseCallback error code.
        code: i32,
    },
}

/// Maps Android AdvertiseCallback failure codes to BleError (docs/03, DCR-086).
pub fn advertise_error(code: i32) -> BleError {
    match code {
        5 => BleError::Unsupported,
        1 => BleError::Io(std::io::ErrorKind::InvalidData),
        _ => BleError::Io(std::io::ErrorKind::Other),
    }
}

/// Maps Android ScanCallback failure codes to BleError (docs/03, DCR-086).
pub fn scan_error(code: i32) -> BleError {
    match code {
        4 => BleError::Unsupported,
        _ => BleError::Io(std::io::ErrorKind::Other),
    }
}

/// Extracts any BleError from a resolved BleOutcome (docs/03, DCR-086).
pub fn outcome_error(outcome: &BleOutcome) -> Option<BleError> {
    match outcome {
        BleOutcome::Ok => None,
        BleOutcome::Unsupported => Some(BleError::Unsupported),
        BleOutcome::PermissionDenied => Some(BleError::PermissionDenied),
        BleOutcome::AdapterUnavailable => Some(BleError::AdapterUnavailable),
        BleOutcome::AdvertiseFailed { code } => Some(advertise_error(*code)),
    }
}

/// What Kotlin pushes through the scan channel (docs/03, DCR-086).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "push",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ScanPush {
    /// Observation report containing device handle and base64 service data.
    Report {
        /// Device handle string reported by Android.
        handle: String,
        /// Base64-encoded advertisement service data.
        service_data: String,
    },
    /// Radio scan failure reported by ScanCallback.
    Failed {
        /// Android ScanCallback error code.
        code: i32,
    },
}

/// Converts a ScanPush into an optional scan report result (docs/03, DCR-086).
pub fn scan_push_entry(push: &ScanPush) -> Option<Result<ScanReport, BleError>> {
    match push {
        ScanPush::Failed { code } => Some(Err(scan_error(*code))),
        ScanPush::Report {
            handle,
            service_data,
        } => {
            let decoded = STANDARD.decode(service_data).ok()?;
            if decoded.len() != SERVICE_DATA_LEN {
                return None;
            }
            ScanReport::new(handle, &decoded).ok().map(Ok)
        }
    }
}

/// Maximum capacity of the bounded queue before oldest items are evicted.
pub const SCAN_QUEUE_CAPACITY: usize = 64;

/// Bounded queue between the Android binder thread and async Rust (docs/03, DCR-086).
pub struct ScanQueue {
    inner: Mutex<VecDeque<Result<ScanReport, BleError>>>,
    notify: Notify,
}

impl Default for ScanQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanQueue {
    /// Creates an empty bounded scan queue.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(SCAN_QUEUE_CAPACITY)),
            notify: Notify::new(),
        }
    }

    /// Pushes an entry, evicting the oldest item if the queue is full.
    pub fn push(&self, item: Result<ScanReport, BleError>) {
        let mut queue = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if queue.len() >= SCAN_QUEUE_CAPACITY {
            match queue.pop_front() {
                Some(_) | None => {}
            }
        }
        queue.push_back(item);
        drop(queue);
        self.notify.notify_one();
    }

    /// Asynchronously yields the next queued scan entry in order, waiting if empty.
    pub async fn pop(&self) -> Result<ScanReport, BleError> {
        loop {
            let notified = self.notify.notified();
            {
                let mut queue = match self.inner.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(item) = queue.pop_front() {
                    return item;
                }
            }
            notified.await;
        }
    }
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartAdvertisingArgs {
    service_data: String,
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartScanArgs {
    channel: Channel<serde_json::Value>,
}

/// Android advertiser forwarding to Kotlin via TradrPlugin (docs/03, DCR-086).
#[cfg(target_os = "android")]
pub struct AndroidBleAdvertiser<R: Runtime> {
    handle: PluginHandle<R>,
}

#[cfg(target_os = "android")]
impl<R: Runtime> AndroidBleAdvertiser<R> {
    /// Creates a new Android BLE advertiser from a plugin handle.
    pub fn new(handle: PluginHandle<R>) -> Self {
        Self { handle }
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> tradr_discovery::BleAdvertiser for AndroidBleAdvertiser<R> {
    fn start(
        &mut self,
        service_data: [u8; SERVICE_DATA_LEN],
    ) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            let encoded = STANDARD.encode(service_data);
            let outcome: BleOutcome = self
                .handle
                .run_mobile_plugin_async(
                    "startBleAdvertising",
                    StartAdvertisingArgs {
                        service_data: encoded,
                    },
                )
                .await
                .map_err(|_err| BleError::Io(std::io::ErrorKind::Other))?;

            match outcome_error(&outcome) {
                Some(err) => Err(err),
                None => Ok(()),
            }
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), BleError>> {
        Box::pin(async move {
            let outcome: BleOutcome = self
                .handle
                .run_mobile_plugin_async("stopBleAdvertising", ())
                .await
                .map_err(|_err| BleError::Io(std::io::ErrorKind::Other))?;

            match outcome_error(&outcome) {
                Some(err) => Err(err),
                None => Ok(()),
            }
        })
    }
}

/// Android scanner forwarding to Kotlin via TradrPlugin and ScanQueue (docs/03, DCR-086).
#[cfg(target_os = "android")]
pub struct AndroidBleScanner<R: Runtime> {
    handle: PluginHandle<R>,
    queue: std::sync::Arc<ScanQueue>,
}

#[cfg(target_os = "android")]
impl<R: Runtime> AndroidBleScanner<R> {
    /// Initializes scanner with a channel callback and starts the radio scan.
    pub async fn new(handle: PluginHandle<R>) -> Result<Self, BleError> {
        let queue = std::sync::Arc::new(ScanQueue::new());
        let queue_clone = std::sync::Arc::clone(&queue);
        let channel = Channel::new(move |body| {
            if let Ok(push) = body.deserialize::<ScanPush>()
                && let Some(entry) = scan_push_entry(&push)
            {
                queue_clone.push(entry);
            }
            Ok(())
        });

        let outcome: BleOutcome = handle
            .run_mobile_plugin_async("startBleScan", StartScanArgs { channel })
            .await
            .map_err(|_err| BleError::Io(std::io::ErrorKind::Other))?;

        match outcome_error(&outcome) {
            Some(err) => Err(err),
            None => Ok(Self { handle, queue }),
        }
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> tradr_discovery::BleScanner for AndroidBleScanner<R> {
    fn next_report(&mut self) -> BoxFuture<'_, Result<ScanReport, BleError>> {
        Box::pin(async move { self.queue.pop().await })
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> Drop for AndroidBleScanner<R> {
    fn drop(&mut self) {
        match self
            .handle
            .run_mobile_plugin::<BleOutcome>("stopBleScan", ())
        {
            Ok(_) => {}
            Err(err) => {
                eprintln!("failed to stop BLE scan on drop: {err}");
            }
        }
    }
}

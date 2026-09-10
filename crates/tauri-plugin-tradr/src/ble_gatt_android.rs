#![forbid(unsafe_code)]
//! Android BLE GATT server byte streams (docs/03, DCR-099, DCR-101).
//! Mappings, link queue, and registry carry no cfg so host cargo test validates them.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tradr_core::{BoxFuture, TransportError};
use tradr_transport::noise::ByteSource;

#[cfg(target_os = "android")]
use tauri::{Runtime, plugin::PluginHandle};
#[cfg(target_os = "android")]
use tradr_transport::noise::ByteSink;

/// What a Kotlin GATT server command resolves with (docs/03, DCR-101).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum GattServerOutcome {
    /// GATT server started or stopped successfully.
    Ok,
    /// Hardware feature or role is not supported on this device.
    Unsupported,
    /// Required platform permissions were denied.
    PermissionDenied,
    /// Bluetooth adapter is disabled or unavailable.
    AdapterUnavailable,
    /// Android GATT server failed to start or register service.
    ServerFailed,
}

/// What a Kotlin GATT send or close command resolves with (docs/03, DCR-101).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum GattSendOutcome {
    /// Notification send or link close completed successfully.
    Ok,
    /// Target device is no longer connected.
    NoSuchLink,
    /// Platform refused or failed the notification.
    SendFailed,
}

/// Maps a resolved GattServerOutcome to an optional transport error.
pub fn server_outcome_error(outcome: &GattServerOutcome) -> Option<TransportError> {
    match outcome {
        GattServerOutcome::Ok => None,
        GattServerOutcome::Unsupported => Some(TransportError::Io(ErrorKind::Unsupported)),
        GattServerOutcome::PermissionDenied => {
            Some(TransportError::Io(ErrorKind::PermissionDenied))
        }
        GattServerOutcome::AdapterUnavailable => Some(TransportError::Io(ErrorKind::NotConnected)),
        GattServerOutcome::ServerFailed => Some(TransportError::Io(ErrorKind::Other)),
    }
}

/// Maps a resolved GattSendOutcome to an optional transport error.
pub fn send_outcome_error(outcome: &GattSendOutcome) -> Option<TransportError> {
    match outcome {
        GattSendOutcome::Ok => None,
        GattSendOutcome::NoSuchLink => Some(TransportError::Closed),
        GattSendOutcome::SendFailed => Some(TransportError::Io(ErrorKind::Other)),
    }
}

/// What Kotlin pushes through the GATT server channel (docs/03, DCR-101).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "push",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum GattPush {
    /// Client Characteristic Configuration descriptor subscribed for notifications.
    Subscribed {
        /// Remote peer address string.
        handle: String,
    },
    /// Central-to-peripheral characteristic write containing base64 payload.
    Bytes {
        /// Remote peer address string.
        handle: String,
        /// Base64-encoded delivery bytes.
        data: String,
    },
    /// Client Characteristic Configuration descriptor unsubscribed.
    Unsubscribed {
        /// Remote peer address string.
        handle: String,
    },
    /// Remote peer disconnected at the Link Layer.
    Disconnected {
        /// Remote peer address string.
        handle: String,
    },
}

/// Bound on undelivered inbound bytes held for a single link (docs/03, DCR-101).
pub const GATT_LINK_QUEUE_CAPACITY: usize = 8192;

struct GattLinkInner {
    queue: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    ended: bool,
    latched_error: Option<TransportError>,
}

/// Inbound byte stream for one GATT link (docs/03, DCR-101).
pub struct GattLink {
    inner: Mutex<GattLinkInner>,
    notify: Notify,
}

impl Default for GattLink {
    fn default() -> Self {
        Self::new()
    }
}

impl GattLink {
    /// Creates an empty GATT link byte stream.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(GattLinkInner {
                queue: VecDeque::new(),
                queued_bytes: 0,
                ended: false,
                latched_error: None,
            }),
            notify: Notify::new(),
        }
    }

    /// Appends inbound bytes to the queue, or latches OutOfMemory if the capacity would overflow.
    pub fn push(&self, delivery: Vec<u8>) {
        if delivery.is_empty() {
            return;
        }
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.latched_error.is_some() || inner.ended {
            return;
        }
        if inner.queued_bytes.saturating_add(delivery.len()) > GATT_LINK_QUEUE_CAPACITY {
            inner.latched_error = Some(TransportError::Io(ErrorKind::OutOfMemory));
            inner.queue.clear();
            inner.queued_bytes = 0;
            drop(inner);
            self.notify.notify_one();
            return;
        }
        inner.queued_bytes += delivery.len();
        inner.queue.push_back(delivery);
        drop(inner);
        self.notify.notify_one();
    }

    pub(crate) fn latch_error(&self, err: TransportError) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.latched_error.is_some() {
            return;
        }
        inner.latched_error = Some(err);
        inner.queue.clear();
        inner.queued_bytes = 0;
        drop(inner);
        self.notify.notify_one();
    }

    /// Signals that the remote central disconnected or unsubscribed.
    pub fn end(&self) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.ended {
            return;
        }
        inner.ended = true;
        drop(inner);
        self.notify.notify_one();
    }

    /// Asynchronously reads the next delivery chunk in order, waiting when empty.
    pub async fn pop(&self) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            let notified = self.notify.notified();
            {
                let mut inner = match self.inner.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(err) = inner.latched_error {
                    return Err(err);
                }
                if let Some(chunk) = inner.queue.pop_front() {
                    inner.queued_bytes = inner.queued_bytes.saturating_sub(chunk.len());
                    return Ok(Some(chunk));
                }
                if inner.ended {
                    return Ok(None);
                }
            }
            notified.await;
        }
    }
}

struct GattLinksInner {
    links: HashMap<String, Arc<GattLink>>,
    incoming: VecDeque<String>,
}

/// Registry of active GATT links keyed by remote device handle (docs/03, DCR-101).
pub struct GattLinks {
    inner: Mutex<GattLinksInner>,
    notify: Notify,
}

impl Default for GattLinks {
    fn default() -> Self {
        Self::new()
    }
}

impl GattLinks {
    /// Creates an empty GATT link registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(GattLinksInner {
                links: HashMap::new(),
                incoming: VecDeque::new(),
            }),
            notify: Notify::new(),
        }
    }

    /// Applies a push event from Kotlin to the corresponding link state.
    pub fn apply(&self, push: &GattPush) {
        match push {
            GattPush::Subscribed { handle } => {
                let mut inner = match self.inner.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(old_link) = inner.links.get(handle) {
                    old_link.end();
                }
                let new_link = Arc::new(GattLink::new());
                inner.links.insert(handle.clone(), new_link);
                inner.incoming.push_back(handle.clone());
                drop(inner);
                self.notify.notify_one();
            }
            GattPush::Bytes { handle, data } => {
                let link = {
                    let inner = match self.inner.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    inner.links.get(handle).cloned()
                };
                let Some(link) = link else {
                    return;
                };
                match STANDARD.decode(data) {
                    Ok(bytes) => link.push(bytes),
                    Err(_) => {
                        link.latch_error(TransportError::Io(ErrorKind::InvalidData));
                    }
                }
            }
            GattPush::Unsubscribed { handle } | GattPush::Disconnected { handle } => {
                let link = {
                    let mut inner = match self.inner.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    inner.links.remove(handle)
                };
                if let Some(link) = link {
                    link.end();
                }
            }
        }
    }

    /// Asynchronously returns the next subscribed handle in arrival order.
    pub async fn next_link(&self) -> String {
        loop {
            let notified = self.notify.notified();
            {
                let mut inner = match self.inner.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(handle) = inner.incoming.pop_front() {
                    return handle;
                }
            }
            notified.await;
        }
    }

    /// Returns the active link for handle, or None if not currently subscribed.
    pub fn link(&self, handle: &str) -> Option<Arc<GattLink>> {
        let inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.links.get(handle).cloned()
    }
}

/// Byte source consuming an inbound GATT link's deliveries (docs/03, DCR-101).
pub struct GattLinkSource {
    link: Arc<GattLink>,
}

impl GattLinkSource {
    /// Creates a new byte source wrapping an inbound GATT link.
    pub fn new(link: Arc<GattLink>) -> Self {
        Self { link }
    }
}

impl ByteSource for GattLinkSource {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { self.link.pop().await })
    }
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendBleGattBytesArgs {
    handle: String,
    data: String,
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CloseBleGattLinkArgs {
    handle: String,
}

/// Transmits outbound bytes to a connected central over Android GATT (docs/03, DCR-101).
#[cfg(target_os = "android")]
pub struct GattLinkSink<R: Runtime> {
    handle: PluginHandle<R>,
    link_handle: String,
}

#[cfg(target_os = "android")]
impl<R: Runtime> GattLinkSink<R> {
    /// Creates a new byte sink wrapping an active GATT link handle.
    pub fn new(handle: PluginHandle<R>, link_handle: String) -> Self {
        Self {
            handle,
            link_handle,
        }
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> ByteSink for GattLinkSink<R> {
    fn send_bytes<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let encoded = STANDARD.encode(bytes);
            let outcome: GattSendOutcome = self
                .handle
                .run_mobile_plugin_async(
                    "sendBleGattBytes",
                    SendBleGattBytesArgs {
                        handle: self.link_handle.clone(),
                        data: encoded,
                    },
                )
                .await
                .map_err(|_err| TransportError::Io(ErrorKind::Other))?;

            match send_outcome_error(&outcome) {
                Some(err) => Err(err),
                None => Ok(()),
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            let outcome: GattSendOutcome = self
                .handle
                .run_mobile_plugin_async(
                    "closeBleGattLink",
                    CloseBleGattLinkArgs {
                        handle: self.link_handle.clone(),
                    },
                )
                .await
                .map_err(|_err| TransportError::Io(ErrorKind::Other))?;

            match send_outcome_error(&outcome) {
                Some(TransportError::Closed) | None => Ok(()),
                Some(err) => Err(err),
            }
        })
    }
}

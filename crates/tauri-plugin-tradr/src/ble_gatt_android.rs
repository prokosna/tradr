#![forbid(unsafe_code)]
//! Android BLE GATT server byte streams (docs/03, DCR-099, DCR-101).
//! Mappings, link queue, and registry carry no cfg so host cargo test validates them.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;
use tradr_core::{BoxFuture, Incoming, SecureChannel, TransportError};
use tradr_transport::noise::ByteSource;

#[cfg(target_os = "android")]
use tauri::{Runtime, ipc::Channel, plugin::PluginHandle};
#[cfg(target_os = "android")]
use tradr_core::{Clock, KeyBinding, KeyBindingVerifier, KeyStore, Rng};
#[cfg(target_os = "android")]
use tradr_transport::ble::accept_link;
#[cfg(target_os = "android")]
use tradr_transport::noise::{ByteSink, Responder, map_noise_error};

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

/// Seam decoupling the GATT server and Link Layer from the accept loop (docs/03, DCR-102).
pub trait GattAcceptor: Send + Sync + 'static {
    /// Asynchronously waits for the next subscribed link handle.
    fn next_link(&self) -> BoxFuture<'_, String>;

    /// Completes the Noise handshake for the given link handle, returning an authenticated channel.
    fn handshake(
        self: Arc<Self>,
        handle: String,
    ) -> BoxFuture<'static, Result<Box<dyn SecureChannel>, TransportError>>;
}

/// Inbound listener accepting authenticated BLE GATT channels (docs/03, DCR-102).
pub struct GattIncoming {
    rx: mpsc::Receiver<Box<dyn SecureChannel>>,
    pump_task: tokio::task::JoinHandle<()>,
}

impl GattIncoming {
    /// Creates a new GATT incoming listener driving handshakes over the given acceptor.
    pub fn new(acceptor: Arc<dyn GattAcceptor>) -> Self {
        let (tx, rx) = mpsc::channel(1);
        let pump_task = tokio::spawn(async move {
            let mut handshakes = JoinSet::new();
            loop {
                while handshakes.try_join_next().is_some() {}

                let handle = acceptor.next_link().await;
                let acceptor_clone = Arc::clone(&acceptor);
                let tx_clone = tx.clone();
                handshakes.spawn(async move {
                    match acceptor_clone.handshake(handle.clone()).await {
                        Ok(channel) => {
                            if tx_clone.send(channel).await.is_err() {
                                eprintln!(
                                    "BLE GATT incoming channel discarded: listener dropped before accepting handle {handle}"
                                );
                            }
                        }
                        Err(err) => {
                            eprintln!("BLE GATT handshake failed for handle {handle}: {err}");
                        }
                    }
                });
            }
        });

        Self { rx, pump_task }
    }
}

impl Drop for GattIncoming {
    fn drop(&mut self) {
        self.pump_task.abort();
    }
}

impl Incoming for GattIncoming {
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            match self.rx.recv().await {
                Some(channel) => Ok(channel),
                None => Err(TransportError::Closed),
            }
        })
    }
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartBleGattServerArgs {
    channel: Channel,
}

/// GATT acceptor backed by Android BluetoothGattServer (docs/03, DCR-101, DCR-102).
#[cfg(target_os = "android")]
pub struct AndroidGattAcceptor<R: Runtime> {
    handle: PluginHandle<R>,
    links: Arc<GattLinks>,
    key_store: Arc<dyn KeyStore>,
    rng: Arc<dyn Rng + Send + Sync>,
    verifier: Arc<dyn KeyBindingVerifier>,
    binding: KeyBinding,
    clock: Arc<dyn Clock + Send + Sync>,
}

#[cfg(target_os = "android")]
impl<R: Runtime> AndroidGattAcceptor<R> {
    /// Starts the Android GATT server and initializes the link registry.
    pub async fn new(
        handle: PluginHandle<R>,
        key_store: Arc<dyn KeyStore>,
        rng: Arc<dyn Rng + Send + Sync>,
        verifier: Arc<dyn KeyBindingVerifier>,
        binding: KeyBinding,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, TransportError> {
        let links = Arc::new(GattLinks::new());
        let links_clone = Arc::clone(&links);
        let channel = Channel::new(move |body| {
            if let Ok(push) = body.deserialize::<GattPush>() {
                links_clone.apply(&push);
            }
            Ok(())
        });

        let outcome: GattServerOutcome = handle
            .run_mobile_plugin_async("startBleGattServer", StartBleGattServerArgs { channel })
            .await
            .map_err(|_err| TransportError::Io(ErrorKind::Other))?;

        if let Some(err) = server_outcome_error(&outcome) {
            return Err(err);
        }

        Ok(Self {
            handle,
            links,
            key_store,
            rng,
            verifier,
            binding,
            clock,
        })
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> Drop for AndroidGattAcceptor<R> {
    fn drop(&mut self) {
        match self
            .handle
            .run_mobile_plugin::<GattServerOutcome>("stopBleGattServer", ())
        {
            Ok(_) => {}
            Err(err) => {
                eprintln!("failed to stop BLE GATT server on drop: {err}");
            }
        }
    }
}

#[cfg(target_os = "android")]
impl<R: Runtime> GattAcceptor for AndroidGattAcceptor<R> {
    fn next_link(&self) -> BoxFuture<'_, String> {
        Box::pin(self.links.next_link())
    }

    fn handshake(
        self: Arc<Self>,
        handle: String,
    ) -> BoxFuture<'static, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            let link = self.links.link(&handle).ok_or(TransportError::Closed)?;
            let source = GattLinkSource::new(link);
            let sink = GattLinkSink::new(self.handle.clone(), handle);
            let responder = Responder::new(
                Arc::clone(&self.key_store),
                Arc::clone(&self.rng),
                Arc::clone(&self.verifier),
                self.binding.clone(),
            )
            .map_err(map_noise_error)?;
            let channel = accept_link(sink, source, responder, &*self.clock).await?;
            Ok(Box::new(channel) as Box<dyn SecureChannel>)
        })
    }
}

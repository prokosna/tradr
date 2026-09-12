//! Linux GATT client implementation using BlueZ and bluer (docs/03, DCR-099).

use std::io::ErrorKind;
use std::sync::Arc;

use tokio::sync::Mutex;
use tradr_core::{
    BoxFuture, Clock, KeyBinding, KeyBindingVerifier, KeyStore, Rng, SecureChannel, TransportError,
};
use tradr_proto::mux::StreamOpener;

use super::{
    BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID, BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID,
    BLE_GATT_SERVICE_UUID, BLE_GATT_TRANSPORT_ID, GattCentral, delivery, operations,
};
use crate::noise::{
    BLE_GATT_MAX_FRAME_SIZE, BLE_GATT_MAX_RECORD, ByteSink, ByteSource, Initiator, LinkSink,
    NoiseChannel, NoiseChannelConfig, RecordSink, RecordSource, handshake_as_initiator,
    map_noise_error,
};

/// Maps a BlueZ error kind onto the corresponding transport error.
pub fn gatt_error(kind: &bluer::ErrorKind) -> TransportError {
    match kind {
        bluer::ErrorKind::NotFound
        | bluer::ErrorKind::DoesNotExist
        | bluer::ErrorKind::NotAvailable
        | bluer::ErrorKind::NotReady
        | bluer::ErrorKind::ServicesUnresolved
        | bluer::ErrorKind::ConnectionAttemptFailed => TransportError::Unreachable,
        bluer::ErrorKind::NotAuthorized
        | bluer::ErrorKind::NotPermitted
        | bluer::ErrorKind::NotSupported => TransportError::Rejected,
        bluer::ErrorKind::AuthenticationFailed
        | bluer::ErrorKind::AuthenticationRejected
        | bluer::ErrorKind::AuthenticationCanceled => TransportError::AuthenticationFailed,
        bluer::ErrorKind::AuthenticationTimeout | bluer::ErrorKind::InProgress => {
            TransportError::TimedOut
        }
        bluer::ErrorKind::NotificationSessionStopped => TransportError::Closed,
        _ => TransportError::Io(ErrorKind::Other),
    }
}

/// Transmits bytes across a GATT characteristic using write without response.
pub struct GattByteSink {
    // The mutex keeps concurrent senders from interleaving pieces of two byte streams.
    writer: Mutex<Option<bluer::gatt::CharacteristicWriter>>,
}

impl GattByteSink {
    fn new(writer: bluer::gatt::CharacteristicWriter) -> Self {
        Self {
            writer: Mutex::new(Some(writer)),
        }
    }
}

impl ByteSink for GattByteSink {
    fn send_bytes<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let guard = self.writer.lock().await;
            let writer = guard.as_ref().ok_or(TransportError::Closed)?;
            let ops = operations(bytes, writer.mtu())?;
            for op in ops {
                writer
                    .send(op)
                    .await
                    .map_err(|e| TransportError::Io(e.kind()))?;
            }
            Ok(())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            let mut guard = self.writer.lock().await;
            *guard = None;
            Ok(())
        })
    }
}

/// Receives bytes from a GATT characteristic notification session.
pub struct GattByteSource {
    reader: bluer::gatt::CharacteristicReader,
}

impl GattByteSource {
    fn new(reader: bluer::gatt::CharacteristicReader) -> Self {
        Self { reader }
    }
}

impl ByteSource for GattByteSource {
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { delivery(self.reader.recv().await) })
    }
}

/// Connects to a remote peripheral, acquires both characteristics, and returns the byte streams.
pub async fn connect(
    adapter: &bluer::Adapter,
    address: bluer::Address,
) -> Result<(GattByteSink, GattByteSource), TransportError> {
    let device = adapter.device(address).map_err(|e| gatt_error(&e.kind))?;
    if !device
        .is_connected()
        .await
        .map_err(|e| gatt_error(&e.kind))?
    {
        device.connect().await.map_err(|e| gatt_error(&e.kind))?;
    }

    let service_uuid = bluer::Uuid::from_bytes(BLE_GATT_SERVICE_UUID);
    let mut matched_service = None;
    for service in device.services().await.map_err(|e| gatt_error(&e.kind))? {
        if service.uuid().await.map_err(|e| gatt_error(&e.kind))? == service_uuid {
            matched_service = Some(service);
            break;
        }
    }
    let service = matched_service.ok_or(TransportError::Unreachable)?;

    let c2p_uuid = bluer::Uuid::from_bytes(BLE_GATT_CENTRAL_TO_PERIPHERAL_UUID);
    let p2c_uuid = bluer::Uuid::from_bytes(BLE_GATT_PERIPHERAL_TO_CENTRAL_UUID);
    let mut c2p_char = None;
    let mut p2c_char = None;
    for characteristic in service
        .characteristics()
        .await
        .map_err(|e| gatt_error(&e.kind))?
    {
        let uuid = characteristic
            .uuid()
            .await
            .map_err(|e| gatt_error(&e.kind))?;
        if uuid == c2p_uuid {
            c2p_char = Some(characteristic);
        } else if uuid == p2c_uuid {
            p2c_char = Some(characteristic);
        }
    }
    let c2p = c2p_char.ok_or(TransportError::Unreachable)?;
    let p2c = p2c_char.ok_or(TransportError::Unreachable)?;

    let reader = p2c.notify_io().await.map_err(|e| gatt_error(&e.kind))?;
    let writer = c2p.write_io().await.map_err(|e| gatt_error(&e.kind))?;

    Ok((GattByteSink::new(writer), GattByteSource::new(reader)))
}

/// Dials a remote peripheral and performs the Noise handshake, returning an authenticated channel.
pub async fn dial(
    adapter: &bluer::Adapter,
    address: bluer::Address,
    initiator: Initiator,
    clock: &(dyn Clock + Sync),
) -> Result<NoiseChannel, TransportError> {
    let start = clock.monotonic_now();
    let (sink, source) = connect(adapter, address).await?;
    let sink: Arc<dyn LinkSink> = Arc::new(RecordSink::new(sink, BLE_GATT_MAX_RECORD));
    let mut source = RecordSource::new(source, BLE_GATT_MAX_RECORD);
    let session = handshake_as_initiator(initiator, &*sink, &mut source).await?;
    let rtt = clock.monotonic_now().duration_since(start);
    let config = NoiseChannelConfig {
        transport: BLE_GATT_TRANSPORT_ID,
        opener: StreamOpener::Dialler,
        max_frame_size: BLE_GATT_MAX_FRAME_SIZE,
        record_limit: BLE_GATT_MAX_FRAME_SIZE,
        rtt,
    };
    NoiseChannel::new(session, sink, Box::new(source), config)
}

/// Linux BLE central implementation using BlueZ.
pub struct BluerCentral {
    adapter: bluer::Adapter,
    key_store: Arc<dyn KeyStore>,
    rng: Arc<dyn Rng + Send + Sync>,
    verifier: Arc<dyn KeyBindingVerifier>,
    binding: KeyBinding,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl BluerCentral {
    /// Creates a new Linux BLE central instance.
    pub fn new(
        adapter: bluer::Adapter,
        key_store: Arc<dyn KeyStore>,
        rng: Arc<dyn Rng + Send + Sync>,
        verifier: Arc<dyn KeyBindingVerifier>,
        binding: KeyBinding,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            adapter,
            key_store,
            rng,
            verifier,
            binding,
            clock,
        }
    }
}

impl GattCentral for BluerCentral {
    fn dial<'a>(
        &'a self,
        address: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            let addr = address
                .parse::<bluer::Address>()
                .map_err(|_| TransportError::Unreachable)?;
            let initiator = Initiator::new(
                Arc::clone(&self.key_store),
                Arc::clone(&self.rng),
                Arc::clone(&self.verifier),
                self.binding.clone(),
            )
            .map_err(map_noise_error)?;
            let channel = dial(&self.adapter, addr, initiator, &*self.clock).await?;
            Ok(Box::new(channel) as Box<dyn SecureChannel>)
        })
    }

    fn abandon<'a>(&'a self, address: &'a str) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let addr = address
                .parse::<bluer::Address>()
                .map_err(|_| TransportError::Unreachable)?;
            let device = self.adapter.device(addr).map_err(|e| gatt_error(&e.kind))?;
            device.disconnect().await.map_err(|e| gatt_error(&e.kind))?;
            Ok(())
        })
    }
}

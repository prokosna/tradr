//! Length-prefixed record framing over byte-oriented links (WI-M7-007g).

use tradr_core::{BoxFuture, TransportError};

use super::link::{LinkSink, LinkSource};

/// The largest record `ble-gatt` moves: docs/04's 512-byte mux record plus
/// Poly1305's 16-byte tag, as specified in docs/03.
pub const BLE_GATT_MAX_RECORD: u16 = 528;

/// Transmits a byte stream over a connection whose operation boundaries carry no meaning.
pub trait ByteSink: Send + Sync {
    /// Delivers the bytes in order, chopping them to whatever the link carries in one operation,
    /// and the MTU is never seen above it.
    fn send_bytes<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>>;

    /// Shuts down the transmission direction of the byte stream.
    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>>;
}

/// Receives an incoming byte stream from a connection whose operation boundaries carry no meaning.
pub trait ByteSource: Send {
    /// Yields whatever arrived, with no record boundary of its own, and `Ok(None)` means the link ended.
    fn recv_bytes(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;
}

/// Frames outgoing records with a two-byte big-endian length prefix onto a byte sink.
pub struct RecordSink<S> {
    inner: S,
    max_record: u16,
}

impl<S: ByteSink> RecordSink<S> {
    /// Wraps `inner` with a maximum record size bound.
    pub fn new(inner: S, max_record: u16) -> Self {
        Self { inner, max_record }
    }
}

impl<S: ByteSink> LinkSink for RecordSink<S> {
    fn send_record<'a>(&'a self, record: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if record.is_empty() || record.len() > self.max_record as usize {
                return Err(TransportError::Io(std::io::ErrorKind::InvalidInput));
            }
            let len_bytes = (record.len() as u16).to_be_bytes();
            let mut wire = Vec::with_capacity(2 + record.len());
            wire.extend_from_slice(&len_bytes);
            wire.extend_from_slice(record);
            self.inner.send_bytes(&wire).await
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        self.inner.close()
    }
}

/// Reassembles length-prefixed records from an incoming byte source.
pub struct RecordSource<S> {
    inner: S,
    max_record: u16,
    buf: Vec<u8>,
    latched_error: Option<TransportError>,
}

impl<S: ByteSource> RecordSource<S> {
    /// Wraps `inner` with a maximum record size bound.
    pub fn new(inner: S, max_record: u16) -> Self {
        Self {
            inner,
            max_record,
            buf: Vec::new(),
            latched_error: None,
        }
    }
}

impl<S: ByteSource> LinkSource for RecordSource<S> {
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move {
            if let Some(err) = self.latched_error {
                return Err(err);
            }

            loop {
                if self.buf.len() >= 2 {
                    let announced = u16::from_be_bytes([self.buf[0], self.buf[1]]);
                    if announced == 0 || announced > self.max_record {
                        let err = TransportError::Io(std::io::ErrorKind::InvalidData);
                        self.latched_error = Some(err);
                        self.buf.clear();
                        return Err(err);
                    }
                    let total_len = 2 + announced as usize;
                    if self.buf.len() >= total_len {
                        let record = self.buf[2..total_len].to_vec();
                        self.buf.drain(..total_len);
                        return Ok(Some(record));
                    }
                }

                let delivery = match self.inner.recv_bytes().await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => {
                        if self.buf.is_empty() {
                            return Ok(None);
                        }
                        let err = TransportError::Io(std::io::ErrorKind::InvalidData);
                        self.latched_error = Some(err);
                        self.buf.clear();
                        return Err(err);
                    }
                    // A mid-record error leaves an unknown boundary, so resuming would splice bytes onto a partial record.
                    Err(err) => {
                        self.latched_error = Some(err);
                        self.buf.clear();
                        return Err(err);
                    }
                };

                if delivery.len() > self.max_record as usize + 2 {
                    let err = TransportError::Io(std::io::ErrorKind::InvalidData);
                    self.latched_error = Some(err);
                    self.buf.clear();
                    return Err(err);
                }

                self.buf.extend_from_slice(&delivery);
            }
        })
    }
}

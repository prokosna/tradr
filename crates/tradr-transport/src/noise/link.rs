//! Record-oriented link traits for Noise transport framing (WI-M7-007f).

use tradr_core::{BoxFuture, TransportError};

/// Delivers whole records to the underlying link.
pub trait LinkSink: Send + Sync {
    /// Transmits a single record across the link.
    fn send_record<'a>(&'a self, record: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>>;

    /// Shuts down the transmission half of the link.
    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>>;
}

/// Consumes whole records from the underlying link.
pub trait LinkSource: Send {
    /// Receives the next complete record from the link, returning None when the link ends.
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;
}

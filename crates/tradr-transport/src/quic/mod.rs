//! The `quinn` backing for `direct-quic` (docs/03). Change Drill D3
//! budgets a swap away from `quinn` to this directory alone, so a `quinn`
//! type appears nowhere else in the crate.

mod channel;
mod error;
mod stream;
mod transport;

pub use transport::{QuicTransport, QuicTransportError};

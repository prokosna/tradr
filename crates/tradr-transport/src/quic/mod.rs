//! The `quinn` backing for `direct-quic` (docs/03). Change Drill D3
//! budgets a swap away from `quinn` to this directory alone, so a `quinn`
//! type appears nowhere else in the crate. `Transport`, `Incoming` and
//! `SecureChannel` are `WI-M1-004d`; this module is only the stream
//! wrappers and the `TransportError` mapping underneath them.

// Nothing outside this Work Item's tests constructs a stream wrapper or
// calls a mapping function yet: `WI-M1-004d` is the first caller.
#![allow(dead_code)]

mod error;
mod stream;

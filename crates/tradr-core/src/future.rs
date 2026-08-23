//! The boxed-future alias every asynchronous Layer 1 trait method returns.
//! Its own module because `Transport` (WI-M0-006e) reuses it, not only `Vfs`.

use std::future::Future;
use std::pin::Pin;

/// A pinned, boxed, `Send` future: an `async fn` in a trait is not dyn
/// compatible, which `Vfs` needs to be (ADR-0013).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

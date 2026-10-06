//! The device's side of a Brokr: registering and collecting Deferred Deliveries
//! behind a port, so no HTTP type reaches this crate (docs/13, Change Drill D6).

mod api;
mod collect;
mod register;

pub use api::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, InboxEntry,
    RegisterRequest, Session,
};
pub use collect::{CollectContext, CollectReport, collect_once};
pub use register::register;

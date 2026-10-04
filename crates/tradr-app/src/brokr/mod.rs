//! The device's side of a Brokr: registering and collecting Deferred Deliveries
//! behind a port, so no HTTP type reaches this crate (docs/13, Change Drill D6).

mod api;
mod collect;
mod http;
mod register;
mod settings;

pub use api::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, InboxEntry,
    RegisterRequest, Session,
};
pub use collect::{CollectContext, CollectReport, collect_once};
pub use http::HttpBrokrApi;
pub use register::register;
pub use settings::{
    BrokrSettings, JoinToken, SettingsError, clear_join_token, clear_session, clear_settings,
    load_join_token, load_session, load_settings, save_join_token, save_session, save_settings,
};

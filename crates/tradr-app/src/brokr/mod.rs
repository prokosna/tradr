//! The device's side of a Brokr: registering and collecting Deferred Deliveries
//! behind a port, so no HTTP type reaches this crate (docs/13, Change Drill D6).

mod api;
mod collect;
mod collector;
mod devices;
mod http;
mod outbox;
mod register;
mod send;
mod settings;

pub use api::{
    BrokrApi, BrokrError, BrokrFuture, BrokrInfo, ByteStream, Challenge, DeliveryId, DeliveryState,
    InboxEntry, OutboxEntry, OutboxState, RegisterRequest, Session, UploadStream,
};
pub use collect::{CollectContext, CollectReport, collect_once};
pub use collector::{
    ArrivalHook, Collector, CollectorParts, CollectorStatus, LinkView, LinksFn, OwnAccountFn,
    ensure_session, run_pass,
};
pub use devices::{DeliveryDto, KnownDeviceDto, delivery_dto, delivery_dtos, known_device_dtos};
pub use http::HttpBrokrApi;
pub use outbox::{DeliveryStatus, OutboxError, SentDeliveries, SentRecord};
pub use register::register;
pub use send::{SendContext, SendDeferredContext, SentDelivery, send_deferred};
pub use settings::{
    BrokrSettings, JoinToken, SettingsError, clear_join_token, clear_session, clear_settings,
    load_join_token, load_session, load_settings, save_join_token, save_session, save_settings,
};

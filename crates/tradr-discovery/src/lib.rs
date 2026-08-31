#![forbid(unsafe_code)]
//! mDNS, BLE advertise and scan, static pins, Brokr presence.

mod mdns;
mod static_peer;
mod txt;

pub use mdns::{MDNS_SOURCE_ID, MdnsSource, SERVICE_TYPE, advertisement, instance_name};
pub use static_peer::{
    STATIC_PEER_DEFAULT_PORT, STATIC_PEER_SOURCE_ID, StaticPeer, StaticPeerError, StaticPeerId,
    StaticPeerRegistry, StaticPeerSource,
};
pub use txt::{
    AGREEMENT_KEY_TAG_LEN, PLATFORM_MAX_LEN, Platform, PlatformError, TxtError, TxtRecord,
};

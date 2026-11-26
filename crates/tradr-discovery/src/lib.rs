#![forbid(unsafe_code)]
//! mDNS and static pins.

mod mdns;
mod static_peer;
mod txt;

pub use mdns::{
    MDNS_SOURCE_ID, MdnsRecheck, MdnsSource, SERVICE_TYPE, advertisement, instance_name,
};
pub use static_peer::{
    STATIC_PEER_DEFAULT_PORT, STATIC_PEER_SOURCE_ID, StaticPeer, StaticPeerError, StaticPeerId,
    StaticPeerRegistry, StaticPeerSource,
};
pub use txt::{
    AGREEMENT_KEY_TAG_LEN, PLATFORM_MAX_LEN, Platform, PlatformError, TxtError, TxtRecord,
};

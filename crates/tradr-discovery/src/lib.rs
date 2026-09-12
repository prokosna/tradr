#![forbid(unsafe_code)]
//! mDNS, BLE advertise and scan, static pins, Brokr presence.

mod advertisement;
mod ble;
#[cfg(target_os = "linux")]
mod ble_linux;
mod eid;
mod mdns;
mod rotation;
mod static_peer;
mod txt;

pub use advertisement::{
    AD_STRUCTURE_OVERHEAD, ADVERTISEMENT_MAX_LEN, ADVERTISEMENT_VERSION, Advertisement,
    AdvertisementError, FLAGS_AD_LEN, PlatformCode, SERVICE_DATA_LEN, TRADR_SERVICE_UUID,
    TRADR_SERVICE_UUID_LE,
};
pub use ble::{
    BLE_OBSERVATION_TTL_SECS, BLE_SOURCE_ID, BleAdvertiser, BleError, BleScanner, BleSource,
    BroadcastSecrets, DeclaredCapabilities, ScanReport, ScanReportError,
};
#[cfg(target_os = "linux")]
pub use ble_linux::{BluerAdvertiser, BluerScanner, ble_error, tradr_scan_report};
pub use eid::{
    BROADCAST_SECRET_LEN, BroadcastSecret, EID_LEN, EID_WINDOW_SECS, Eid, EidError, EidWindow,
};
pub use mdns::{MDNS_SOURCE_ID, MdnsSource, SERVICE_TYPE, advertisement, instance_name};
pub use rotation::{
    BLE_ADVERTISED_SET_MAX, BLE_ADVERTISEMENT_SLOT_SECS, BleRotation, RotationTick,
};
pub use static_peer::{
    STATIC_PEER_DEFAULT_PORT, STATIC_PEER_SOURCE_ID, StaticPeer, StaticPeerError, StaticPeerId,
    StaticPeerRegistry, StaticPeerSource,
};
pub use txt::{
    AGREEMENT_KEY_TAG_LEN, PLATFORM_MAX_LEN, Platform, PlatformError, TxtError, TxtRecord,
};

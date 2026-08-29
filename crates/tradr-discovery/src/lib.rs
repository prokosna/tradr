#![forbid(unsafe_code)]
//! mDNS, BLE advertise and scan, static pins, Brokr presence.

mod mdns;
mod txt;

pub use mdns::{MDNS_SOURCE_ID, MdnsSource, SERVICE_TYPE, advertisement, instance_name};
pub use txt::{
    AGREEMENT_KEY_TAG_LEN, PLATFORM_MAX_LEN, Platform, PlatformError, TxtError, TxtRecord,
};

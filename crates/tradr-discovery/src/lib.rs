#![forbid(unsafe_code)]
//! mDNS, BLE advertise and scan, static pins, Brokr presence.

mod txt;

pub use txt::{
    AGREEMENT_KEY_TAG_LEN, PLATFORM_MAX_LEN, Platform, PlatformError, TxtError, TxtRecord,
};

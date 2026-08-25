#![forbid(unsafe_code)]
//! Encodes and decodes the `tradr.v1` wire messages generated from `proto/tradr/v1/`.

/// Generated protobuf types for the `tradr.v1` package.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/tradr.v1.rs"));
}

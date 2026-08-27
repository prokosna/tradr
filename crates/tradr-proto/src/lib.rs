#![forbid(unsafe_code)]
//! Encodes and decodes the `tradr.v1` wire messages generated from
//! `proto/tradr/v1/`, and carries the byte framing those messages travel
//! inside. The framing (docs/04's "Framing") knows nothing about protobuf.

/// Generated protobuf types for the `tradr.v1` package.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/tradr.v1.rs"));
}

pub mod framing;
pub mod hello;
pub mod message_type;

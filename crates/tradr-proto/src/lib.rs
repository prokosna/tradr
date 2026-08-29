#![forbid(unsafe_code)]
//! Encodes and decodes the `tradr.v1` wire messages generated from
//! `proto/tradr/v1/`, and carries the byte framing those messages travel
//! inside. The framing (docs/04's "Framing") knows nothing about protobuf.

/// Generated protobuf types for the `tradr.v1` package.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/tradr.v1.rs"));
}

pub mod control;
pub mod data;
pub mod framing;
pub mod hello;
pub mod message_type;

pub use control::{
    OfferFrameError, OfferWireError, decode_transfer_accept_frame, decode_transfer_offer_frame,
    decode_transfer_reject_frame, encode_transfer_accept_frame, encode_transfer_offer_frame,
    encode_transfer_reject_frame, transfer_accept_from_wire, transfer_accept_to_wire,
    transfer_offer_from_wire, transfer_offer_to_wire, transfer_reject_from_wire,
    transfer_reject_to_wire,
};
pub use data::{
    TransferFrameError, TransferWireError, chunk_data_header_from_wire, chunk_data_header_to_wire,
    chunk_request_from_wire, chunk_request_to_wire, chunk_rerequest_from_wire,
    chunk_rerequest_to_wire, decode_chunk_data_header_frame, decode_chunk_request_frame,
    decode_chunk_rerequest_frame, decode_flow_control_frame, decode_item_complete_frame,
    decode_transfer_progress_frame, encode_chunk_data_header_frame, encode_chunk_request_frame,
    encode_chunk_rerequest_frame, encode_flow_control_frame, encode_item_complete_frame,
    encode_transfer_progress_frame, flow_control_from_wire, flow_control_to_wire,
    item_complete_from_wire, item_complete_to_wire, transfer_progress_from_wire,
    transfer_progress_to_wire,
};

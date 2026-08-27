//! Supervisor-authored tests for the numbers a peer supplies in a
//! `ChunkData` header (CLAUDE.md section 6). docs/04 says the offset is an
//! input to verification rather than only to placement, and these three
//! fields are where an untrusted peer's arithmetic first enters this
//! process. Every one of them was passed straight through before WI-M1-018.

use prost::Message;
use tradr_core::REFERENCE_CHUNK_SIZE_BYTES;
use tradr_proto::data::chunk_data_header_from_wire;
use tradr_proto::v1;

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn header(chunk_index: u64, payload_len: u32, offset_in_chunk: u32) -> v1::ChunkData {
    v1::ChunkData {
        transfer_id: VALID_V7.to_string(),
        item_id: "photo_1".to_string(),
        chunk_index,
        payload_len,
        last: false,
        offset_in_chunk,
    }
}

#[test]
fn a_well_formed_header_is_accepted() {
    let decoded = chunk_data_header_from_wire(header(3, 1024, 4096))
        .expect("a header inside every bound must decode");

    assert_eq!(decoded.chunk_index().value(), 3);
    assert_eq!(decoded.payload_len(), 1024);
    assert_eq!(decoded.offset_in_chunk(), 4096);
}

#[test]
fn an_offset_at_or_beyond_the_reference_chunk_is_refused() {
    let bound = REFERENCE_CHUNK_SIZE_BYTES as u32;

    assert!(
        chunk_data_header_from_wire(header(0, 1024, bound - 1)).is_ok(),
        "the last byte of a reference chunk is a legal offset"
    );
    assert!(
        chunk_data_header_from_wire(header(0, 1024, bound)).is_err(),
        "docs/04: offset_in_chunk is an offset within the 1 MiB reference chunk"
    );
    assert!(
        chunk_data_header_from_wire(header(0, 1024, u32::MAX)).is_err(),
        "a peer must not name an offset four thousand chunks past the one it claims"
    );
}

#[test]
fn an_empty_payload_is_refused() {
    assert!(
        chunk_data_header_from_wire(header(0, 0, 0)).is_err(),
        "a bao slice carries an 8-byte length header at minimum, so a zero payload is malformed"
    );
}

#[test]
fn a_chunk_index_whose_byte_offset_overflows_is_refused() {
    for index in [
        u64::MAX,
        u64::MAX / 2,
        (u64::MAX / REFERENCE_CHUNK_SIZE_BYTES) + 1,
    ] {
        assert!(
            chunk_data_header_from_wire(header(index, 1024, 0)).is_err(),
            "chunk_index {index} has no byte offset inside u64, and the multiplication \
             is what a receiver would perform before writing"
        );
    }
}

// DCR-055 retires field 5. protobuf keeps decoding a message that still
// carries it, which is the property that makes retiring one safe -- but
// only if nothing reads it, so this pins both halves at once.
#[test]
fn the_retired_verify_path_field_is_ignored_rather_than_read() {
    let clean = header(1, 2048, 512);
    let mut with_field_5 = clean.encode_to_vec();

    // Field 5, wire type 2 (length-delimited): tag (5 << 3) | 2, then a
    // 32-byte body standing in for the tree path this field used to hold.
    with_field_5.push(0x2A);
    with_field_5.push(32);
    with_field_5.extend_from_slice(&[9u8; 32]);

    let reparsed =
        v1::ChunkData::decode(with_field_5.as_slice()).expect("an unknown field must not fail");
    let from_stale_peer =
        chunk_data_header_from_wire(reparsed).expect("the rest of the header is well formed");
    let from_clean = chunk_data_header_from_wire(clean).expect("the same header without field 5");

    assert_eq!(
        from_stale_peer, from_clean,
        "a peer still sending the retired field must decode to exactly the same header"
    );
}

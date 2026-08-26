//! docs/04-protocol.md's "Framing" section, in particular the three
//! subsections written under DCR-049: which `max_frame_size` bounds which
//! direction, why a bad length ends the connection rather than being
//! skipped, and why the announced length is never trusted for an
//! allocation.

use tradr_proto::framing::{FrameDecoder, FrameError, encode_frame};

#[test]
fn encode_is_byte_for_byte() {
    let encoded = encode_frame(0x07, b"hi", 1024).expect("well within limit");
    assert_eq!(encoded, vec![0x00, 0x00, 0x00, 0x03, 0x07, b'h', b'i']);
}

#[test]
fn round_trips_through_a_decoder() {
    let encoded = encode_frame(0x11, b"payload", 1024).expect("well within limit");

    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&encoded);
    let frame = decoder
        .next_frame()
        .expect("valid frame must decode")
        .expect("a whole frame was fed");

    assert_eq!(frame.type_code(), 0x11);
    assert_eq!(frame.payload(), b"payload");
}

#[test]
fn empty_payload_round_trips_as_five_bytes() {
    let encoded = encode_frame(0x02, b"", 1024).expect("well within limit");
    assert_eq!(encoded.len(), 5);
    assert_eq!(&encoded[..4], &[0x00, 0x00, 0x00, 0x01]);

    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&encoded);
    let frame = decoder
        .next_frame()
        .expect("valid frame must decode")
        .expect("a whole frame was fed");

    assert_eq!(frame.type_code(), 0x02);
    assert_eq!(frame.payload(), b"" as &[u8]);
}

#[test]
fn payload_of_limit_minus_one_encodes_but_limit_is_refused() {
    let limit: u32 = 16;
    let fits = vec![0xAA; (limit - 1) as usize];
    let too_big = vec![0xAA; limit as usize];

    assert!(encode_frame(0x01, &fits, limit).is_ok());

    let err = encode_frame(0x01, &too_big, limit).expect_err("1 + payload.len() exceeds limit");
    assert_eq!(
        err,
        FrameError::Oversized {
            announced: (limit + 1) as u64,
            limit
        }
    );
}

#[test]
fn decode_side_accepts_exactly_the_limit_and_refuses_one_more() {
    let limit: u32 = 16;

    // The two sides agree by construction: `len == limit` is legal per
    // docs/04 ("len ... is bounded by max_frame_size"), so encoding a
    // payload of `limit - 1` bytes must decode cleanly under that limit.
    let payload = vec![0xAA; (limit - 1) as usize];
    let encoded = encode_frame(0x01, &payload, limit).expect("len == limit is legal");

    let mut decoder = FrameDecoder::new(limit);
    decoder.feed(&encoded);
    let frame = decoder
        .next_frame()
        .expect("a frame whose len equals the limit must decode")
        .expect("the whole frame was fed");
    assert_eq!(frame.payload(), payload.as_slice());
}

#[test]
fn decode_side_refuses_limit_plus_one() {
    let limit: u32 = 16;
    let mut decoder = FrameDecoder::new(limit);
    decoder.feed(&(limit + 1).to_be_bytes());

    let err = decoder
        .next_frame()
        .expect_err("a header announcing one more than the limit is refused");
    assert_eq!(
        err,
        FrameError::Oversized {
            announced: (limit + 1) as u64,
            limit
        }
    );
}

#[test]
fn zero_limit_refuses_every_encode_including_empty() {
    let err = encode_frame(0x01, b"", 0).expect_err("zero limit admits no frame at all");
    assert_eq!(
        err,
        FrameError::Oversized {
            announced: 1,
            limit: 0
        }
    );
}

#[test]
fn fed_one_byte_at_a_time_yields_exactly_one_frame() {
    let encoded = encode_frame(0x05, b"abc", 1024).expect("well within limit");
    let mut decoder = FrameDecoder::new(1024);

    let mut yielded = 0;
    for (index, byte) in encoded.iter().enumerate() {
        decoder.feed(&[*byte]);
        match decoder
            .next_frame()
            .expect("bytes fed so far are a valid prefix")
        {
            None => assert!(
                index < encoded.len() - 1,
                "the frame must not be reported complete before its last byte"
            ),
            Some(frame) => {
                yielded += 1;
                assert_eq!(
                    index,
                    encoded.len() - 1,
                    "the frame must complete on the last byte"
                );
                assert_eq!(frame.type_code(), 0x05);
                assert_eq!(frame.payload(), b"abc");
            }
        }
    }
    assert_eq!(yielded, 1);
}

#[test]
fn two_frames_in_one_feed_come_out_in_order() {
    let first = encode_frame(0x01, b"one", 1024).expect("well within limit");
    let second = encode_frame(0x02, b"two", 1024).expect("well within limit");
    let mut both = first;
    both.extend_from_slice(&second);

    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&both);

    let frame_a = decoder
        .next_frame()
        .expect("valid")
        .expect("first frame present");
    assert_eq!(frame_a.type_code(), 0x01);
    assert_eq!(frame_a.payload(), b"one");

    let frame_b = decoder
        .next_frame()
        .expect("valid")
        .expect("second frame present");
    assert_eq!(frame_b.type_code(), 0x02);
    assert_eq!(frame_b.payload(), b"two");

    assert_eq!(decoder.next_frame().expect("no more bytes buffered"), None);
}

#[test]
fn a_feed_split_inside_the_four_byte_header_still_yields_the_frame() {
    let encoded = encode_frame(0x09, b"hello world", 1024).expect("well within limit");

    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&encoded[..2]);
    assert_eq!(decoder.next_frame().expect("no whole header yet"), None);

    decoder.feed(&encoded[2..]);
    let frame = decoder
        .next_frame()
        .expect("valid frame must decode")
        .expect("a whole frame was fed");

    assert_eq!(frame.type_code(), 0x09);
    assert_eq!(frame.payload(), b"hello world");
}

#[test]
fn hostile_oversized_header_costs_nothing_before_any_payload_arrives() {
    let limit: u32 = 1 << 20;
    let mut decoder = FrameDecoder::new(limit);

    // Only the four header bytes are ever supplied; no payload byte exists.
    decoder.feed(&0xffff_ffffu32.to_be_bytes());
    assert_eq!(
        decoder.buffered_len(),
        4,
        "nothing beyond the header bytes was ever held"
    );

    let err = decoder
        .next_frame()
        .expect_err("an announced 4 GiB frame must be rejected");
    assert_eq!(
        err,
        FrameError::Oversized {
            announced: 0xffff_ffff,
            limit
        }
    );
    assert_eq!(
        decoder.buffered_len(),
        0,
        "a fatal error drops the buffer rather than holding peer bytes forever"
    );
}

#[test]
fn hostile_zero_length_header_is_empty() {
    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&0u32.to_be_bytes());

    let err = decoder
        .next_frame()
        .expect_err("len == 0 describes no frame");
    assert_eq!(err, FrameError::Empty);
}

#[test]
fn decoder_is_poisoned_after_oversized() {
    let mut decoder = FrameDecoder::new(1 << 20);
    decoder.feed(&0xffff_ffffu32.to_be_bytes());
    let first_err = decoder.next_frame().expect_err("oversized header");
    assert_eq!(
        decoder.buffered_len(),
        0,
        "the bad header must not still be sitting in the buffer to re-produce this error"
    );

    let valid = encode_frame(0x01, b"fine", 1 << 20).expect("well within limit");
    decoder.feed(&valid);

    let second_err = decoder
        .next_frame()
        .expect_err("a poisoned decoder never recovers");
    assert_eq!(second_err, first_err);
}

#[test]
fn decoder_is_poisoned_after_empty() {
    let mut decoder = FrameDecoder::new(1024);
    decoder.feed(&0u32.to_be_bytes());
    let first_err = decoder.next_frame().expect_err("empty header");
    assert_eq!(
        decoder.buffered_len(),
        0,
        "the bad header must not still be sitting in the buffer to re-produce this error"
    );

    let valid = encode_frame(0x01, b"fine", 1024).expect("well within limit");
    decoder.feed(&valid);

    let second_err = decoder
        .next_frame()
        .expect_err("a poisoned decoder never recovers");
    assert_eq!(second_err, first_err);
}

#[test]
fn each_side_advertises_its_own_limit() {
    let encoded = encode_frame(0x01, &vec![0xAA; 600], 1 << 20).expect("under the 1 MiB bound");

    let mut generous = FrameDecoder::new(1 << 20);
    generous.feed(&encoded);
    assert!(
        generous
            .next_frame()
            .expect("under this decoder's own bound")
            .is_some()
    );

    let mut stingy = FrameDecoder::new(512);
    stingy.feed(&encoded);
    let err = stingy
        .next_frame()
        .expect_err("over this decoder's own, smaller bound");
    assert_eq!(
        err,
        FrameError::Oversized {
            announced: 601,
            limit: 512
        }
    );
}

#[test]
fn compaction_drains_a_thousand_small_frames() {
    let mut decoder = FrameDecoder::new(1024);
    let mut max_buffered = 0;

    for i in 0..1000u32 {
        let encoded = encode_frame(0x01, &i.to_be_bytes(), 1024).expect("well within limit");
        decoder.feed(&encoded);
        max_buffered = max_buffered.max(decoder.buffered_len());

        let frame = decoder
            .next_frame()
            .expect("each iteration feeds exactly one whole frame")
            .expect("a whole frame was fed");
        assert_eq!(frame.payload(), i.to_be_bytes());
    }

    assert_eq!(decoder.buffered_len(), 0);
    assert!(
        max_buffered <= 5 + 4,
        "buffered_len must never exceed one frame's length ({max_buffered} observed)"
    );
}

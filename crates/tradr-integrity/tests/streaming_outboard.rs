//! Supervisor-authored tests for the streaming sender's half of `bao`
//! (CLAUDE.md section 6, docs/04 "The sender streams a file", DCR-164).
//! The standard is byte equality with the whole-buffer `outboard` and
//! `slice`, which the verifier's own suite already pins.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use tradr_integrity::{OutboardBuilder, SliceError, outboard, slice, slice_from_window};

const MIB: u64 = 1024 * 1024;

const SIZES: [u64; 9] = [0, 1, 1023, 1024, 1025, MIB, MIB + 1, 2 * MIB, 3 * MIB + 17];

// Deterministic and not compressible into a run of equal bytes, so a
// window taken from the wrong offset cannot happen to match.
fn content(len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len as usize);
    let mut x: u32 = 0x9e37_79b9;
    while (out.len() as u64) < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len as usize);
    out
}

fn spooled(data: &[u8]) -> (Vec<u8>, tradr_core::ContentHash) {
    let mut builder = OutboardBuilder::new(Cursor::new(Vec::new()));
    for piece in data.chunks(MIB as usize) {
        builder
            .update(piece)
            .expect("an in-memory spool cannot fail");
    }
    let (spool, hash) = builder.finish().expect("an in-memory spool cannot fail");
    (spool.into_inner(), hash)
}

// Accepts nothing, so an encoder that drops a spool error hands back an
// outboard that was never written.
struct BrokenSpool;

impl Read for BrokenSpool {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("the scratch disk went away"))
    }
}

impl Write for BrokenSpool {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("the scratch disk went away"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("the scratch disk went away"))
    }
}

impl Seek for BrokenSpool {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Err(io::Error::other("the scratch disk went away"))
    }
}

#[test]
fn a_streamed_outboard_equals_the_whole_buffer_outboard_at_every_size() {
    for size in SIZES {
        let data = content(size);
        let (expected_ob, expected_hash) = outboard(&data);
        let (ob, hash) = spooled(&data);

        assert_eq!(hash, expected_hash, "content hash differs at size {size}");
        assert!(ob == expected_ob, "outboard bytes differ at size {size}");
    }
}

#[test]
fn content_fed_in_uneven_pieces_yields_the_same_outboard() {
    let data = content(MIB + 1025);
    let (expected_ob, expected_hash) = outboard(&data);

    let mut builder = OutboardBuilder::new(Cursor::new(Vec::new()));
    for piece in data.chunks(7) {
        builder
            .update(piece)
            .expect("an in-memory spool cannot fail");
    }
    builder.update(&[]).expect("an empty piece is not an error");
    let (spool, hash) = builder.finish().expect("an in-memory spool cannot fail");

    assert_eq!(hash, expected_hash);
    assert!(spool.into_inner() == expected_ob);
}

#[test]
fn a_spool_that_cannot_be_written_is_reported() {
    let data = content(2 * MIB);
    let mut builder = OutboardBuilder::new(BrokenSpool);
    let fed = data
        .chunks(MIB as usize)
        .try_for_each(|p| builder.update(p));

    assert!(
        fed.is_err() || builder.finish().is_err(),
        "an outboard that never reached the spool must not answer a hash"
    );
}

#[test]
fn every_chunk_sliced_from_its_window_equals_the_whole_buffer_slice() {
    for size in SIZES {
        let data = content(size);
        let (whole_ob, _) = outboard(&data);
        let (spool, _) = spooled(&data);

        let chunks = size.div_ceil(MIB).max(1);
        for index in 0..chunks {
            let start = index * MIB;
            let end = (start + MIB).min(size);
            let window = &data[start as usize..end as usize];

            let expected = slice(&data, &whole_ob, start, end - start)
                .expect("the range lies inside the content");
            let got = slice_from_window(window, start, Cursor::new(&spool), start, end - start)
                .expect("the range lies inside the window");

            assert!(
                got == expected,
                "slice differs for chunk {index} of size {size}"
            );
        }
    }
}

#[test]
fn a_subdivided_piece_inside_a_window_equals_the_whole_buffer_slice() {
    let data = content(3 * MIB + 17);
    let (whole_ob, _) = outboard(&data);
    let (spool, _) = spooled(&data);
    let window = &data[MIB as usize..(2 * MIB) as usize];

    for (offset, len) in [(MIB, 4096), (MIB + 4096, 4096), (MIB + 1000, 3000)] {
        let expected = slice(&data, &whole_ob, offset, len).expect("inside the content");
        let got = slice_from_window(window, MIB, Cursor::new(&spool), offset, len)
            .expect("inside the window");
        assert!(got == expected, "slice differs at {offset}+{len}");
    }
}

#[test]
fn a_range_reaching_outside_the_window_is_refused() {
    let data = content(3 * MIB);
    let (spool, _) = spooled(&data);
    let window = &data[MIB as usize..(2 * MIB) as usize];

    for (offset, len) in [(0, MIB), (MIB - 1, 2), (2 * MIB - 1, 2), (2 * MIB, 1)] {
        assert_eq!(
            slice_from_window(window, MIB, Cursor::new(&spool), offset, len),
            Err(SliceError::OutOfRange),
            "{offset}+{len} lies outside the window at 1 MiB"
        );
    }
}

// A window holding more bytes than the file the outboard describes is a
// caller's mistake; extracting from it would serve a slice the receiver
// refuses, so the length the outboard records bounds the range too.
#[test]
fn a_range_past_the_content_the_outboard_records_is_refused() {
    let data = content(MIB + 100);
    let (spool, _) = spooled(&data);
    let mut padded = data[MIB as usize..].to_vec();
    padded.extend_from_slice(&[0u8; 200]);

    assert_eq!(
        slice_from_window(&padded, MIB, Cursor::new(&spool), MIB, 300),
        Err(SliceError::OutOfRange)
    );
}

#[test]
fn a_range_whose_end_overflows_is_refused() {
    let data = content(MIB);
    let (spool, _) = spooled(&data);

    assert_eq!(
        slice_from_window(&data, 0, Cursor::new(&spool), 1, u64::MAX),
        Err(SliceError::OutOfRange)
    );
}

// Accepts every write and refuses to seek, which only finishing needs,
// so a builder that drops the error from its last step is what fails.
struct UnseekableSpool(Vec<u8>);

impl Read for UnseekableSpool {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("the scratch disk went away"))
    }
}

impl Write for UnseekableSpool {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for UnseekableSpool {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Err(io::Error::other("the scratch disk went away"))
    }
}

#[test]
fn a_spool_that_fails_only_when_finishing_is_reported() {
    let data = content(2 * MIB);
    let mut builder = OutboardBuilder::new(UnseekableSpool(Vec::new()));
    builder
        .update(&data)
        .expect("writes alone succeed on this spool");

    assert!(
        builder.finish().is_err(),
        "an outboard left in post-order must not answer a hash"
    );
}

// bao reads whole 1024-byte chunks, so a window that starts inside one
// cannot serve it; the extraction must fail rather than read other bytes.
#[test]
fn a_window_missing_part_of_a_needed_chunk_is_refused() {
    let data = content(2 * MIB);
    let (spool, _) = spooled(&data);
    let window = &data[1000..5000];

    assert!(
        slice_from_window(window, 1000, Cursor::new(&spool), 1000, 10).is_err(),
        "the chunk at 0 is not in a window starting at 1000"
    );

    let window = &data[1500..5000];
    assert!(
        slice_from_window(window, 1500, Cursor::new(&spool), 1500, 10).is_err(),
        "the chunk at 1024 is not in a window starting at 1500"
    );
}

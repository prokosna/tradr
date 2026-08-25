//! Supervisor-authored tests for the operating system entropy source that
//! feeds Device Key generation. Critical Module, CLAUDE.md section 6: a
//! predictable key is a derivable key, and nothing downstream notices --
//! every signature it makes verifies perfectly.

use tradr_core::Rng;
use tradr_identity::OsRng;

// A source that is stuck returns the same bytes every time and passes any
// test that asks only whether it succeeded. Sixteen bytes repeating by
// chance is 2^-128.
#[test]
fn two_draws_differ() {
    let rng = OsRng;
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];

    rng.fill_bytes(&mut first)
        .expect("the os source should answer");
    rng.fill_bytes(&mut second)
        .expect("the os source should answer");

    assert_ne!(first, second);
}

// The failure this guards is a source that fills a prefix and leaves the
// rest as it found it. A key whose tail is a constant is a key with far
// less entropy than its length claims, and it verifies just as well.
#[test]
fn the_whole_buffer_is_written_including_its_tail() {
    let rng = OsRng;
    let mut buffer = [0xAAu8; 1024];

    rng.fill_bytes(&mut buffer)
        .expect("the os source should answer");

    assert!(
        buffer[512..].iter().any(|&b| b != 0xAA),
        "the second half of the buffer was left untouched"
    );
    assert!(
        buffer[1000..].iter().any(|&b| b != 0xAA),
        "the tail of the buffer was left untouched"
    );
}

// Every length a caller might pass, not a length someone chose. A P-256
// scalar is 32 bytes, but nothing in the trait says so.
#[test]
fn every_length_up_to_sixty_five_is_filled() {
    let rng = OsRng;

    for len in 1..=65usize {
        let mut a = vec![0u8; len];
        let mut b = vec![0u8; len];
        rng.fill_bytes(&mut a).expect("the os source should answer");
        rng.fill_bytes(&mut b).expect("the os source should answer");
        assert_ne!(a, b, "two draws of {len} bytes were identical");
    }
}

#[test]
fn a_zero_length_draw_succeeds() {
    let rng = OsRng;
    let mut empty: [u8; 0] = [];

    assert!(rng.fill_bytes(&mut empty).is_ok());
}

// Not a randomness test -- it cannot be one. It catches a source that
// answers with zeroes, which is what an unwired or short-circuited
// implementation returns and which no other test here would notice.
#[test]
fn a_large_draw_is_not_all_zeroes() {
    let rng = OsRng;
    let mut buffer = vec![0u8; 4096];

    rng.fill_bytes(&mut buffer)
        .expect("the os source should answer");

    assert!(buffer.iter().any(|&b| b != 0));
    let zeroes = buffer.iter().filter(|&&b| b == 0).count();
    assert!(
        zeroes < 200,
        "{zeroes} of 4096 bytes were zero, far above the ~16 a real source gives"
    );
}

// The trait is used behind `&dyn Rng` everywhere, so it has to be usable
// that way rather than only through a concrete type.
#[test]
fn it_is_usable_as_a_trait_object() {
    let rng: &dyn Rng = &OsRng;
    let mut buffer = [0u8; 32];

    assert!(rng.fill_bytes(&mut buffer).is_ok());
}

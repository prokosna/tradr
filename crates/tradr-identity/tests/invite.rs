//! Tests `tradr_identity::create_invite` (docs/11-account-linking.md,
//! "What the Invite carries, and how it travels" and "What an invite's
//! expiry decides, and what it does not"). Fakes are local, mirroring
//! `tests/hello_exchange.rs`.

use std::cell::Cell;
use std::time::Instant;

use tradr_core::{Clock, DisplayName, Monotonic, PublicKeyPoint, Rng, RngError, UnixTime};
use tradr_identity::{INVITE_TTL_SECS, create_invite};

// ---- Fakes --------------------------------------------------------------

// Returns bytes from a fixed sequence, one at a time, so a test can tell
// exactly which draw produced which field.
struct SequenceRng {
    bytes: Vec<u8>,
    offset: Cell<usize>,
}

impl SequenceRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            offset: Cell::new(0),
        }
    }
}

impl Rng for SequenceRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        let start = self.offset.get();
        let end = start + buf.len();
        buf.copy_from_slice(&self.bytes[start..end]);
        self.offset.set(end);
        Ok(())
    }
}

// A source that always fails, so a caller cannot receive an `Invite` built
// from bytes it never actually drew.
struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _buf: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::Source("no entropy source".into()))
    }
}

// Rule E3 forbids waiting on wall-clock time, so expiry is expressed by
// choosing the clock rather than by letting one run.
struct FixedClock {
    secs: i64,
    started: Instant,
}

impl FixedClock {
    fn at(secs: i64) -> Self {
        Self {
            secs,
            started: Instant::now(),
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.secs)
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(self.started)
    }
}

// ---- Builders -------------------------------------------------------------

const NOW: i64 = 1_800_000_000;

// A 32-byte draw whose two halves differ, so a generator confusing them
// with each other is caught by inequality alone.
fn draw() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    bytes
}

// An uncompressed point filled with a fixed pattern. Nothing here does
// curve arithmetic, so the bytes need only be the right length.
fn point(first: u8) -> PublicKeyPoint {
    let mut bytes = [0x04u8; 65];
    for (i, byte) in bytes.iter_mut().enumerate().skip(1) {
        *byte = first.wrapping_add(i as u8);
    }
    PublicKeyPoint::from_bytes(&bytes).expect("65 bytes is a point")
}

// ---- InviteId / HalfSecret split ------------------------------------------

#[test]
fn invite_id_is_the_first_16_drawn_bytes_and_half_secret_the_last_16() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    let expected_first_half: [u8; 16] = std::array::from_fn(|i| i as u8);
    let expected_second_half: [u8; 16] = std::array::from_fn(|i| (i + 16) as u8);

    assert_eq!(invite.invite_id().as_bytes(), &expected_first_half);
    assert_eq!(invite.half_secret().as_bytes(), &expected_second_half);
    assert_ne!(
        invite.invite_id().as_bytes(),
        invite.half_secret().as_bytes()
    );
}

// ---- expires_at -------------------------------------------------------

#[test]
fn expires_at_is_exactly_now_plus_the_ttl() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    assert_eq!(
        invite.expires_at(),
        UnixTime::from_secs(NOW + INVITE_TTL_SECS)
    );
}

// Written with the TTL as a literal rather than INVITE_TTL_SECS, so a
// change to the constant's value cannot pass unnoticed alongside it.
#[test]
fn an_invite_expires_five_minutes_after_it_is_created() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    assert_eq!(invite.expires_at(), UnixTime::from_secs(NOW + 5 * 60));
}

#[test]
fn a_clock_at_i64_max_does_not_overflow_or_panic() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(i64::MAX);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    assert_eq!(invite.expires_at(), UnixTime::from_secs(i64::MAX));
}

// ---- Expiry checks against the produced invite -----------------------

#[test]
fn the_invite_is_not_expired_at_creation_time() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    assert!(!invite.is_expired(UnixTime::from_secs(NOW), 0));
}

#[test]
fn the_invite_is_not_expired_one_second_before_it_expires() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    let one_before = UnixTime::from_secs(NOW + INVITE_TTL_SECS - 1);
    assert!(!invite.is_expired(one_before, 0));
}

#[test]
fn the_invite_is_expired_one_second_after_it_expires() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    let one_after = UnixTime::from_secs(NOW + INVITE_TTL_SECS + 1);
    assert!(invite.is_expired(one_after, 0));
}

// ---- display_name -------------------------------------------------------

#[test]
fn display_name_is_carried_through_when_supplied() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);
    let name = DisplayName::new("kitchen-laptop").expect("a valid display name");

    let invite = create_invite(
        &rng,
        &clock,
        point(1),
        point(2),
        "token".to_string(),
        Some(name.clone()),
    )
    .expect("a working rng and clock must produce an invite");

    assert_eq!(invite.display_name(), Some(&name));
}

#[test]
fn display_name_is_none_when_not_supplied() {
    let rng = SequenceRng::new(draw());
    let clock = FixedClock::at(NOW);

    let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
        .expect("a working rng and clock must produce an invite");

    assert_eq!(invite.display_name(), None);
}

// ---- Negative: a failing rng propagates rather than producing an invite ----

#[test]
fn a_failing_rng_makes_create_invite_return_its_error_not_an_invite() {
    let clock = FixedClock::at(NOW);

    let result = create_invite(
        &FailingRng,
        &clock,
        point(1),
        point(2),
        "token".to_string(),
        None,
    );

    assert!(result.is_err());
}

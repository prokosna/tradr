//! Supervisor-authored tests for the wall and monotonic clock an
//! Attestation's staleness check is measured against. A clock reading
//! zero makes every token look thirty days old; one that runs backwards
//! makes the JWKS refetch budget refill on demand.

use tradr_core::Clock;
use tradr_identity::SystemClock;

// A clock stuck at the epoch, or one reporting milliseconds as seconds,
// passes any test that only asks whether it returned. These bounds are
// wide enough to survive for decades and tight enough to catch both.
#[test]
fn the_wall_clock_reads_as_seconds_since_the_epoch() {
    let now = SystemClock.now().as_secs();

    assert!(now > 1_750_000_000, "clock reads {now}, before mid-2025");
    assert!(now < 4_000_000_000, "clock reads {now}, past the year 2096");
}

#[test]
fn the_wall_clock_agrees_with_the_standard_library() {
    let ours = SystemClock.now().as_secs();
    let theirs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the host clock should be after the epoch")
        .as_secs() as i64;

    assert!((ours - theirs).abs() <= 2, "ours {ours}, std {theirs}");
}

// Non-decreasing is the whole contract, and it is checked without a sleep
// (rule E3). It cannot be checked by asking whether one reading is later
// than the previous one: `duration_since` saturates to zero rather than
// going negative, so that comparison is true whatever the source does.
// Measuring every reading from one fixed start does detect it.
#[test]
fn the_monotonic_clock_never_goes_backwards() {
    let start = SystemClock.monotonic_now();
    let mut furthest = std::time::Duration::ZERO;

    for reading in 0..1000 {
        let elapsed = SystemClock.monotonic_now().duration_since(start);
        assert!(
            elapsed >= furthest,
            "reading {reading} came back {elapsed:?} after the start, behind an earlier {furthest:?}"
        );
        furthest = elapsed;
    }
}

// The reading has to advance at some point, or a rate limiter measured
// against it never expires and a stuck source is indistinguishable from a
// fast machine.
#[test]
fn the_monotonic_clock_does_advance() {
    let start = SystemClock.monotonic_now();
    let mut spins = 0u64;

    loop {
        let now = SystemClock.monotonic_now();
        if now.duration_since(start).as_nanos() > 0 {
            break;
        }
        spins += 1;
        assert!(spins < 100_000_000, "the monotonic clock never advanced");
    }
}

#[test]
fn it_is_usable_as_a_trait_object() {
    let clock: &dyn Clock = &SystemClock;

    assert!(clock.now().as_secs() > 1_750_000_000);
}

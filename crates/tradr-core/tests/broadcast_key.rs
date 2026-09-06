//! Supervisor-authored tests for the Account Broadcast Key value type
//! and the collision rule, written before the implementation. A Critical
//! Module (CLAUDE.md section 6): a rule that is not a total order
//! converges on nothing, while every EID it derives still rotates, still
//! matches, and still fails nothing.

use tradr_core::{
    ACCOUNT_BROADCAST_KEY_LEN, AccountBroadcastKey, BroadcastKeyError, CollisionOutcome, UnixTime,
    resolve_collision,
};

const EARLIER: i64 = 1_756_684_800;
const LATER: i64 = 1_756_684_801;

fn key(bytes: [u8; ACCOUNT_BROADCAST_KEY_LEN]) -> AccountBroadcastKey {
    AccountBroadcastKey::from_bytes(&bytes).expect("32 bytes is an account broadcast key")
}

// A key that is all `fill` except for one byte, so a comparison that
// stops early can be told from one that reads the whole value.
fn key_differing_at(index: usize, fill: u8, byte: u8) -> AccountBroadcastKey {
    let mut bytes = [fill; ACCOUNT_BROADCAST_KEY_LEN];
    bytes[index] = byte;
    key(bytes)
}

fn at(secs: i64) -> UnixTime {
    UnixTime::from_secs(secs)
}

// --- The value type: what it accepts, and what it refuses ---

#[test]
fn thirty_two_bytes_is_an_account_broadcast_key_and_reads_back_unchanged() {
    let bytes: [u8; ACCOUNT_BROADCAST_KEY_LEN] = std::array::from_fn(|i| i as u8);

    let abk = AccountBroadcastKey::from_bytes(&bytes).expect("32 bytes is a key");

    assert_eq!(abk.as_bytes(), &bytes);
}

#[test]
fn the_account_broadcast_key_is_thirty_two_bytes_long() {
    assert_eq!(ACCOUNT_BROADCAST_KEY_LEN, 32);
}

#[test]
fn one_byte_short_is_refused_and_says_both_lengths() {
    let short = [0x11u8; ACCOUNT_BROADCAST_KEY_LEN - 1];

    let err = AccountBroadcastKey::from_bytes(&short).expect_err("31 bytes is not a key");

    assert_eq!(
        err,
        BroadcastKeyError::WrongLength {
            expected: ACCOUNT_BROADCAST_KEY_LEN,
            actual: ACCOUNT_BROADCAST_KEY_LEN - 1,
        }
    );
}

#[test]
fn one_byte_long_is_refused_and_says_both_lengths() {
    let long = [0x11u8; ACCOUNT_BROADCAST_KEY_LEN + 1];

    let err = AccountBroadcastKey::from_bytes(&long).expect_err("33 bytes is not a key");

    assert_eq!(
        err,
        BroadcastKeyError::WrongLength {
            expected: ACCOUNT_BROADCAST_KEY_LEN,
            actual: ACCOUNT_BROADCAST_KEY_LEN + 1,
        }
    );
}

#[test]
fn an_empty_slice_is_refused_rather_than_read_as_a_key_of_zeroes() {
    let err = AccountBroadcastKey::from_bytes(&[]).expect_err("no bytes is not a key");

    assert_eq!(
        err,
        BroadcastKeyError::WrongLength {
            expected: ACCOUNT_BROADCAST_KEY_LEN,
            actual: 0,
        }
    );
}

// Rule F4: the bytes are the secret every device of one account shares,
// so a `{:?}` reaching a log must not carry them.
#[test]
fn debug_redacts_the_bytes_it_holds() {
    let abk = key([0xAB; ACCOUNT_BROADCAST_KEY_LEN]);

    let rendered = format!("{abk:?}");

    assert!(
        !rendered.contains("171") && !rendered.to_lowercase().contains("ab,"),
        "Debug rendered the key material: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "Debug said nothing about withholding the value: {rendered}"
    );
}

// --- The collision rule: the earlier creation time wins ---

#[test]
fn the_earlier_creation_time_wins_when_it_is_the_local_one() {
    let local = key([0xFF; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0x00; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(LATER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

#[test]
fn the_earlier_creation_time_wins_when_it_is_the_remote_one() {
    let local = key([0x00; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0xFF; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(LATER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// The time decides before the bytes do. Here the bytes alone would give
// the opposite answer, so a rule that compared bytes first fails this.
#[test]
fn a_later_key_loses_even_when_its_bytes_are_the_smaller_ones() {
    let local = key([0x00; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0xFF; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(LATER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

#[test]
fn a_negative_creation_time_still_orders_as_a_signed_number() {
    let local = key([0x01; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0x02; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(-1), &remote, at(1));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

// --- The collision rule: on a tie, the smaller value ---

#[test]
fn a_tie_is_broken_by_the_smaller_bytes_when_they_are_the_local_ones() {
    let local = key([0x01; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0x02; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

#[test]
fn a_tie_is_broken_by_the_smaller_bytes_when_they_are_the_remote_ones() {
    let local = key([0x02; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0x01; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// The comparison is over the whole value and not over its first byte:
// these two agree everywhere except the last.
#[test]
fn a_tie_is_broken_by_the_last_byte_when_every_earlier_byte_agrees() {
    let local = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x08);
    let remote = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x09);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

// The mirror of the case above, and the one that catches a comparison
// stopping at the first byte: there the two keys are equal, so an early
// stop answers KeepLocal where the rule says AdoptRemote.
#[test]
fn a_tie_decided_by_the_last_byte_can_go_against_the_local_key_too() {
    let local = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x09);
    let remote = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x08);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// A byte above 0x7f must order above one below it. A comparison that ran
// over signed bytes would call 0x80 the smaller of these two.
#[test]
fn a_tie_orders_bytes_as_unsigned_numbers() {
    let local = key_differing_at(0, 0x00, 0x80);
    let remote = key_differing_at(0, 0x00, 0x7f);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// Two devices already holding one key is not a collision, and the rule
// has to be total anyway: it must answer rather than have no answer.
#[test]
fn an_identical_pair_keeps_the_local_key_because_there_is_nothing_to_resolve() {
    let local = key([0x42; ACCOUNT_BROADCAST_KEY_LEN]);
    let remote = key([0x42; ACCOUNT_BROADCAST_KEY_LEN]);

    let outcome = resolve_collision(&local, at(EARLIER), &remote, at(EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

// --- What makes the rule converge rather than merely agree ---

// Both sides run the same function with the operands swapped, so the two
// must name the same winner. A rule that preferred the local side on any
// input fails one direction of this.
#[test]
fn both_sides_of_one_meeting_name_the_same_winner() {
    let cases: [(u8, i64, u8, i64); 4] = [
        (0x01, EARLIER, 0x02, LATER),
        (0x02, LATER, 0x01, EARLIER),
        (0x01, EARLIER, 0x02, EARLIER),
        (0x02, EARLIER, 0x01, EARLIER),
    ];

    for (mine, my_time, theirs, their_time) in cases {
        let a = key([mine; ACCOUNT_BROADCAST_KEY_LEN]);
        let b = key([theirs; ACCOUNT_BROADCAST_KEY_LEN]);

        let from_a = resolve_collision(&a, at(my_time), &b, at(their_time));
        let from_b = resolve_collision(&b, at(their_time), &a, at(my_time));

        let a_wins_at_a = from_a == CollisionOutcome::KeepLocal;
        let a_wins_at_b = from_b == CollisionOutcome::AdoptRemote;
        assert_eq!(
            a_wins_at_a, a_wins_at_b,
            "the two sides disagreed for {mine:#x}@{my_time} against {theirs:#x}@{their_time}"
        );
    }
}

// Three devices that each generated a key settle on the same one whatever
// order they meet in. This is what the rule being a total order buys, and
// it is the property the design is written against.
#[test]
fn three_devices_converge_on_one_key_whichever_pairs_meet_first() {
    let devices: [(u8, i64); 3] = [(0x30, EARLIER + 2), (0x10, EARLIER), (0x20, EARLIER + 1)];

    let orders: [[usize; 3]; 3] = [[0, 1, 2], [1, 2, 0], [2, 0, 1]];
    let mut settled = Vec::new();

    for order in orders {
        // Each device starts holding its own key, then meets the other
        // two in this order and keeps whatever the rule says.
        for start in 0..3 {
            let (mut held, mut held_at) = devices[start];
            for &other in &order {
                let (theirs, their_at) = devices[other];
                let mine = key([held; ACCOUNT_BROADCAST_KEY_LEN]);
                let peer = key([theirs; ACCOUNT_BROADCAST_KEY_LEN]);
                if resolve_collision(&mine, at(held_at), &peer, at(their_at))
                    == CollisionOutcome::AdoptRemote
                {
                    held = theirs;
                    held_at = their_at;
                }
            }
            settled.push(held);
        }
    }

    assert!(
        settled.iter().all(|&held| held == 0x10),
        "the devices did not converge on the earliest key: {settled:?}"
    );
}

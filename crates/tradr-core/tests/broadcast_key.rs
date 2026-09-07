//! Supervisor-authored tests for the Account Broadcast Key value type
//! and the collision rule, written before the implementation. A Critical
//! Module (CLAUDE.md section 6): a rule that is not a total order
//! converges on nothing, and one that orders the wrong field first undoes
//! every rotation while every EID it derives still matches.

use tradr_core::{
    ACCOUNT_BROADCAST_KEY_LEN, AccountBroadcastKey, BroadcastKeyError, BroadcastKeyOffer,
    BroadcastKeyOfferError, CollisionOutcome, FIRST_KEY_GENERATION, UnixTime, next_generation,
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

fn offer(fill: u8, generation: u32, created_at: i64) -> BroadcastKeyOffer {
    BroadcastKeyOffer::new(
        key([fill; ACCOUNT_BROADCAST_KEY_LEN]),
        generation,
        at(created_at),
    )
    .expect("a non-zero generation and a creation time after the epoch is an offer")
}

fn offer_of(key: AccountBroadcastKey, generation: u32, created_at: i64) -> BroadcastKeyOffer {
    BroadcastKeyOffer::new(key, generation, at(created_at))
        .expect("a non-zero generation and a creation time after the epoch is an offer")
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

// --- The offer: the triple the rule orders, and what it refuses ---

#[test]
fn an_offer_reads_back_the_three_values_it_was_built_from() {
    let bytes: [u8; ACCOUNT_BROADCAST_KEY_LEN] = std::array::from_fn(|i| i as u8);

    let made = BroadcastKeyOffer::new(key(bytes), 7, at(EARLIER)).expect("a well-formed offer");

    assert_eq!(made.key().as_bytes(), &bytes);
    assert_eq!(made.generation(), 7);
    assert_eq!(made.created_at(), at(EARLIER));
}

// proto3 omits a zero-valued scalar, so a peer sending no generation at
// all produces `0`. A value obtainable by sending nothing must never be
// one the order can be won or lost on (docs/11).
#[test]
fn generation_zero_is_refused_because_it_is_what_sending_nothing_produces() {
    let err = BroadcastKeyOffer::new(key([0x01; ACCOUNT_BROADCAST_KEY_LEN]), 0, at(EARLIER))
        .expect_err("generation 0 is not a generation");

    assert_eq!(err, BroadcastKeyOfferError::ZeroIsNotAGeneration);
}

// The same hazard on the other field, and also a clock reading the epoch.
#[test]
fn a_creation_time_at_the_epoch_is_refused_and_says_the_seconds_it_saw() {
    let err = BroadcastKeyOffer::new(key([0x01; ACCOUNT_BROADCAST_KEY_LEN]), 1, at(0))
        .expect_err("the epoch is not a creation time");

    assert_eq!(
        err,
        BroadcastKeyOfferError::CreatedAtNotAfterEpoch { seconds: 0 }
    );
}

// A clock set before 1970 would otherwise win every tie in the account.
#[test]
fn a_creation_time_before_the_epoch_is_refused_and_says_the_seconds_it_saw() {
    let err = BroadcastKeyOffer::new(key([0x01; ACCOUNT_BROADCAST_KEY_LEN]), 1, at(-1))
        .expect_err("a time before the epoch is not a creation time");

    assert_eq!(
        err,
        BroadcastKeyOfferError::CreatedAtNotAfterEpoch { seconds: -1 }
    );
}

// The boundary is exclusive on one side only: one second past the epoch
// is a creation time, so the refusal above is not an off-by-one.
#[test]
fn one_second_after_the_epoch_is_a_creation_time() {
    let made = BroadcastKeyOffer::new(key([0x01; ACCOUNT_BROADCAST_KEY_LEN]), 1, at(1))
        .expect("one second past the epoch is a creation time");

    assert_eq!(made.created_at(), at(1));
}

// The smallest generation any device writes, so a fresh draw cannot beat
// a rotation on the field that decides first.
#[test]
fn the_first_generation_is_one() {
    assert_eq!(FIRST_KEY_GENERATION, 1);

    let made = BroadcastKeyOffer::new(
        key([0x01; ACCOUNT_BROADCAST_KEY_LEN]),
        FIRST_KEY_GENERATION,
        at(EARLIER),
    );

    assert!(made.is_ok(), "the first generation must be a valid one");
}

// Rule F4 again: an offer holds the same secret the key does.
#[test]
fn an_offers_debug_redacts_the_key_it_carries() {
    let made = offer(0xAB, 3, EARLIER);

    let rendered = format!("{made:?}");

    assert!(
        !rendered.contains("171") && !rendered.to_lowercase().contains("ab,"),
        "Debug rendered the key material: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "Debug said nothing about withholding the value: {rendered}"
    );
}

// --- Which generation a rotation produces ---

#[test]
fn a_device_holding_no_key_generates_the_first_generation() {
    assert_eq!(next_generation(None), FIRST_KEY_GENERATION);
}

#[test]
fn a_rotation_is_the_generation_it_replaces_plus_one() {
    assert_eq!(next_generation(Some(1)), 2);
    assert_eq!(next_generation(Some(41)), 42);
}

// Saturating and never wrapping: `0` is the one value the offer refuses,
// so a wrap would make the last rotation of a device unusable.
#[test]
fn the_last_generation_saturates_rather_than_wrapping_to_the_refused_value() {
    assert_eq!(next_generation(Some(u32::MAX)), u32::MAX);
}

// --- The order: the generation decides first ---

#[test]
fn the_higher_generation_wins_when_it_is_the_local_one() {
    let outcome = resolve_collision(&offer(0x01, 2, EARLIER), &offer(0x02, 1, EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

#[test]
fn the_higher_generation_wins_when_it_is_the_remote_one() {
    let outcome = resolve_collision(&offer(0x01, 1, EARLIER), &offer(0x02, 2, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// This is DCR-090 in one test. A rotation is a newer key, so it carries
// the later creation time; a rule ordering on the creation time first
// hands the meeting to the key the rotation existed to remove, and
// nothing else in this design would notice.
#[test]
fn a_rotation_beats_the_key_it_replaced_even_though_it_was_made_later() {
    let rotated = offer(0xF0, 2, LATER);
    let stale = offer(0x0F, 1, EARLIER);

    assert_eq!(
        resolve_collision(&rotated, &stale),
        CollisionOutcome::KeepLocal
    );
    assert_eq!(
        resolve_collision(&stale, &rotated),
        CollisionOutcome::AdoptRemote
    );
}

// The mirror hazard: flipping the creation time's direction instead of
// adding the generation would make every newly joined device replace the
// account's key. A draw is the first generation and made now.
#[test]
fn a_fresh_draw_loses_to_an_established_key_of_the_same_generation() {
    let established = offer(0xF0, FIRST_KEY_GENERATION, EARLIER);
    let draw = offer(0x0F, FIRST_KEY_GENERATION, LATER);

    assert_eq!(
        resolve_collision(&established, &draw),
        CollisionOutcome::KeepLocal
    );
    assert_eq!(
        resolve_collision(&draw, &established),
        CollisionOutcome::AdoptRemote
    );
}

// The generation decides before the bytes do: here the bytes alone would
// give the opposite answer.
#[test]
fn a_lower_generation_loses_even_when_its_bytes_are_the_smaller_ones() {
    let outcome = resolve_collision(&offer(0x00, 1, EARLIER), &offer(0xFF, 2, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// --- The order: on an equal generation, the earlier creation time ---

#[test]
fn the_earlier_creation_time_wins_when_it_is_the_local_one() {
    let outcome = resolve_collision(&offer(0xFF, 4, EARLIER), &offer(0x00, 4, LATER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

#[test]
fn the_earlier_creation_time_wins_when_it_is_the_remote_one() {
    let outcome = resolve_collision(&offer(0x00, 4, LATER), &offer(0xFF, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// The time decides before the bytes do. Here the bytes alone would give
// the opposite answer, so a rule that compared bytes first fails this.
#[test]
fn a_later_key_loses_even_when_its_bytes_are_the_smaller_ones() {
    let outcome = resolve_collision(&offer(0x00, 4, LATER), &offer(0xFF, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// --- The order: on a full tie, the smaller value ---

#[test]
fn a_tie_is_broken_by_the_smaller_bytes_when_they_are_the_local_ones() {
    let outcome = resolve_collision(&offer(0x01, 4, EARLIER), &offer(0x02, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

#[test]
fn a_tie_is_broken_by_the_smaller_bytes_when_they_are_the_remote_ones() {
    let outcome = resolve_collision(&offer(0x02, 4, EARLIER), &offer(0x01, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// The comparison is over the whole value and not over its first byte:
// these two agree everywhere except the last.
#[test]
fn a_tie_is_broken_by_the_last_byte_when_every_earlier_byte_agrees() {
    let local = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x08);
    let remote = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x09);

    let outcome = resolve_collision(&offer_of(local, 4, EARLIER), &offer_of(remote, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

// The mirror of the case above, and the one that catches a comparison
// stopping at the first byte: there the two keys are equal, so an early
// stop answers KeepLocal where the rule says AdoptRemote.
#[test]
fn a_tie_decided_by_the_last_byte_can_go_against_the_local_key_too() {
    let local = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x09);
    let remote = key_differing_at(ACCOUNT_BROADCAST_KEY_LEN - 1, 0x07, 0x08);

    let outcome = resolve_collision(&offer_of(local, 4, EARLIER), &offer_of(remote, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// A byte above 0x7f must order above one below it. A comparison that ran
// over signed bytes would call 0x80 the smaller of these two.
#[test]
fn a_tie_orders_bytes_as_unsigned_numbers() {
    let local = key_differing_at(0, 0x00, 0x80);
    let remote = key_differing_at(0, 0x00, 0x7f);

    let outcome = resolve_collision(&offer_of(local, 4, EARLIER), &offer_of(remote, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::AdoptRemote);
}

// Two devices already holding one key is not a collision, and the rule
// has to be total anyway: it must answer rather than have no answer.
#[test]
fn an_identical_pair_keeps_the_local_key_because_there_is_nothing_to_resolve() {
    let outcome = resolve_collision(&offer(0x42, 4, EARLIER), &offer(0x42, 4, EARLIER));

    assert_eq!(outcome, CollisionOutcome::KeepLocal);
}

// --- What makes the rule converge rather than merely agree ---

// Both sides run the same function with the operands swapped, and what
// has to agree is the key each ends up holding rather than the outcome
// each names: two devices already holding one key both answer KeepLocal
// and have not disagreed. A rule that preferred the local side on any
// input leaves the two sides holding different keys and fails here.
#[test]
fn both_sides_of_one_meeting_end_up_holding_the_same_key() {
    let cases: [(u8, u32, i64, u8, u32, i64); 8] = [
        (0x01, 1, EARLIER, 0x02, 1, LATER),
        (0x02, 1, LATER, 0x01, 1, EARLIER),
        (0x01, 1, EARLIER, 0x02, 1, EARLIER),
        (0x02, 1, EARLIER, 0x01, 1, EARLIER),
        (0x01, 2, LATER, 0x02, 1, EARLIER),
        (0x02, 1, EARLIER, 0x01, 2, LATER),
        (0x01, 3, EARLIER, 0x01, 3, EARLIER),
        (0xFF, 2, EARLIER, 0x00, 2, LATER),
    ];

    for (mine, my_gen, my_time, theirs, their_gen, their_time) in cases {
        let a = offer(mine, my_gen, my_time);
        let b = offer(theirs, their_gen, their_time);

        let a_holds = match resolve_collision(&a, &b) {
            CollisionOutcome::KeepLocal => mine,
            CollisionOutcome::AdoptRemote => theirs,
        };
        let b_holds = match resolve_collision(&b, &a) {
            CollisionOutcome::KeepLocal => theirs,
            CollisionOutcome::AdoptRemote => mine,
        };

        assert_eq!(
            a_holds, b_holds,
            "the two sides ended up holding different keys for \
             {mine:#x}/g{my_gen}@{my_time} against {theirs:#x}/g{their_gen}@{their_time}"
        );
    }
}

// Three devices that each hold a key settle on the same one whatever
// order they meet in. This is what the rule being a total order buys, and
// it is the property the design is written against. The winner here is
// the only generation-2 key, which no creation time would have chosen.
#[test]
fn three_devices_converge_on_one_key_whichever_pairs_meet_first() {
    let devices: [(u8, u32, i64); 3] = [
        (0x30, 1, EARLIER + 2),
        (0x10, 1, EARLIER),
        (0x20, 2, EARLIER + 1),
    ];

    let orders: [[usize; 3]; 3] = [[0, 1, 2], [1, 2, 0], [2, 0, 1]];
    let mut settled = Vec::new();

    for order in orders {
        // Each device starts holding its own key, then meets the other
        // two in this order and keeps whatever the rule says.
        for start in 0..3 {
            let mut held = devices[start];
            for &other in &order {
                let theirs = devices[other];
                let mine = offer(held.0, held.1, held.2);
                let peer = offer(theirs.0, theirs.1, theirs.2);
                if resolve_collision(&mine, &peer) == CollisionOutcome::AdoptRemote {
                    held = theirs;
                }
            }
            settled.push(held.0);
        }
    }

    assert!(
        settled.iter().all(|&held| held == 0x20),
        "the devices did not converge on the highest generation: {settled:?}"
    );
}

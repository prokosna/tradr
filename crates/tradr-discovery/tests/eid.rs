//! Supervisor-authored tests for EID derivation, written before the
//! implementation. A Critical Module (CLAUDE.md section 6): an EID that
//! does not change with its window is a permanent identifier on the air,
//! and nothing downstream notices, because a scanner deriving the same
//! constant matches it perfectly and every other test stays green.

use tradr_core::UnixTime;
use tradr_discovery::{
    BROADCAST_SECRET_LEN, BroadcastSecret, EID_LEN, EID_WINDOW_SECS, Eid, EidError, EidWindow,
};

// The window `WINDOW_START` opens: 1_800_000_000 / 900 is exact, so the
// three seconds below sit at the window's first, last and next-first
// instant without any arithmetic in the test.
const WINDOW_INDEX: i64 = 2_000_000;
const WINDOW_START: i64 = 1_800_000_000;
const WINDOW_LAST: i64 = 1_800_000_899;
const NEXT_WINDOW_START: i64 = 1_800_000_900;

// Mid-window, so a test that is not about a boundary does not sit on one.
const MID_WINDOW: i64 = 1_800_000_450;

fn secret_a() -> BroadcastSecret {
    BroadcastSecret::from_bytes(&[0x11; BROADCAST_SECRET_LEN]).expect("32 bytes is a secret")
}

fn secret_b() -> BroadcastSecret {
    BroadcastSecret::from_bytes(&[0x22; BROADCAST_SECRET_LEN]).expect("32 bytes is a secret")
}

fn window(index: i64) -> EidWindow {
    EidWindow::from_index(index)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- The construction ADR-0018 fixed, pinned by value ---

#[test]
fn an_eid_is_the_first_eight_bytes_of_derive_key_over_the_secret_then_the_big_endian_window() {
    let eid = secret_a().eid(window(WINDOW_INDEX));

    assert_eq!(hex(eid.as_bytes()), "8a2d2bde1539e37a");
}

#[test]
fn the_window_is_appended_big_endian_and_a_little_endian_one_derives_something_else() {
    // ADR-0018 fixes the width and the byte order. The value below is the
    // same secret and window with the eight bytes reversed, and it is here
    // so the vector above is known to discriminate the two.
    let eid = secret_a().eid(window(WINDOW_INDEX));

    assert_ne!(hex(eid.as_bytes()), "21081bea8576169e");
}

#[test]
fn the_bootstrap_secret_is_derive_key_over_the_account_id_under_its_own_context() {
    let account_id = b"https://accounts.google.com\x00109876543210987654321";

    let secret = BroadcastSecret::bootstrap(account_id);

    assert_eq!(
        hex(secret.as_bytes()),
        "3cf895e8df7788473caff1df1cf80200a9d0b8997f74cac653c2d4abc9dbe663"
    );
}

#[test]
fn the_bootstrap_context_is_not_the_eid_context() {
    // The same material under "tradr-eid-v1" instead of
    // "tradr-bootstrap-v1". Two contexts that were accidentally one would
    // be invisible in every other test here, because both sides of a pair
    // would still agree with each other.
    let account_id = b"https://accounts.google.com\x00109876543210987654321";

    let secret = BroadcastSecret::bootstrap(account_id);

    assert_ne!(
        hex(secret.as_bytes()),
        "1d6cd7230942a1962ba61716df39c10394e6f0a22f7fa1bd0bd7bf8bc7e97435"
    );
}

#[test]
fn a_bootstrap_secret_derives_an_eid_the_same_way_any_other_secret_does() {
    // ADR-0018's point 4: one construction over three secrets, so the
    // bootstrap secret is not a second code path.
    let account_id = b"https://accounts.google.com\x00109876543210987654321";

    let eid = BroadcastSecret::bootstrap(account_id).eid(window(WINDOW_INDEX));

    assert_eq!(hex(eid.as_bytes()), "814bfa171b1b4ff5");
}

// --- Rotation: the property the module exists for ---

#[test]
fn an_eid_changes_when_the_window_advances() {
    // The tracking defect, stated as a test: an implementation that
    // ignores the window broadcasts one value forever, and every matching
    // test in this file still passes.
    let secret = secret_a();

    assert_ne!(
        secret.eid(window(WINDOW_INDEX)),
        secret.eid(window(WINDOW_INDEX + 1))
    );
}

#[test]
fn an_eid_is_the_same_for_the_same_secret_and_window() {
    // Two devices holding one secret must derive the same eight bytes, or
    // they never see each other at all.
    let secret = secret_a();

    assert_eq!(
        secret.eid(window(WINDOW_INDEX)),
        secret.eid(window(WINDOW_INDEX))
    );
}

#[test]
fn two_secrets_derive_different_eids_in_the_same_window() {
    assert_ne!(
        secret_a().eid(window(WINDOW_INDEX)),
        secret_b().eid(window(WINDOW_INDEX))
    );
}

#[test]
fn an_eid_occupies_exactly_the_advertised_eight_bytes() {
    // docs/03 fits the EID into a 31-byte advertisement with eight bytes
    // allotted to it, so the length is a wire constraint and not a taste.
    assert_eq!(EID_LEN, 8);
    assert_eq!(secret_a().eid(window(WINDOW_INDEX)).as_bytes().len(), 8);
}

// --- Windows: where the boundary is, and which direction rounds ---

#[test]
fn a_window_spans_the_fifteen_minutes_docs_03_specifies() {
    assert_eq!(EID_WINDOW_SECS, 900);
}

#[test]
fn the_first_and_last_second_of_a_window_share_it() {
    assert_eq!(
        EidWindow::containing(UnixTime::from_secs(WINDOW_START)).index(),
        WINDOW_INDEX
    );
    assert_eq!(
        EidWindow::containing(UnixTime::from_secs(WINDOW_LAST)).index(),
        WINDOW_INDEX
    );
}

#[test]
fn the_next_second_after_a_window_opens_the_next_one() {
    assert_eq!(
        EidWindow::containing(UnixTime::from_secs(NEXT_WINDOW_START)).index(),
        WINDOW_INDEX + 1
    );
}

#[test]
fn a_time_before_the_epoch_floors_rather_than_truncating_toward_zero() {
    // ADR-0018's third sub-decision. Rust's `/` truncates toward zero, so
    // `-1 / 900` is 0 and a device with a clock set before 1970 would
    // share the epoch's own window with every other such device --
    // silently, since both sides would agree.
    assert_eq!(EidWindow::containing(UnixTime::from_secs(-1)).index(), -1);
    assert_eq!(EidWindow::containing(UnixTime::from_secs(-900)).index(), -1);
    assert_eq!(EidWindow::containing(UnixTime::from_secs(-901)).index(), -2);
}

#[test]
fn a_negative_window_derives_the_eid_its_index_says_and_not_the_epoch_window() {
    assert_eq!(
        hex(secret_a().eid(window(0)).as_bytes()),
        "3d4a511553c5fb05"
    );
    assert_eq!(
        hex(secret_a().eid(window(-1)).as_bytes()),
        "d40ff35ebed65dd3"
    );
}

// --- Matching: the three windows, and only those three ---

#[test]
fn matching_accepts_an_eid_from_the_current_window() {
    let secret = secret_a();
    let observed = secret.eid(window(WINDOW_INDEX));

    assert_eq!(
        secret.matches(&observed, UnixTime::from_secs(MID_WINDOW)),
        Some(window(WINDOW_INDEX))
    );
}

#[test]
fn matching_accepts_an_eid_from_the_previous_and_the_next_window() {
    // docs/03: "To absorb clock skew, scanners try the t-1, t, and t+1
    // windows."
    let secret = secret_a();
    let now = UnixTime::from_secs(MID_WINDOW);

    let earlier = secret.eid(window(WINDOW_INDEX - 1));
    let later = secret.eid(window(WINDOW_INDEX + 1));

    assert_eq!(
        secret.matches(&earlier, now),
        Some(window(WINDOW_INDEX - 1))
    );
    assert_eq!(secret.matches(&later, now), Some(window(WINDOW_INDEX + 1)));
}

#[test]
fn matching_refuses_an_eid_two_windows_away_in_either_direction() {
    // The direction that matters. A wider allowance keeps recognising a
    // device by an identifier it has already rotated away from, which is
    // the tracking window this design bounds at 15 minutes -- and a
    // widened bound fails no other test in this file.
    let secret = secret_a();
    let now = UnixTime::from_secs(MID_WINDOW);

    let far_earlier = secret.eid(window(WINDOW_INDEX - 2));
    let far_later = secret.eid(window(WINDOW_INDEX + 2));

    assert_eq!(secret.matches(&far_earlier, now), None);
    assert_eq!(secret.matches(&far_later, now), None);
}

#[test]
fn matching_refuses_an_eid_derived_from_a_different_secret() {
    let observed = secret_b().eid(window(WINDOW_INDEX));

    assert_eq!(
        secret_a().matches(&observed, UnixTime::from_secs(MID_WINDOW)),
        None
    );
}

#[test]
fn matching_reports_which_window_answered_rather_than_only_that_one_did() {
    // The window is what a caller needs to tell a fresh sighting from one
    // that is already a quarter of an hour old.
    let secret = secret_a();
    let observed = secret.eid(window(WINDOW_INDEX - 1));

    let matched = secret.matches(&observed, UnixTime::from_secs(MID_WINDOW));

    assert_eq!(matched.map(EidWindow::index), Some(WINDOW_INDEX - 1));
}

// --- Construction from bytes, and what a secret must not print ---

#[test]
fn a_broadcast_secret_refuses_material_that_is_not_thirty_two_bytes() {
    // `unwrap_err` rather than comparing the whole `Result`: a
    // `BroadcastSecret` has no `PartialEq`, following `LinkSecret`, because
    // comparing secret material byte-wise is what a constant-time
    // comparison exists to avoid.
    assert_eq!(
        BroadcastSecret::from_bytes(&[0x11; 31]).unwrap_err(),
        EidError::WrongLength {
            expected: BROADCAST_SECRET_LEN,
            actual: 31
        }
    );
    assert_eq!(
        BroadcastSecret::from_bytes(&[0x11; 33]).unwrap_err(),
        EidError::WrongLength {
            expected: BROADCAST_SECRET_LEN,
            actual: 33
        }
    );
}

#[test]
fn an_eid_refuses_material_that_is_not_eight_bytes() {
    assert_eq!(
        Eid::from_bytes(&[0x11; 7]),
        Err(EidError::WrongLength {
            expected: EID_LEN,
            actual: 7
        })
    );
}

#[test]
fn an_eid_round_trips_through_its_bytes() {
    // A scanner builds one from what arrived on the air, so this is the
    // path every observation takes.
    let derived = secret_a().eid(window(WINDOW_INDEX));

    let rebuilt = Eid::from_bytes(derived.as_bytes()).expect("eight bytes is an Eid");

    assert_eq!(rebuilt, derived);
}

#[test]
fn a_broadcast_secret_does_not_print_its_bytes() {
    // Rule F4. An ABK or a Link Secret reaching a log is the whole secret
    // behind every EID a device has ever broadcast, which makes every past
    // sighting of it linkable after the fact.
    let printed = format!("{:?}", secret_a());

    assert!(
        !printed.contains("11"),
        "Debug printed the bytes: {printed}"
    );
    assert!(printed.contains("redacted"), "got: {printed}");
}

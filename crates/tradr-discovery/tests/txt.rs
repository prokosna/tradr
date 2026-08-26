//! Tests for the mDNS TXT record codec (docs/03, "1. mDNS / DNS-SD -- the
//! same LAN, Tier 0"). See tradr-core/tests/discovery.rs for the style
//! this follows.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tradr_core::{Capabilities, DEVICE_ID_LEN, DeviceId, DisplayName, DisplayNameError};
use tradr_discovery::{
    AGREEMENT_KEY_TAG_LEN, PLATFORM_MAX_LEN, Platform, PlatformError, TxtError, TxtRecord,
};

fn device(byte: u8) -> DeviceId {
    DeviceId::from_bytes(&[byte; DEVICE_ID_LEN]).expect("16 bytes must construct")
}

fn tag(byte: u8) -> [u8; AGREEMENT_KEY_TAG_LEN] {
    [byte; AGREEMENT_KEY_TAG_LEN]
}

fn find<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn valid_record(display_name: Option<DisplayName>) -> TxtRecord {
    TxtRecord::new(
        device(0x11),
        tag(0x22),
        display_name,
        Capabilities::DIRECT_QUIC,
        Platform::new("linux").expect("valid platform"),
    )
}

// --- Round trip ---

#[test]
fn round_trips_with_a_display_name() {
    let name = DisplayName::new("Alice's laptop").expect("valid display name");
    let original = valid_record(Some(name));

    let pairs = original.to_pairs();
    let parsed = TxtRecord::parse(&pairs).expect("valid record must parse");

    assert_eq!(original, parsed);
}

#[test]
fn round_trips_without_a_display_name() {
    let original = valid_record(None);

    let pairs = original.to_pairs();
    let parsed = TxtRecord::parse(&pairs).expect("valid record must parse");

    assert_eq!(original, parsed);
}

#[test]
fn to_pairs_omits_n_entirely_when_there_is_no_display_name() {
    let record = valid_record(None);
    let pairs = record.to_pairs();

    assert!(find(&pairs, "n").is_none());
}

#[test]
fn id_renders_as_exactly_twenty_two_characters() {
    let record = valid_record(None);
    let pairs = record.to_pairs();

    let id = find(&pairs, "id").expect("id must be present");
    assert_eq!(id.len(), 22);
}

#[test]
fn pk_renders_as_exactly_eleven_characters() {
    let record = valid_record(None);
    let pairs = record.to_pairs();

    let pk = find(&pairs, "pk").expect("pk must be present");
    assert_eq!(pk.len(), 11);
}

// --- Missing required keys ---

fn valid_pairs() -> Vec<(String, String)> {
    valid_record(None).to_pairs()
}

fn without_key(key: &str) -> Vec<(String, String)> {
    valid_pairs()
        .into_iter()
        .filter(|(k, _)| k != key)
        .collect()
}

#[test]
fn parse_rejects_missing_v() {
    assert_eq!(
        TxtRecord::parse(&without_key("v")),
        Err(TxtError::MissingKey("v"))
    );
}

#[test]
fn parse_rejects_missing_id() {
    assert_eq!(
        TxtRecord::parse(&without_key("id")),
        Err(TxtError::MissingKey("id"))
    );
}

#[test]
fn parse_rejects_missing_pk() {
    assert_eq!(
        TxtRecord::parse(&without_key("pk")),
        Err(TxtError::MissingKey("pk"))
    );
}

#[test]
fn parse_rejects_missing_p() {
    assert_eq!(
        TxtRecord::parse(&without_key("p")),
        Err(TxtError::MissingKey("p"))
    );
}

#[test]
fn parse_rejects_missing_c() {
    assert_eq!(
        TxtRecord::parse(&without_key("c")),
        Err(TxtError::MissingKey("c"))
    );
}

// --- Unrecognised version is accepted, not filtered ---

#[test]
fn parse_accepts_an_unrecognised_version() {
    let mut pairs = valid_pairs();
    for (k, v) in pairs.iter_mut() {
        if k == "v" {
            *v = "9999".to_string();
        }
    }

    let record = TxtRecord::parse(&pairs).expect("an unknown version must still parse");
    assert_eq!(record.version(), 9999);
}

// --- Malformed id ---

fn replace(pairs: &mut [(String, String)], key: &str, value: &str) {
    for (k, v) in pairs.iter_mut() {
        if k == key {
            *v = value.to_string();
        }
    }
}

#[test]
fn parse_rejects_id_that_is_not_valid_base64url() {
    let mut pairs = valid_pairs();
    replace(&mut pairs, "id", "not!valid!base64!");

    assert_eq!(TxtRecord::parse(&pairs), Err(TxtError::MalformedDeviceId));
}

#[test]
fn parse_rejects_id_that_decodes_to_fifteen_bytes() {
    let mut pairs = valid_pairs();
    let short = URL_SAFE_NO_PAD.encode([0u8; 15]);
    replace(&mut pairs, "id", &short);

    assert_eq!(TxtRecord::parse(&pairs), Err(TxtError::MalformedDeviceId));
}

#[test]
fn parse_rejects_id_that_decodes_to_seventeen_bytes() {
    let mut pairs = valid_pairs();
    let long = URL_SAFE_NO_PAD.encode([0u8; 17]);
    replace(&mut pairs, "id", &long);

    assert_eq!(TxtRecord::parse(&pairs), Err(TxtError::MalformedDeviceId));
}

// --- Malformed pk ---

#[test]
fn parse_rejects_pk_that_decodes_to_seven_bytes() {
    let mut pairs = valid_pairs();
    let short = URL_SAFE_NO_PAD.encode([0u8; 7]);
    replace(&mut pairs, "pk", &short);

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::MalformedAgreementKeyTag)
    );
}

#[test]
fn parse_rejects_pk_that_decodes_to_nine_bytes() {
    let mut pairs = valid_pairs();
    let long = URL_SAFE_NO_PAD.encode([0u8; 9]);
    replace(&mut pairs, "pk", &long);

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::MalformedAgreementKeyTag)
    );
}

// --- Malformed c ---

#[test]
fn parse_rejects_c_that_is_not_a_number() {
    let mut pairs = valid_pairs();
    replace(&mut pairs, "c", "not-a-number");

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::MalformedCapabilities)
    );
}

#[test]
fn parse_rejects_c_that_exceeds_u16() {
    let mut pairs = valid_pairs();
    replace(&mut pairs, "c", "70000");

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::MalformedCapabilities)
    );
}

// --- Reserved capability bits survive the round trip ---

#[test]
fn a_reserved_capability_bit_round_trips_unmasked() {
    let reserved_bit_9 = 1u16 << 9;
    let record = TxtRecord::new(
        device(0x33),
        tag(0x44),
        None,
        Capabilities::from_bits(Capabilities::DIRECT_QUIC.bits() | reserved_bit_9),
        Platform::new("linux").expect("valid platform"),
    );

    let pairs = record.to_pairs();
    let parsed = TxtRecord::parse(&pairs).expect("valid record must parse");

    assert_eq!(
        parsed.capabilities().bits() & reserved_bit_9,
        reserved_bit_9
    );
}

// --- Invalid display name ---

#[test]
fn parse_rejects_an_over_length_display_name() {
    let mut pairs = valid_pairs();
    let too_long = "a".repeat(33);
    pairs.push(("n".to_string(), too_long));

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::InvalidDisplayName(DisplayNameError::TooLong(33)))
    );
}

#[test]
fn parse_rejects_a_display_name_with_a_control_character() {
    let mut pairs = valid_pairs();
    pairs.push(("n".to_string(), "bad\u{0007}name".to_string()));

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::InvalidDisplayName(
            DisplayNameError::ControlCharacter('\u{0007}')
        ))
    );
}

// --- Invalid platform ---

#[test]
fn parse_rejects_an_empty_platform() {
    let mut pairs = valid_pairs();
    replace(&mut pairs, "p", "");

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::InvalidPlatform(PlatformError::Empty))
    );
}

#[test]
fn parse_rejects_an_over_length_platform() {
    let mut pairs = valid_pairs();
    let too_long = "a".repeat(PLATFORM_MAX_LEN + 1);
    replace(&mut pairs, "p", &too_long);

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::InvalidPlatform(PlatformError::TooLong(
            PLATFORM_MAX_LEN + 1
        )))
    );
}

#[test]
fn parse_rejects_a_platform_with_a_control_character() {
    let mut pairs = valid_pairs();
    replace(&mut pairs, "p", "li\u{0007}nux");

    assert_eq!(
        TxtRecord::parse(&pairs),
        Err(TxtError::InvalidPlatform(PlatformError::ControlCharacter(
            '\u{0007}'
        )))
    );
}

// --- Unknown keys and duplicates ---

#[test]
fn an_unknown_extra_key_is_ignored() {
    let mut pairs = valid_pairs();
    pairs.push(("future-key".to_string(), "future-value".to_string()));

    assert!(TxtRecord::parse(&pairs).is_ok());
}

#[test]
fn a_duplicate_key_takes_the_first_occurrence() {
    let mut pairs = valid_pairs();
    // Prepend a bogus first "v" so the genuine value becomes the second
    // occurrence, proving the first, not the last, wins.
    pairs.insert(0, ("v".to_string(), "42".to_string()));

    let record = TxtRecord::parse(&pairs).expect("valid record must parse");
    assert_eq!(record.version(), 42);
}

// --- Platform accepts an unheard-of value (Change Drill D7) ---

#[test]
fn platform_new_accepts_known_and_unheard_of_values() {
    for value in ["linux", "win", "mac", "android", "ios"] {
        assert!(Platform::new(value).is_ok(), "{value} must be accepted");
    }
}

// --- The base64 alphabet is url-safe, not standard: pinned with bytes
// deliberately chosen so the encoding contains both '-' and '_', since a
// repeated-byte DeviceId such as `device(0x11)` never does and would let
// the wrong alphabet pass unnoticed ---

#[test]
fn id_round_trips_through_an_encoding_that_exercises_both_url_safe_characters() {
    // Chosen so URL_SAFE_NO_PAD renders both '-' and '_'; STANDARD_NO_PAD
    // would render '+' and '/' at the same positions instead.
    let bytes: [u8; DEVICE_ID_LEN] = [
        67, 120, 77, 197, 203, 227, 90, 123, 63, 10, 111, 174, 191, 129, 219, 209,
    ];
    let device_id = DeviceId::from_bytes(&bytes).expect("16 bytes must construct");

    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    assert!(encoded.contains('-'), "premise: encoding must contain '-'");
    assert!(encoded.contains('_'), "premise: encoding must contain '_'");

    let record = TxtRecord::new(
        device_id,
        tag(0x22),
        None,
        Capabilities::DIRECT_QUIC,
        Platform::new("linux").expect("valid platform"),
    );

    let pairs = record.to_pairs();
    assert_eq!(find(&pairs, "id"), Some(encoded.as_str()));

    let parsed = TxtRecord::parse(&pairs).expect("valid record must parse");
    assert_eq!(record, parsed);
}

#[test]
fn pk_round_trips_through_an_encoding_that_exercises_both_url_safe_characters() {
    // Chosen so URL_SAFE_NO_PAD renders both '-' and '_'; STANDARD_NO_PAD
    // would render '+' and '/' at the same positions instead.
    let bytes: [u8; AGREEMENT_KEY_TAG_LEN] = [4, 86, 2, 84, 207, 187, 254, 217];

    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    assert!(encoded.contains('-'), "premise: encoding must contain '-'");
    assert!(encoded.contains('_'), "premise: encoding must contain '_'");

    let record = TxtRecord::new(
        device(0x11),
        bytes,
        None,
        Capabilities::DIRECT_QUIC,
        Platform::new("linux").expect("valid platform"),
    );

    let pairs = record.to_pairs();
    assert_eq!(find(&pairs, "pk"), Some(encoded.as_str()));

    let parsed = TxtRecord::parse(&pairs).expect("valid record must parse");
    assert_eq!(record, parsed);
}

// --- Platform's length bound is measured in bytes, not chars ---

#[test]
fn platform_new_rejects_seventeen_bytes_and_accepts_sixteen_bytes_measured_in_bytes_not_chars() {
    // "\u{00e9}" (e-acute) is 2 bytes in UTF-8, so 8 copies is exactly
    // PLATFORM_MAX_LEN (16) bytes, and 8 copies plus one ASCII byte is
    // exactly 17 bytes while still only 9 chars.
    let accepted = "\u{00e9}".repeat(8);
    assert_eq!(accepted.len(), PLATFORM_MAX_LEN);
    assert!(Platform::new(&accepted).is_ok());

    let rejected = format!("{accepted}a");
    assert_eq!(rejected.len(), PLATFORM_MAX_LEN + 1);
    assert_eq!(
        Platform::new(&rejected),
        Err(PlatformError::TooLong(PLATFORM_MAX_LEN + 1))
    );
}

//! Supervisor-authored tests for the Deferred Delivery envelope (docs/13,
//! ADR-0025, DCR-173). Critical Module: opening an envelope is where a forged
//! or altered delivery would be accepted.

use std::cell::RefCell;

use tradr_core::{
    ContentHash, DomainTag, KeyBinding, KeyStore, KeyStoreError, PublicIdentity, PublicKeyPoint,
    RelPath, Rng, RngError, SharedSecret, TransferId, TrustTier, UnixTime,
};
use tradr_identity::envelope::{
    EnvelopeError, EnvelopeItem, EnvelopeSender, open_envelope, parse_outer_header, seal_envelope,
};
use tradr_identity::{OsRng, SoftwareKeyStore};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 24 * 3600;
const TRANSFER: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

struct Device {
    store: SoftwareKeyStore,
    identity: PublicIdentity,
}

fn device() -> Device {
    let store = SoftwareKeyStore::generate(&OsRng).expect("generate");
    let identity = store.public_identity().expect("identity");
    Device { store, identity }
}

fn binding_for(d: &Device, not_after: i64) -> KeyBinding {
    let sig = d
        .store
        .sign(DomainTag::KeyBind, d.identity.agreement_pub().as_bytes())
        .expect("sign binding");
    KeyBinding::new(
        d.identity.agreement_pub().clone(),
        sig,
        UnixTime::from_secs(not_after),
    )
}

fn sender_material(d: &Device) -> EnvelopeSender {
    EnvelopeSender::new(
        d.identity.clone(),
        binding_for(d, NOW + 30 * DAY),
        "attestation-token-of-sender".to_string(),
    )
}

fn item(path: &str, bytes: &[u8]) -> EnvelopeItem {
    EnvelopeItem::new(
        RelPath::new(path).expect("relpath"),
        bytes.len() as u64,
        ContentHash::from_bytes(blake3::hash(bytes).into()),
    )
}

fn transfer() -> TransferId {
    TRANSFER.parse().expect("transfer id")
}

fn agree_with(d: &Device) -> impl Fn(&PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> + '_ {
    move |peer| d.store.agree(peer)
}

fn same_account(_: &str, _: &PublicIdentity, _: UnixTime) -> Result<TrustTier, String> {
    Ok(TrustTier::SameAccount)
}

fn big(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

fn sealed(
    sender: &Device,
    recipient: &Device,
    created_at: i64,
    files: &[(&str, &[u8])],
) -> Vec<u8> {
    let items: Vec<(EnvelopeItem, &[u8])> = files.iter().map(|(p, b)| (item(p, b), *b)).collect();
    seal_envelope(
        &recipient.identity,
        &sender_material(sender),
        &sender.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(created_at),
        &items,
    )
    .expect("seal")
}

#[test]
fn a_recipient_opens_what_was_sealed_to_it() {
    let (alice, bob) = (device(), device());
    let large = big(2 * 1024 * 1024 + 513);
    let bytes = sealed(
        &alice,
        &bob,
        NOW - 60,
        &[("photos/large.bin", &large), ("empty.txt", b"")],
    );

    let opened = open_envelope(
        &bytes,
        &bob.identity,
        &agree_with(&bob),
        UnixTime::from_secs(NOW),
        &same_account,
    )
    .expect("open");

    assert_eq!(opened.transfer_id(), transfer());
    assert_eq!(opened.sender(), &alice.identity);
    assert_eq!(opened.created_at(), UnixTime::from_secs(NOW - 60));
    assert_eq!(opened.tier(), TrustTier::SameAccount);
    assert_eq!(opened.items().len(), 2);
    assert_eq!(opened.items()[0].rel_path().as_str(), "photos/large.bin");
    assert_eq!(opened.contents()[0], large);
    assert!(opened.contents()[1].is_empty());
}

#[test]
fn the_outer_header_routes_and_reveals_no_name() {
    let (alice, bob) = (device(), device());
    let bytes = sealed(&alice, &bob, NOW, &[("secret-report.pdf", b"contents")]);

    let header = parse_outer_header(&bytes).expect("header");
    assert_eq!(header.recipient_device_id(), bob.identity.device_id());
    assert_eq!(header.sender_device_id(), alice.identity.device_id());
    assert_eq!(header.total_len(), bytes.len() as u64);

    let needle = b"secret-report.pdf";
    assert!(!bytes.windows(needle.len()).any(|w| w == needle));
    let token = b"attestation-token-of-sender";
    assert!(!bytes.windows(token.len()).any(|w| w == token));
}

#[test]
fn another_device_cannot_open_it() {
    let (alice, bob, eve) = (device(), device(), device());
    let bytes = sealed(&alice, &bob, NOW, &[("a.txt", b"hello")]);
    assert!(
        open_envelope(
            &bytes,
            &eve.identity,
            &agree_with(&eve),
            UnixTime::from_secs(NOW),
            &same_account
        )
        .is_err()
    );
    assert!(
        open_envelope(
            &bytes,
            &bob.identity,
            &agree_with(&eve),
            UnixTime::from_secs(NOW),
            &same_account
        )
        .is_err()
    );
}

fn open_as_bob(bytes: &[u8], bob: &Device) -> Result<(), EnvelopeError> {
    open_envelope(
        bytes,
        &bob.identity,
        &agree_with(bob),
        UnixTime::from_secs(NOW),
        &same_account,
    )
    .map(|_| ())
}

#[test]
fn rewriting_either_device_id_in_the_header_is_refused() {
    let (alice, bob, carol) = (device(), device(), device());
    let bytes = sealed(&alice, &bob, NOW, &[("a.txt", b"hello")]);
    let header = parse_outer_header(&bytes).expect("header");
    let recipient = header.recipient_device_id();
    let sender = header.sender_device_id();

    for (from, to) in [
        (recipient, carol.identity.device_id()),
        (sender, carol.identity.device_id()),
    ] {
        let mut altered = bytes.clone();
        let pos = altered
            .windows(16)
            .position(|w| w == from.as_bytes())
            .expect("device id present in header");
        altered[pos..pos + 16].copy_from_slice(to.as_bytes());
        assert!(open_as_bob(&altered, &bob).is_err());
    }
}

#[test]
fn a_flipped_byte_anywhere_after_the_header_is_refused() {
    let (alice, bob) = (device(), device());
    let bytes = sealed(&alice, &bob, NOW, &[("a.bin", &big(1024 * 1024 + 10))]);
    for pos in [bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
        let mut altered = bytes.clone();
        altered[pos] ^= 0x01;
        assert!(open_as_bob(&altered, &bob).is_err(), "byte {pos}");
    }
}

#[test]
fn a_truncated_envelope_is_refused() {
    let (alice, bob) = (device(), device());
    let bytes = sealed(&alice, &bob, NOW, &[("a.bin", &big(3 * 1024 * 1024))]);
    for cut in [1, 100, 1024 * 1024 + 40] {
        assert!(
            open_as_bob(&bytes[..bytes.len() - cut], &bob).is_err(),
            "cut {cut}"
        );
    }
}

#[test]
fn an_envelope_with_trailing_bytes_is_refused() {
    let (alice, bob) = (device(), device());
    let mut bytes = sealed(&alice, &bob, NOW, &[("a.txt", b"hello")]);
    bytes.extend_from_slice(b"extra");
    assert!(open_as_bob(&bytes, &bob).is_err());
}

#[test]
fn swapping_two_data_records_is_refused() {
    let (alice, bob) = (device(), device());
    let first = vec![0x11u8; 1024 * 1024];
    let second = vec![0x22u8; 1024 * 1024];
    let mut payload = first.clone();
    payload.extend_from_slice(&second);
    let bytes = sealed(&alice, &bob, NOW, &[("a.bin", &payload)]);

    // Records carry a length prefix; find the two full data records by size and swap them.
    let record_len = 1024 * 1024 + 16;
    let ends: Vec<usize> = (0..bytes.len().saturating_sub(4))
        .filter(|&i| {
            u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize
                == record_len
        })
        .collect();
    assert!(
        ends.len() >= 2,
        "two full-size records with a u32 big-endian length prefix"
    );
    let (a, b) = (ends[0], ends[1]);
    let mut altered = bytes.clone();
    let rec_a = bytes[a..a + 4 + record_len].to_vec();
    let rec_b = bytes[b..b + 4 + record_len].to_vec();
    altered[a..a + 4 + record_len].copy_from_slice(&rec_b);
    altered[b..b + 4 + record_len].copy_from_slice(&rec_a);
    assert!(open_as_bob(&altered, &bob).is_err());
}

#[test]
fn a_manifest_signed_by_another_identity_key_is_refused() {
    let (alice, bob, mallory) = (device(), device(), device());
    let items = [(item("a.txt", b"hello"), b"hello".as_slice())];
    // Claims to be Alice but signs with Mallory's key.
    let bytes = seal_envelope(
        &bob.identity,
        &sender_material(&alice),
        &mallory.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW),
        &items,
    )
    .expect("seal");
    assert!(matches!(
        open_as_bob(&bytes, &bob),
        Err(EnvelopeError::SignatureInvalid)
    ));
}

#[test]
fn a_key_binding_for_another_agreement_key_or_expired_at_creation_is_refused() {
    let (alice, bob, other) = (device(), device(), device());
    let items = [(item("a.txt", b"hello"), b"hello".as_slice())];

    let foreign = EnvelopeSender::new(
        alice.identity.clone(),
        binding_for(&other, NOW + DAY),
        "t".into(),
    );
    let bytes = seal_envelope(
        &bob.identity,
        &foreign,
        &alice.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW),
        &items,
    )
    .expect("seal");
    assert!(open_as_bob(&bytes, &bob).is_err());

    let expired = EnvelopeSender::new(
        alice.identity.clone(),
        binding_for(&alice, NOW - 100),
        "t".into(),
    );
    let bytes = seal_envelope(
        &bob.identity,
        &expired,
        &alice.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW - 50),
        &items,
    )
    .expect("seal");
    assert!(open_as_bob(&bytes, &bob).is_err());
}

#[test]
fn the_attestation_check_decides_and_is_asked_about_creation_time() {
    let (alice, bob) = (device(), device());
    let bytes = sealed(&alice, &bob, NOW - 5 * DAY, &[("a.txt", b"hello")]);

    let seen: RefCell<Option<(String, PublicIdentity, UnixTime)>> = RefCell::new(None);
    let recording = |token: &str, id: &PublicIdentity, at: UnixTime| -> Result<TrustTier, String> {
        *seen.borrow_mut() = Some((token.to_string(), id.clone(), at));
        Ok(TrustTier::Linked)
    };
    let opened = open_envelope(
        &bytes,
        &bob.identity,
        &agree_with(&bob),
        UnixTime::from_secs(NOW),
        &recording,
    )
    .expect("linked is accepted");
    assert_eq!(opened.tier(), TrustTier::Linked);
    let (token, id, at) = seen.borrow().clone().expect("asked");
    assert_eq!(token, "attestation-token-of-sender");
    assert_eq!(id, alice.identity);
    assert_eq!(at, UnixTime::from_secs(NOW - 5 * DAY));

    let refusing = |_: &str, _: &PublicIdentity, _: UnixTime| -> Result<TrustTier, String> {
        Err("stale".into())
    };
    assert!(
        open_envelope(
            &bytes,
            &bob.identity,
            &agree_with(&bob),
            UnixTime::from_secs(NOW),
            &refusing
        )
        .is_err()
    );

    let nearby = |_: &str, _: &PublicIdentity, _: UnixTime| -> Result<TrustTier, String> {
        Ok(TrustTier::NearbyEphemeral)
    };
    assert!(
        open_envelope(
            &bytes,
            &bob.identity,
            &agree_with(&bob),
            UnixTime::from_secs(NOW),
            &nearby
        )
        .is_err()
    );
}

#[test]
fn creation_time_must_fall_within_thirty_days_and_not_far_ahead() {
    let (alice, bob) = (device(), device());
    let ok_old = sealed(&alice, &bob, NOW - 30 * DAY + 60, &[("a.txt", b"x")]);
    assert!(open_as_bob(&ok_old, &bob).is_ok());
    let too_old = sealed(&alice, &bob, NOW - 30 * DAY - 60, &[("a.txt", b"x")]);
    assert!(open_as_bob(&too_old, &bob).is_err());
    let ok_ahead = sealed(&alice, &bob, NOW + 299, &[("a.txt", b"x")]);
    assert!(open_as_bob(&ok_ahead, &bob).is_ok());
    let too_far_ahead = sealed(&alice, &bob, NOW + 301, &[("a.txt", b"x")]);
    assert!(open_as_bob(&too_far_ahead, &bob).is_err());
}

#[test]
fn an_item_whose_bytes_do_not_match_its_content_hash_is_refused() {
    let (alice, bob) = (device(), device());
    let wrong = EnvelopeItem::new(
        RelPath::new("a.txt").expect("relpath"),
        5,
        ContentHash::from_bytes([0u8; 32]),
    );
    let bytes = seal_envelope(
        &bob.identity,
        &sender_material(&alice),
        &alice.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW),
        &[(wrong, b"hello".as_slice())],
    )
    .expect("seal");
    assert!(open_as_bob(&bytes, &bob).is_err());
}

#[test]
fn an_item_whose_bytes_do_not_match_its_declared_size_is_refused_by_the_sender() {
    let (alice, bob) = (device(), device());
    let lying = EnvelopeItem::new(
        RelPath::new("a.txt").expect("relpath"),
        99,
        ContentHash::from_bytes(blake3::hash(b"hello").into()),
    );
    assert!(
        seal_envelope(
            &bob.identity,
            &sender_material(&alice),
            &alice.store,
            &OsRng,
            transfer(),
            UnixTime::from_secs(NOW),
            &[(lying, b"hello".as_slice())],
        )
        .is_err()
    );
}

struct Zeros;

impl Rng for Zeros {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(0);
        Ok(())
    }
}

#[test]
fn an_rng_that_yields_no_key_is_an_error_and_not_a_panic() {
    let (alice, bob) = (device(), device());
    assert!(
        seal_envelope(
            &bob.identity,
            &sender_material(&alice),
            &alice.store,
            &Zeros,
            transfer(),
            UnixTime::from_secs(NOW),
            &[(item("a.txt", b"x"), b"x".as_slice())],
        )
        .is_err()
    );
}

#[test]
fn garbage_is_an_error_and_not_a_panic() {
    let bob = device();
    for len in [0usize, 1, 16, 33, 100, 200] {
        assert!(open_as_bob(&vec![0xA5; len], &bob).is_err(), "len {len}");
    }
}

//! Supervisor-authored tests for streaming a Deferred Delivery envelope
//! (docs/13, ADR-0025). Critical Module: a multi-gigabyte delivery must be
//! sealed and opened without holding it whole, and accepted no sooner.

use tradr_core::{
    ContentHash, DomainTag, KeyBinding, KeyStore, KeyStoreError, PublicIdentity, PublicKeyPoint,
    RelPath, SharedSecret, TransferId, TrustTier, UnixTime,
};
use tradr_identity::envelope::{
    EnvelopeItem, EnvelopeReader, EnvelopeSender, EnvelopeWriter, ReaderEvent, open_envelope,
};
use tradr_identity::{OsRng, SoftwareKeyStore};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 24 * 3600;
const MIB: usize = 1024 * 1024;

struct Device {
    store: SoftwareKeyStore,
    identity: PublicIdentity,
}

fn device() -> Device {
    let store = SoftwareKeyStore::generate(&OsRng).expect("generate");
    let identity = store.public_identity().expect("identity");
    Device { store, identity }
}

fn sender_material(d: &Device) -> EnvelopeSender {
    let sig = d
        .store
        .sign(DomainTag::KeyBind, d.identity.agreement_pub().as_bytes())
        .expect("sign binding");
    EnvelopeSender::new(
        d.identity.clone(),
        KeyBinding::new(
            d.identity.agreement_pub().clone(),
            sig,
            UnixTime::from_secs(NOW + 30 * DAY),
        ),
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
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("transfer id")
}

fn agree_with(d: &Device) -> impl Fn(&PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> + '_ {
    move |peer| d.store.agree(peer)
}

fn same_account(_: &str, _: &PublicIdentity, _: UnixTime) -> Result<TrustTier, String> {
    Ok(TrustTier::SameAccount)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32).wrapping_mul(31).wrapping_add(seed as u32) % 251) as u8)
        .collect()
}

// Seals through the streaming writer, pushing the items' bytes in slices of `slice`.
fn write_streamed(
    sender: &Device,
    recipient: &Device,
    files: &[(&str, Vec<u8>)],
    slice: usize,
) -> (Vec<u8>, u64) {
    let items: Vec<EnvelopeItem> = files.iter().map(|(p, b)| item(p, b)).collect();
    let (mut writer, mut out) = EnvelopeWriter::new(
        &recipient.identity,
        &sender_material(sender),
        &sender.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW),
        items,
    )
    .expect("writer");
    let declared = writer.total_len();
    let all: Vec<u8> = files.iter().flat_map(|(_, b)| b.iter().copied()).collect();
    for chunk in all.chunks(slice.max(1)) {
        out.extend(writer.push(chunk).expect("push"));
    }
    out.extend(writer.finish().expect("finish"));
    (out, declared)
}

struct Collected {
    manifest_first: bool,
    items: Vec<Vec<u8>>,
    verified: Vec<usize>,
}

// Opens through the streaming reader, feeding `bytes` in slices of `slice`.
fn read_streamed(recipient: &Device, bytes: &[u8], slice: usize) -> Result<Collected, String> {
    let agree = agree_with(recipient);
    let mut reader = EnvelopeReader::new(
        &recipient.identity,
        &agree,
        UnixTime::from_secs(NOW),
        &same_account,
    );
    let mut collected = Collected {
        manifest_first: false,
        items: Vec::new(),
        verified: Vec::new(),
    };
    let mut seen_any = false;
    for chunk in bytes.chunks(slice.max(1)) {
        for event in reader.feed(chunk).map_err(|e| e.to_string())? {
            match event {
                ReaderEvent::Manifest(manifest) => {
                    collected.manifest_first = !seen_any;
                    collected.items = vec![Vec::new(); manifest.items().len()];
                }
                ReaderEvent::ItemData { index, bytes } => collected.items[index].extend(bytes),
                ReaderEvent::ItemVerified { index } => collected.verified.push(index),
            }
            seen_any = true;
        }
    }
    reader.finish().map_err(|e| e.to_string())?;
    Ok(collected)
}

#[test]
fn what_the_writer_streams_opens_in_memory_and_matches_its_declared_length() {
    let (alice, bob) = (device(), device());
    let files = vec![
        ("big.bin", pattern(3 * MIB + 777, 1)),
        ("small.txt", b"hello".to_vec()),
        ("empty", Vec::new()),
    ];
    for slice in [4096, MIB - 1, 5 * MIB] {
        let (bytes, declared) = write_streamed(&alice, &bob, &files, slice);
        assert_eq!(bytes.len() as u64, declared, "slice {slice}");
        let opened = open_envelope(
            &bytes,
            &bob.identity,
            &agree_with(&bob),
            UnixTime::from_secs(NOW),
            &same_account,
        )
        .expect("open");
        for (i, (_, b)) in files.iter().enumerate() {
            assert_eq!(&opened.contents()[i], b, "slice {slice}, item {i}");
        }
    }
}

#[test]
fn single_byte_pushes_produce_an_envelope_that_opens() {
    let (alice, bob) = (device(), device());
    let files = vec![("a.txt", pattern(5000, 3)), ("b.txt", pattern(17, 4))];
    let (bytes, _) = write_streamed(&alice, &bob, &files, 1);
    assert!(
        open_envelope(
            &bytes,
            &bob.identity,
            &agree_with(&bob),
            UnixTime::from_secs(NOW),
            &same_account
        )
        .is_ok()
    );
}

#[test]
fn the_reader_yields_the_manifest_first_then_each_items_bytes_then_its_verification() {
    let (alice, bob) = (device(), device());
    let files = vec![
        ("one.bin", pattern(MIB + 5, 7)),
        ("two.bin", pattern(2 * MIB, 8)),
        ("three", Vec::new()),
    ];
    let (bytes, _) = write_streamed(&alice, &bob, &files, 64 * 1024);
    for slice in [1000, 65_537, MIB + 3, bytes.len()] {
        let got = read_streamed(&bob, &bytes, slice).expect("read");
        assert!(got.manifest_first, "slice {slice}");
        for (i, (_, b)) in files.iter().enumerate() {
            assert_eq!(&got.items[i], b, "slice {slice}, item {i}");
        }
        assert_eq!(got.verified, vec![0, 1, 2], "slice {slice}");
    }
}

#[test]
fn the_reader_opens_what_the_in_memory_sealer_made() {
    let (alice, bob) = (device(), device());
    let content = pattern(2 * MIB + 9, 9);
    let bytes = tradr_identity::envelope::seal_envelope(
        &bob.identity,
        &sender_material(&alice),
        &alice.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW),
        &[(item("x.bin", &content), content.as_slice())],
    )
    .expect("seal");
    let got = read_streamed(&bob, &bytes, 300_000).expect("read");
    assert_eq!(got.items[0], content);
}

#[test]
fn a_corrupted_item_is_never_verified_and_the_read_fails() {
    let (alice, bob) = (device(), device());
    let good = pattern(1000, 1);
    let mut claimed = item("a.bin", &good);
    claimed = EnvelopeItem::new(
        claimed.rel_path().clone(),
        claimed.size(),
        ContentHash::from_bytes([7u8; 32]),
    );
    let (mut writer, mut bytes) = EnvelopeWriter::new(
        &bob.identity,
        &sender_material(&alice),
        &alice.store,
        &OsRng,
        transfer(),
        UnixTime::from_secs(NOW),
        vec![claimed, item("b.bin", b"second")],
    )
    .expect("writer");
    bytes.extend(writer.push(&good).expect("push"));
    bytes.extend(writer.push(b"second").expect("push"));
    bytes.extend(writer.finish().expect("finish"));

    let agree = agree_with(&bob);
    let mut reader = EnvelopeReader::new(
        &bob.identity,
        &agree,
        UnixTime::from_secs(NOW),
        &same_account,
    );
    let mut verified = Vec::new();
    let mut failed = false;
    for chunk in bytes.chunks(4096) {
        match reader.feed(chunk) {
            Ok(events) => {
                for e in events {
                    if let ReaderEvent::ItemVerified { index } = e {
                        verified.push(index);
                    }
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(failed, "a hash mismatch must fail the feed");
    assert!(!verified.contains(&0));
}

#[test]
fn another_recipient_gets_an_error_before_any_item_bytes() {
    let (alice, bob, eve) = (device(), device(), device());
    let (bytes, _) = write_streamed(&alice, &bob, &[("a.bin", pattern(MIB, 1))], 4096);
    let agree = agree_with(&eve);
    let mut reader = EnvelopeReader::new(
        &eve.identity,
        &agree,
        UnixTime::from_secs(NOW),
        &same_account,
    );
    for chunk in bytes.chunks(4096) {
        match reader.feed(chunk) {
            Ok(events) => assert!(
                events
                    .iter()
                    .all(|e| !matches!(e, ReaderEvent::ItemData { .. })),
                "no item bytes for the wrong recipient"
            ),
            Err(_) => return,
        }
    }
    panic!("the wrong recipient must be refused");
}

#[test]
fn a_truncated_stream_fails_at_finish_and_trailing_bytes_fail_at_feed() {
    let (alice, bob) = (device(), device());
    let (bytes, _) = write_streamed(&alice, &bob, &[("a.bin", pattern(2 * MIB, 2))], 4096);
    assert!(read_streamed(&bob, &bytes[..bytes.len() - 10], 4096).is_err());
    let mut longer = bytes.clone();
    longer.extend_from_slice(b"x");
    assert!(read_streamed(&bob, &longer, 4096).is_err());
}

#[test]
fn a_writer_refuses_more_or_fewer_bytes_than_declared() {
    let (alice, bob) = (device(), device());
    let make = || {
        EnvelopeWriter::new(
            &bob.identity,
            &sender_material(&alice),
            &alice.store,
            &OsRng,
            transfer(),
            UnixTime::from_secs(NOW),
            vec![item("a.txt", b"hello")],
        )
        .expect("writer")
        .0
    };
    let mut too_many = make();
    assert!(too_many.push(b"hello!").is_err() || too_many.finish().is_err());
    let mut too_few = make();
    too_few.push(b"hell").expect("push");
    assert!(too_few.finish().is_err());
}

//! Supervisor-written tests for the inviter's half of the linking
//! exchange (CLAUDE.md section 6). A wrong answer here links a stranger's
//! account, and every check it makes is one no later stage repeats.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tauri_plugin_tradr::link_exchange::{
    InviterParams, LinkAttestationRequest, LinkDecision, LinkOutcome, LinkProposal,
    serve_link_reply,
};
use tradr_core::{
    BoxFuture, Clock, DeviceId, DisplayName, HalfSecret, Invite, InviteId, KeyStore,
    LinkDeclineReason, LinkReply, LinkSecret, Monotonic, PublicIdentity, PublicKeyPoint, Rng,
    RngError, SendStream, TransportError, UnixTime,
};
use tradr_identity::{AccountId, Link, SoftwareKeyStore, derive_link_id, derive_link_secret};
use tradr_proto::framing::FrameDecoder;
use tradr_proto::link::decode_link_decline_frame;
use tradr_proto::message_type::MessageType;

// ---- Test doubles --------------------------------------------------------

struct SeededRng {
    state: AtomicU64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
        }
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        for slot in buf.iter_mut() {
            let mut x = self.state.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state.store(x, Ordering::Relaxed);
            *slot = (x >> 24) as u8;
        }
        Ok(())
    }
}

struct FakeClock {
    now: UnixTime,
}

impl Clock for FakeClock {
    fn now(&self) -> UnixTime {
        self.now
    }

    fn monotonic_now(&self) -> Monotonic {
        Monotonic::from_instant(Instant::now())
    }
}

// Records every write so a test can read what actually went on the wire,
// and appends to the shared log so ordering against `record` is testable.
struct RecordingSend {
    written: Arc<Mutex<Vec<u8>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl SendStream for RecordingSend {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.written
                .lock()
                .expect("the write log is never poisoned")
                .extend_from_slice(buf);
            self.events
                .lock()
                .expect("the event log is never poisoned")
                .push("wrote");
            Ok(())
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move { Ok(()) })
    }
}

// What the verifier was actually handed, in the order the request declares
// it: the token, the two keys, and the DeviceId the channel authenticated.
type VerifiedArguments = (String, PublicKeyPoint, PublicKeyPoint, DeviceId);

const NOW: i64 = 1_800_000_000;
const MAX_FRAME: u32 = 65536;

fn device(seed: u64) -> SoftwareKeyStore {
    SoftwareKeyStore::generate(&SeededRng::new(seed)).expect("a seeded generate must succeed")
}

fn identity_of(store: &SoftwareKeyStore) -> PublicIdentity {
    store.public_identity().expect("a generated store has one")
}

fn half(byte: u8) -> HalfSecret {
    HalfSecret::from_bytes(&[byte; 16]).expect("16 bytes always fit a HalfSecret")
}

fn invite_id(byte: u8) -> InviteId {
    InviteId::from_bytes(&[byte; 16]).expect("16 bytes always fit an InviteId")
}

fn open_invite(alice: &PublicIdentity, id: InviteId, expires_at: i64) -> Invite {
    Invite::new(
        id,
        alice.identity_pub().clone(),
        alice.agreement_pub().clone(),
        "alice_token".to_string(),
        half(0xa1),
        UnixTime::from_secs(expires_at),
    )
}

fn reply_from(bob: &PublicIdentity, id: InviteId) -> LinkReply {
    LinkReply::new(
        id,
        bob.identity_pub().clone(),
        bob.agreement_pub().clone(),
        "bob_token".to_string(),
        half(0xb2),
    )
}

fn peer_account() -> AccountId {
    AccountId::new("https://accounts.google.com", "9273")
}

// The decline the inviter actually put on the wire, or None when it wrote
// something that is not a LinkDecline frame.
fn decline_on_wire(written: &[u8]) -> Option<(InviteId, Option<LinkDeclineReason>)> {
    let mut decoder = FrameDecoder::new(MAX_FRAME);
    decoder.feed(written);
    let frame = decoder.next_frame().ok()??;
    if frame.type_code() != MessageType::LinkDecline.code() {
        return None;
    }
    let decline = decode_link_decline_frame(&frame).ok()?;
    Some((*decline.invite_id(), decline.reason()))
}

struct Harness {
    written: Arc<Mutex<Vec<u8>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
    send: RecordingSend,
}

fn harness() -> Harness {
    let written = Arc::new(Mutex::new(Vec::new()));
    let events = Arc::new(Mutex::new(Vec::new()));
    Harness {
        written: Arc::clone(&written),
        events: Arc::clone(&events),
        send: RecordingSend { written, events },
    }
}

// ---- Tests ---------------------------------------------------------------

#[tokio::test]
async fn a_reply_naming_another_invite_is_refused_and_nothing_is_written() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let invite = open_invite(&alice, invite_id(0x01), NOW + 300);
    let mut h = harness();

    let verified = Arc::new(Mutex::new(false));
    let verified_flag = Arc::clone(&verified);

    let outcome = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, invite_id(0x02)),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        move |_req: LinkAttestationRequest| async move {
            *verified_flag.lock().expect("not poisoned") = true;
            Ok(peer_account())
        },
        |_p: LinkProposal| async { LinkDecision::Approve },
        |_l: Link, _s: LinkSecret| Ok(()),
    )
    .await;

    assert!(
        outcome.is_err(),
        "a reply naming an invite that is not the open one is refused, not declined"
    );
    assert!(
        h.written.lock().expect("not poisoned").is_empty(),
        "the stream closes without a message; docs/11 says an unknown invite is not a decline reason"
    );
    assert!(
        !*verified.lock().expect("not poisoned"),
        "the invite_id is checked before anything is verified"
    );
}

#[tokio::test]
async fn an_expired_invite_is_declined_with_invite_expired() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW - 1);
    let mut h = harness();

    let outcome = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_p: LinkProposal| async { LinkDecision::Approve },
        |_l: Link, _s: LinkSecret| Ok(()),
    )
    .await
    .expect("an expired invite is a decline, not an error");

    assert!(matches!(
        outcome,
        LinkOutcome::Declined(Some(LinkDeclineReason::InviteExpired))
    ));
    assert_eq!(
        decline_on_wire(&h.written.lock().expect("not poisoned")),
        Some((id, Some(LinkDeclineReason::InviteExpired))),
        "the replier is told the window closed, and told which invite"
    );
}

#[tokio::test]
async fn a_reply_whose_attestation_fails_is_declined_and_never_recorded() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();

    let recorded = Arc::new(Mutex::new(false));
    let recorded_flag = Arc::clone(&recorded);

    let outcome = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async {
            Err("nonce does not bind the peer's keys".to_string())
        },
        |_p: LinkProposal| async { LinkDecision::Approve },
        move |_l: Link, _s: LinkSecret| {
            *recorded_flag.lock().expect("not poisoned") = true;
            Ok(())
        },
    )
    .await
    .expect("a failed verification is a decline, not an error");

    assert!(matches!(
        outcome,
        LinkOutcome::Declined(Some(LinkDeclineReason::VerificationFailed))
    ));
    assert!(
        !*recorded.lock().expect("not poisoned"),
        "a Link is never stored for a reply whose Attestation did not verify"
    );
    assert_eq!(
        decline_on_wire(&h.written.lock().expect("not poisoned")),
        Some((id, Some(LinkDeclineReason::VerificationFailed)))
    );
}

#[tokio::test]
async fn verification_is_asked_about_the_channels_device_id_and_the_replys_own_keys() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    // A third device's id stands in for the channel's, so it is provably
    // not BLAKE3 of the reply's own key. A fixture where the two agree
    // cannot tell the authenticated value from a recomputed one, and the
    // key join is exactly the check that difference decides.
    let channel_peer = identity_of(&device(3)).device_id();
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();

    let seen: Arc<Mutex<Option<VerifiedArguments>>> = Arc::new(Mutex::new(None));
    let seen_slot = Arc::clone(&seen);

    let _ = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: channel_peer,
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        move |req: LinkAttestationRequest| async move {
            *seen_slot.lock().expect("not poisoned") = Some((
                req.token.clone(),
                req.identity_pub.clone(),
                req.agreement_pub.clone(),
                req.authenticated_peer,
            ));
            Ok(peer_account())
        },
        |_p: LinkProposal| async { LinkDecision::Decline },
        |_l: Link, _s: LinkSecret| Ok(()),
    )
    .await
    .expect("a declined proposal is still a completed exchange");

    let (token, identity_pub, agreement_pub, authenticated) = seen
        .lock()
        .expect("not poisoned")
        .clone()
        .expect("verification runs on every reply that names the open, unexpired invite");
    assert_eq!(token, "bob_token", "the token verified is the reply's own");
    assert_eq!(&identity_pub, bob.identity_pub());
    assert_eq!(
        &agreement_pub,
        bob.agreement_pub(),
        "step 3 recomputes the nonce over both keys, so both are handed over"
    );
    assert_eq!(
        authenticated, channel_peer,
        "the key join compares against the DeviceId the channel authenticated, never one off the message"
    );
    assert_ne!(
        authenticated,
        bob.device_id(),
        "the fixture must keep the two apart, or this test cannot tell them apart either"
    );
}

#[tokio::test]
async fn a_user_declined_proposal_writes_that_reason_and_stores_nothing() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();

    let recorded = Arc::new(Mutex::new(false));
    let recorded_flag = Arc::clone(&recorded);

    let outcome = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_p: LinkProposal| async { LinkDecision::Decline },
        move |_l: Link, _s: LinkSecret| {
            *recorded_flag.lock().expect("not poisoned") = true;
            Ok(())
        },
    )
    .await
    .expect("a decline is a completed exchange");

    assert!(matches!(
        outcome,
        LinkOutcome::Declined(Some(LinkDeclineReason::UserDeclined))
    ));
    assert!(!*recorded.lock().expect("not poisoned"));
}

#[tokio::test]
async fn the_proposal_carries_the_link_id_both_sides_derive_from_the_inviters_half_first() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();

    let seen = Arc::new(Mutex::new(None));
    let seen_slot = Arc::clone(&seen);

    let _ = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        move |p: LinkProposal| async move {
            *seen_slot.lock().expect("not poisoned") = Some(p.link_id);
            LinkDecision::Decline
        },
        |_l: Link, _s: LinkSecret| Ok(()),
    )
    .await
    .expect("a decline is a completed exchange");

    let expected = derive_link_id(&derive_link_secret(&half(0xa1), &half(0xb2)));
    assert_eq!(
        seen.lock()
            .expect("not poisoned")
            .expect("a proposal is made"),
        expected,
        "half_A is the inviter's and half_B the replier's, in that fixed order"
    );
}

#[tokio::test]
async fn the_link_is_stored_before_link_approve_is_written() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();
    let events = Arc::clone(&h.events);

    let outcome = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_p: LinkProposal| async { LinkDecision::Approve },
        move |_l: Link, _s: LinkSecret| {
            events.lock().expect("not poisoned").push("stored");
            Ok(())
        },
    )
    .await
    .expect("an approved reply completes");

    assert!(matches!(outcome, LinkOutcome::Linked(_)));
    assert_eq!(
        h.events.lock().expect("not poisoned").as_slice(),
        &["stored", "wrote"],
        "LinkApprove asserts the link exists on this side, so it must not precede the write that makes it exist"
    );
}

#[tokio::test]
async fn a_store_that_fails_declines_with_no_reason_at_all() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();

    let outcome = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_p: LinkProposal| async { LinkDecision::Approve },
        |_l: Link, _s: LinkSecret| Err("the link registry could not be written".to_string()),
    )
    .await
    .expect("a store that fails is a decline, not an error");

    assert!(
        matches!(outcome, LinkOutcome::Declined(None)),
        "none of the three reasons is true of a store failure, and an absent reason is already a value this message defines"
    );
    assert_eq!(
        decline_on_wire(&h.written.lock().expect("not poisoned")),
        Some((id, None))
    );
}

#[tokio::test]
async fn the_stored_link_carries_the_verified_account_and_not_anything_off_the_wire() {
    let alice = identity_of(&device(1));
    let bob = identity_of(&device(2));
    let id = invite_id(0x01);
    let invite = open_invite(&alice, id, NOW + 300);
    let mut h = harness();

    let stored: Arc<Mutex<Option<(AccountId, UnixTime, bool)>>> = Arc::new(Mutex::new(None));
    let stored_slot = Arc::clone(&stored);

    let _ = serve_link_reply(
        &mut h.send,
        InviterParams {
            invite: &invite,
            reply: reply_from(&bob, id)
                .with_display_name(DisplayName::new("Bob").expect("a short ascii name is valid")),
            authenticated_peer: bob.device_id(),
            max_frame_size: MAX_FRAME,
        },
        &FakeClock {
            now: UnixTime::from_secs(NOW),
        },
        |_req: LinkAttestationRequest| async { Ok(peer_account()) },
        |_p: LinkProposal| async { LinkDecision::Approve },
        move |link: Link, secret: LinkSecret| {
            assert_eq!(
                derive_link_id(&secret),
                link.link_id(),
                "the secret handed over must derive the id the record is filed under"
            );
            *stored_slot.lock().expect("not poisoned") = Some((
                link.peer_account().clone(),
                link.created_at(),
                link.fingerprint_verified(),
            ));
            Ok(())
        },
    )
    .await
    .expect("an approved reply completes");

    let (account, created_at, verified) = stored
        .lock()
        .expect("not poisoned")
        .clone()
        .expect("an approved reply stores a Link");
    assert_eq!(
        account,
        peer_account(),
        "the account comes from the verified token's own claims"
    );
    assert_eq!(created_at, UnixTime::from_secs(NOW));
    assert!(
        !verified,
        "nothing in this exchange compares Fingerprints, so the flag it writes is false"
    );
}

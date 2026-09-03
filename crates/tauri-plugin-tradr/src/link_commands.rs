//! The command surface and replier dial for account linking (WI-M6-006f,
//! WI-M6-007a): opening an invite, previewing one pasted from elsewhere,
//! replying, answering parked proposals, and listing or removing a Link,
//! along with the testable core for the replier's side of the exchange.

use std::sync::Arc;

use serde::Serialize;
use tauri::State;

use tradr_core::{
    Candidate, Clock, DeviceId, Invite, LinkDeclineReason, LinkId, LinkSecret, PeerExpectation,
    PeerList, PublicIdentity, Rng, SecretStore, SecureChannel, Transport, UnixTime,
};
use tradr_discovery::{MdnsSource, StaticPeerSource};
use tradr_identity::{Link, LinkRegistry, OsRng, SystemClock, create_invite, device_fingerprint};
use tradr_proto::invite::{invite_from_blob, invite_to_blob};
use tradr_transport::quic::QuicTransport;

use crate::attestation::FUTURE_SKEW_LIMIT_SECS;
use crate::identity::IdentityState;
use crate::link_exchange::{
    LinkAttestationRequest, LinkDecision, LinkExchangeError, LinkOutcome, ReplierParams,
    send_link_reply,
};
use crate::link_invite::{LinkInviteState, LinkProposalDto};
use crate::link_registry::LinkRegistryState;
use crate::peer_trust::{PeerTrust, PeerTrustState};
use crate::sign_in::SignInState;

/// What a person is shown when an invite opens: the blob the QR encodes,
/// and this device's own Fingerprint to read aloud.
#[derive(Debug, Clone, Serialize)]
pub struct LinkInviteDto {
    /// The base64url invite blob, exactly what the QR encodes.
    pub blob: String,
    /// This device's own Fingerprint, as its twelve words.
    pub fingerprint: Vec<String>,
}

/// How the exchange this device started ended, and the inviter's own
/// Fingerprint for the person to read aloud (docs/11: the paste channel
/// makes Fingerprint verification mandatory on both sides).
#[derive(Debug, Clone, Serialize)]
pub struct LinkReplyDto {
    /// True when both sides hold the Link.
    pub linked: bool,
    /// The `LinkId` as lowercase hex, when linked.
    pub link_id: Option<String>,
    /// The reason the inviter gave, when it declined and gave one.
    pub decline_reason: Option<String>,
    /// The inviter's Fingerprint, derived from the invite's own two keys.
    pub peer_fingerprint: Vec<String>,
}

/// What DCR-077's pause shows a person after pasting a blob and before
/// anything is dialled: the inviter's Fingerprint to read aloud, and
/// whether the invite is already expired. Carries no account: naming one
/// needs the Attestation verified against a channel's `DeviceId`, and
/// there is no channel here.
#[derive(Debug, Clone, Serialize)]
pub struct LinkInvitePreviewDto {
    /// The inviter's Fingerprint, as its twelve words.
    pub peer_fingerprint: Vec<String>,
    /// Whether `now` is already past the invite's own expiry plus skew.
    pub expired: bool,
}

/// What the replier's side of the exchange needs beyond the channel.
pub struct ReplierDeps<'a> {
    /// The invite this device is replying to.
    pub invite: &'a Invite,
    /// This device's own public identity.
    pub our_identity: &'a PublicIdentity,
    /// This device's own OIDC provider-signed id token.
    pub our_attestation_token: String,
    /// This device's peer trust engine for verifying the inviter.
    pub trust: Arc<PeerTrust>,
    /// This device's link registry for persisting completed links.
    pub registry: Arc<std::sync::Mutex<LinkRegistry>>,
    /// The secret store used to persist the Link Secret.
    pub secrets: Arc<dyn SecretStore + Send + Sync>,
}

/// Opens a fresh link invite window on this device and returns the encoded blob and fingerprint.
#[tauri::command]
pub fn open_link_invite(
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
    invites: State<'_, Arc<LinkInviteState>>,
) -> Result<LinkInviteDto, String> {
    let identity = identity_state.public_identity()?;
    let token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in on this device before showing an invite".to_string())?;

    let invite = create_invite(
        &OsRng,
        &SystemClock,
        identity.identity_pub().clone(),
        identity.agreement_pub().clone(),
        token,
        None,
    )
    .map_err(|e| e.to_string())?;

    let blob = invite_to_blob(&invite);
    let fingerprint = device_fingerprint(identity.identity_pub(), identity.agreement_pub())
        .words()
        .iter()
        .map(|word| word.to_string())
        .collect();

    invites.open(invite).map_err(|e| e.to_string())?;

    Ok(LinkInviteDto { blob, fingerprint })
}

/// Decodes `blob` and reports the inviter's Fingerprint and whether the
/// invite is already expired as of `now`, allowing `skew_secs` of clock
/// skew. The testable core behind `preview_link_invite` (rule: a
/// `#[tauri::command]`'s body is not reachable from any test).
pub fn invite_preview(
    blob: &str,
    now: UnixTime,
    skew_secs: u64,
) -> Result<LinkInvitePreviewDto, String> {
    let invite = invite_from_blob(blob).map_err(|e| e.to_string())?;
    let peer_fingerprint = device_fingerprint(invite.identity_pub(), invite.agreement_pub())
        .words()
        .iter()
        .map(|word| word.to_string())
        .collect();
    let expired = invite.is_expired(now, skew_secs);
    Ok(LinkInvitePreviewDto {
        peer_fingerprint,
        expired,
    })
}

/// Previews a pasted invite blob before anything is dialled or sent
/// (docs/11, DCR-077): the inviter's Fingerprint to read aloud, and
/// whether the window has already closed. Takes no `State` and touches no
/// window -- nothing here may be opened, stored or sent.
#[tauri::command]
pub fn preview_link_invite(blob: String) -> Result<LinkInvitePreviewDto, String> {
    invite_preview(&blob, SystemClock.now(), FUTURE_SKEW_LIMIT_SECS)
}

/// Resolves an invite's inviter device id to a dialable candidate from the peer list.
pub fn dial_target(invite: &Invite, list: &PeerList) -> Result<(DeviceId, Candidate), String> {
    let inviter_device_id =
        DeviceId::from_identity_digest(blake3::hash(invite.identity_pub().as_bytes()).as_bytes());
    for peer in list.peers() {
        if peer.device_id() == Some(inviter_device_id) {
            let candidate = crate::commands::pick_candidate(&peer, &inviter_device_id.to_string())?;
            return Ok((inviter_device_id, candidate));
        }
    }
    Err(format!(
        "device {inviter_device_id} that showed this invite has not been discovered"
    ))
}

/// Drives the replier's side of the link exchange over an established secure channel.
pub async fn execute_send_link_reply(
    channel: &dyn SecureChannel,
    deps: ReplierDeps<'_>,
    clock: &(dyn Clock + Sync),
    rng: &(dyn Rng + Sync),
) -> Result<LinkOutcome, LinkExchangeError> {
    let (mut send, mut recv) = channel
        .open_bi()
        .await
        .map_err(LinkExchangeError::Transport)?;
    let params = ReplierParams {
        invite: deps.invite,
        our_identity: deps.our_identity,
        our_attestation_token: deps.our_attestation_token,
        our_display_name: None,
        authenticated_peer: channel.peer(),
        max_frame_size: channel.max_frame_size(),
        invite_skew_secs: FUTURE_SKEW_LIMIT_SECS,
    };

    let trust = deps.trust.clone();
    let verify = move |request: LinkAttestationRequest| async move {
        trust
            .verify_link(
                &request.token,
                &request.identity_pub,
                &request.agreement_pub,
                request.authenticated_peer,
                clock,
            )
            .await
    };

    let registry = deps.registry.clone();
    let secrets = deps.secrets.clone();
    let record = move |link: Link, secret: LinkSecret| -> Result<(), String> {
        registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .add(link, &secret, secrets.as_ref())
            .map_err(|e| e.to_string())
    };

    send_link_reply(
        send.as_mut(),
        recv.as_mut(),
        params,
        rng,
        clock,
        verify,
        record,
    )
    .await
}

/// Dials the inviter, sends a link reply, and waits for the inviter's approval or decline.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn reply_to_link_invite(
    blob: String,
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
    peer_trust_state: State<'_, PeerTrustState>,
    link_registry: State<'_, LinkRegistryState>,
    mdns_source: State<'_, tokio::sync::Mutex<MdnsSource>>,
    static_peer_source: State<'_, tokio::sync::Mutex<StaticPeerSource>>,
    peer_list: State<'_, tokio::sync::Mutex<PeerList>>,
    transport: State<'_, Arc<QuicTransport>>,
) -> Result<LinkReplyDto, String> {
    let invite = invite_from_blob(&blob).map_err(|e| e.to_string())?;

    {
        let mut mdns = mdns_source.lock().await;
        let mut static_source = static_peer_source.lock().await;
        let mut list = peer_list.lock().await;
        crate::commands::drain_peer_sources(&mut mdns, &mut static_source, &mut list).await?;
    }

    let (inviter_device_id, candidate) = {
        let list = peer_list.lock().await;
        dial_target(&invite, &list)?
    };

    let channel = transport
        .connect(&candidate, &PeerExpectation::Device(inviter_device_id))
        .await
        .map_err(|e| format!("failed to connect to peer at {}: {e}", candidate.address()))?;

    let our_identity = identity_state.public_identity()?;
    let our_attestation_token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in on this device before replying to an invite".to_string())?;
    let trust = peer_trust_state.peer_trust()?;
    let registry = link_registry.registry()?;
    let secrets = identity_state.secret_store()?;

    let deps = ReplierDeps {
        invite: &invite,
        our_identity: &our_identity,
        our_attestation_token,
        trust,
        registry,
        secrets,
    };

    let outcome = execute_send_link_reply(channel.as_ref(), deps, &SystemClock, &OsRng)
        .await
        .map_err(|e| e.to_string())?;

    let peer_fingerprint = device_fingerprint(invite.identity_pub(), invite.agreement_pub())
        .words()
        .iter()
        .map(|word| word.to_string())
        .collect();

    let (linked, link_id, decline_reason) = match outcome {
        LinkOutcome::Linked(id) => (true, Some(id.to_string()), None),
        LinkOutcome::Declined { reason, .. } => (
            false,
            None,
            reason.and_then(|r| match r {
                LinkDeclineReason::UserDeclined => Some("user-declined".to_string()),
                LinkDeclineReason::InviteExpired => Some("invite-expired".to_string()),
                LinkDeclineReason::VerificationFailed => Some("verification-failed".to_string()),
                _ => None,
            }),
        ),
    };

    Ok(LinkReplyDto {
        linked,
        link_id,
        decline_reason,
        peer_fingerprint,
    })
}

/// Answers the pending link proposal with an approval.
#[tauri::command]
pub fn approve_link(invites: State<'_, Arc<LinkInviteState>>) -> Result<(), String> {
    invites
        .answer(LinkDecision::Approve)
        .map_err(|e| e.to_string())
}

/// Answers the pending link proposal with a decline.
#[tauri::command]
pub fn decline_link(invites: State<'_, Arc<LinkInviteState>>) -> Result<(), String> {
    invites
        .answer(LinkDecision::Decline)
        .map_err(|e| e.to_string())
}

/// The proposal currently parked and waiting on a person, if any. Reads
/// the window and never takes, parks, answers or clears anything -- it
/// exists because `link-proposal` fires exactly once and
/// `EmitProposalSink::announce`'s failure is only logged, so a window that
/// attached its listener late would otherwise never see it.
#[tauri::command]
pub fn pending_link_proposal(invites: State<'_, Arc<LinkInviteState>>) -> Option<LinkProposalDto> {
    invites.pending()
}

/// One Link this device holds, as exposed to the frontend (docs/11,
/// "State after linking"). Carries no `fingerprint_verified`: nothing in
/// this workspace ever writes that field `true`, so listing it would show
/// a permanently-false value (DF-38).
#[derive(Debug, Clone, Serialize)]
pub struct LinkDto {
    /// The `LinkId` as lowercase hex.
    pub link_id: String,
    /// The peer's account issuer.
    pub peer_iss: String,
    /// The peer's account subject.
    pub peer_sub: String,
    /// The label the user gave this peer, if any.
    pub peer_label: Option<String>,
    /// When this Link was created, seconds since the Unix epoch.
    pub created_at: i64,
}

/// Lists every Link this device currently holds.
#[tauri::command]
pub fn list_links(link_registry: State<'_, LinkRegistryState>) -> Result<Vec<LinkDto>, String> {
    let registry = link_registry.registry()?;
    let links = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .links()
        .iter()
        .map(|link| LinkDto {
            link_id: link.link_id().to_string(),
            peer_iss: link.peer_account().iss().to_string(),
            peer_sub: link.peer_account().sub().to_string(),
            peer_label: link.peer_label().map(str::to_string),
            created_at: link.created_at().as_secs(),
        })
        .collect();
    Ok(links)
}

/// Removes the Link carrying `link_id`, discarding its Link Secret from
/// the same rung the Device Key was found on (docs/11, "Removing a
/// link").
#[tauri::command]
pub fn remove_link(
    link_id: String,
    link_registry: State<'_, LinkRegistryState>,
    identity_state: State<'_, IdentityState>,
) -> Result<(), String> {
    let id = link_id
        .parse::<LinkId>()
        .map_err(|e| format!("invalid link id '{link_id}': {e}"))?;
    let secrets = identity_state.secret_store()?;
    let registry = link_registry.registry()?;
    registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&id, secrets.as_ref())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use tradr_core::{PublicKeyPoint, RngError};
    use tradr_identity::device_fingerprint;

    use super::*;

    const NOW: i64 = 1_800_000_000;
    const SKEW_SECS: u64 = 300;

    // Returns bytes from a fixed sequence, mirroring
    // crates/tradr-identity/tests/invite.rs's own `SequenceRng`.
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

    // A fixed clock, so expiry is chosen rather than waited on (rule E3).
    struct FixedClock {
        secs: i64,
    }

    impl Clock for FixedClock {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(self.secs)
        }

        fn monotonic_now(&self) -> tradr_core::Monotonic {
            tradr_core::Monotonic::from_instant(std::time::Instant::now())
        }
    }

    fn draw() -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        bytes
    }

    fn point(first: u8) -> PublicKeyPoint {
        let mut bytes = [0x04u8; 65];
        for (i, byte) in bytes.iter_mut().enumerate().skip(1) {
            *byte = first.wrapping_add(i as u8);
        }
        PublicKeyPoint::from_bytes(&bytes).expect("65 bytes is a point")
    }

    // `create_invite` always sets `expires_at` to `NOW + INVITE_TTL_SECS`
    // (300s), so expiry tests choose `now` relative to that fixed value.
    fn fixed_blob() -> String {
        let rng = SequenceRng::new(draw());
        let clock = FixedClock { secs: NOW };
        let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
            .expect("a working rng and clock must produce an invite");
        invite_to_blob(&invite)
    }

    #[test]
    fn a_well_formed_blob_previews_twelve_words_matching_device_fingerprint() {
        let rng = SequenceRng::new(draw());
        let clock = FixedClock { secs: NOW };
        let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
            .expect("a working rng and clock must produce an invite");
        let blob = invite_to_blob(&invite);

        let preview =
            invite_preview(&blob, UnixTime::from_secs(NOW), SKEW_SECS).expect("a valid blob");

        assert_eq!(preview.peer_fingerprint.len(), 12);
        let expected = device_fingerprint(&point(1), &point(2))
            .words()
            .iter()
            .map(|word| word.to_string())
            .collect::<Vec<_>>();
        assert_eq!(preview.peer_fingerprint, expected);
    }

    #[test]
    fn a_preview_built_from_the_wrong_pair_of_keys_fails() {
        let rng = SequenceRng::new(draw());
        let clock = FixedClock { secs: NOW };
        let invite = create_invite(&rng, &clock, point(1), point(2), "token".to_string(), None)
            .expect("a working rng and clock must produce an invite");
        let blob = invite_to_blob(&invite);

        let preview =
            invite_preview(&blob, UnixTime::from_secs(NOW), SKEW_SECS).expect("a valid blob");

        let wrong = device_fingerprint(&point(9), &point(9))
            .words()
            .iter()
            .map(|word| word.to_string())
            .collect::<Vec<_>>();
        assert_ne!(preview.peer_fingerprint, wrong);
    }

    #[test]
    fn a_now_past_expiry_plus_skew_reads_expired() {
        let blob = fixed_blob();
        // create_invite's own TTL is 300s (INVITE_TTL_SECS); one second
        // past expires_at + skew_secs must read expired.
        let now = UnixTime::from_secs(NOW + 300 + SKEW_SECS as i64 + 1);

        let preview = invite_preview(&blob, now, SKEW_SECS).expect("a valid blob");

        assert!(preview.expired);
    }

    #[test]
    fn a_now_inside_expiry_plus_skew_reads_not_expired() {
        let blob = fixed_blob();
        let now = UnixTime::from_secs(NOW + 300 + SKEW_SECS as i64 - 1);

        let preview = invite_preview(&blob, now, SKEW_SECS).expect("a valid blob");

        assert!(!preview.expired);
    }

    #[test]
    fn a_blob_that_is_not_a_valid_invite_is_rejected() {
        let result = invite_preview(
            "not-a-valid-invite-blob",
            UnixTime::from_secs(NOW),
            SKEW_SECS,
        );

        assert!(result.is_err());
    }
}

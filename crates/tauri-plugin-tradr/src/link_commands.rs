//! The command surface and replier dial for account linking (WI-M6-006f).
//!
//! Exposes four Tauri commands for opening an invite window, replying to an
//! invite, and answering parked proposals, along with the testable core for
//! driving the replier's side of the link exchange.

use std::sync::Arc;

use serde::Serialize;
use tauri::State;

use tradr_core::{
    Candidate, Clock, DeviceId, Invite, LinkDeclineReason, LinkSecret, PeerExpectation, PeerList,
    PublicIdentity, Rng, SecretStore, SecureChannel, Transport,
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
use crate::link_invite::LinkInviteState;
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

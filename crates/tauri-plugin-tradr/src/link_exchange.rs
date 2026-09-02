//! Drives the account-linking exchange over a Control stream that opened
//! with `LinkReply` instead of `Hello` (docs/04-protocol.md, "A Control
//! stream may open with `LinkReply` instead of `Hello`"; docs/11-account-
//! linking.md, "How Bob's reply reaches Alice"). No Trust Tier is
//! computed on it; the wire carries only `LinkReply`, `LinkApprove` and `LinkDecline`.

use std::fmt;
use std::future::Future;

use tradr_core::{
    Clock, DeviceId, DisplayName, Fingerprint, HALF_SECRET_LEN, HalfSecret, Invite, LinkApprove,
    LinkDecline, LinkDeclineReason, LinkId, LinkReply, LinkSecret, PublicIdentity, PublicKeyPoint,
    RecvStream, Rng, RngError, SendStream, TransportError,
};
use tradr_identity::{AccountId, Link, derive_link_id, derive_link_secret, device_fingerprint};
use tradr_proto::framing::{Frame, FrameDecoder, FrameError};
use tradr_proto::link::{
    LinkFrameError, decode_link_approve_frame, decode_link_decline_frame,
    encode_link_approve_frame, encode_link_decline_frame, encode_link_reply_frame,
};
use tradr_proto::message_type::{Classification, MessageType, Plane, classify};

/// Everything `verify` needs to check a peer's Attestation over this
/// stream: docs/05's steps 1 to 5, run against `authenticated_peer` --
/// never a `DeviceId` recomputed from the message (docs/11, "What each
/// side verifies").
pub struct LinkAttestationRequest {
    /// The peer's provider-signed id token, unverified.
    pub token: String,
    /// The identity key the peer's Attestation nonce binds.
    pub identity_pub: PublicKeyPoint,
    /// The agreement key the peer's Attestation nonce binds.
    pub agreement_pub: PublicKeyPoint,
    /// The `DeviceId` the channel itself authenticated.
    pub authenticated_peer: DeviceId,
}

/// What the inviter shows a person before approving or declining a reply
/// (docs/11, "How Bob's reply reaches Alice").
pub struct LinkProposal {
    /// The account `verify` returned for the reply.
    pub peer_account: AccountId,
    /// The replier's Fingerprint, derived from its own two keys.
    pub peer_fingerprint: Fingerprint,
    /// The name the replier published about itself, if any.
    pub peer_label: Option<String>,
    /// The `LinkId` both sides derive from the same two halves.
    pub link_id: LinkId,
}

/// What `decide` answers for a `LinkProposal`.
pub enum LinkDecision {
    /// The user approved the link.
    Approve,
    /// The user declined the link.
    Decline,
}

/// How a link exchange over one stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The exchange completed and both sides hold the Link.
    Linked(LinkId),
    /// The exchange completed with no Link stored on this side.
    Declined(Option<LinkDeclineReason>),
}

/// Everything `serve_link_reply` and `send_link_reply` can fail with, as
/// distinct from `LinkOutcome::Declined`, which is a completed exchange
/// (docs/11). No variant and no `Debug` carries any part of an
/// `id_token`, a `HalfSecret` or a `LinkSecret` (rule F4).
#[derive(Debug)]
pub enum LinkExchangeError {
    /// A `LinkReply`, `LinkApprove` or `LinkDecline` named an invite other
    /// than the one this exchange holds. Refused rather than declined: a
    /// stream naming an unknown invite is not this exchange (docs/11).
    UnknownInvite,
    /// The replier's own clock finds the invite already past its window,
    /// before anything is written.
    InviteExpired,
    /// `verify` rejected the token, carrying its reason.
    VerificationFailed(String),
    /// A `LinkApprove`'s `link_id` did not match the one derived here from
    /// the same two halves.
    LinkIdMismatch,
    /// `record` failed on the replier's side, after a `LinkApprove` had
    /// already asserted the link exists on the inviter's. No wire message
    /// exists to answer a `LinkApprove` with, so this can only be
    /// reported rather than declined.
    RecordFailed(String),
    /// The frame read at this position was not one this stream carries
    /// here -- an unassigned code included, since nothing on this stream
    /// is skippable (docs/04, "Deciding which of the two a stream is").
    ProtocolViolation(String),
    /// Drawing the replier's half secret through `Rng` failed.
    Rng(RngError),
    /// Encoding or decoding a link message failed.
    Frame(LinkFrameError),
    /// A frame's length prefix was malformed or exceeded `max_frame_size`.
    Framing(FrameError),
    /// Transport I/O failed while reading or writing a stream.
    Transport(TransportError),
}

impl fmt::Display for LinkExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownInvite => write!(f, "message names an invite this side is not holding"),
            Self::InviteExpired => write!(f, "invite is past its own expiry window"),
            Self::VerificationFailed(reason) => {
                write!(f, "attestation verification failed: {reason}")
            }
            Self::LinkIdMismatch => write!(f, "link_id does not match the one derived here"),
            Self::RecordFailed(reason) => write!(f, "recording the link failed: {reason}"),
            Self::ProtocolViolation(msg) => write!(f, "protocol violation: {msg}"),
            Self::Rng(e) => write!(f, "rng error: {e}"),
            Self::Frame(e) => write!(f, "link message framing error: {e}"),
            Self::Framing(e) => write!(f, "frame error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for LinkExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rng(e) => Some(e),
            Self::Frame(e) => Some(e),
            Self::Framing(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::UnknownInvite
            | Self::InviteExpired
            | Self::VerificationFailed(_)
            | Self::LinkIdMismatch
            | Self::RecordFailed(_)
            | Self::ProtocolViolation(_) => None,
        }
    }
}

/// Parameters for the inviter's side of the exchange: `serve_link_reply`.
pub struct InviterParams<'a> {
    /// The invite this exchange answers.
    pub invite: &'a Invite,
    /// The replier's `LinkReply`, already read off the stream.
    pub reply: LinkReply,
    /// The `DeviceId` the channel authenticated.
    pub authenticated_peer: DeviceId,
    /// The peer's `max_frame_size`, bounding what this side writes.
    pub max_frame_size: u32,
}

/// Parameters for the replier's side of the exchange: `send_link_reply`.
pub struct ReplierParams<'a> {
    /// The invite this device is replying to.
    pub invite: &'a Invite,
    /// This device's own public identity.
    pub our_identity: &'a PublicIdentity,
    /// This device's own OIDC provider-signed id token.
    pub our_attestation_token: String,
    /// The name this device publishes about itself, if any.
    pub our_display_name: Option<DisplayName>,
    /// The `DeviceId` the channel authenticated.
    pub authenticated_peer: DeviceId,
    /// The peer's `max_frame_size`, bounding what this side writes.
    pub max_frame_size: u32,
    /// The clock skew allowance the caller grants the invite's expiry
    /// check (docs/11: the reader takes its allowance from the caller).
    pub invite_skew_secs: u64,
}

// Writes a `LinkDecline` carrying `reason` and returns the matching
// `Declined` outcome. The one place both a failed verification and an
// expired invite and a user decline converge, so the frame is built and
// sent identically every time.
async fn decline(
    send: &mut dyn SendStream,
    invite: &Invite,
    reason: Option<LinkDeclineReason>,
    max_frame_size: u32,
) -> Result<LinkOutcome, LinkExchangeError> {
    let message = LinkDecline::new(*invite.invite_id(), reason);
    let frame_bytes =
        encode_link_decline_frame(&message, max_frame_size).map_err(LinkExchangeError::Frame)?;
    send.write_all(&frame_bytes)
        .await
        .map_err(LinkExchangeError::Transport)?;
    Ok(LinkOutcome::Declined(reason))
}

/// Serves a `LinkReply` as the inviter (docs/11, "How Bob's reply reaches
/// Alice"). Reads no `RecvStream`: the reply is the only frame the
/// inviter ever reads on this stream, and `listener.rs` already read it
/// to decide this exchange should run at all. Runs docs/11's checks in
/// the fixed order the design gives them.
pub async fn serve_link_reply<V, VFut, D, DFut, R>(
    send: &mut dyn SendStream,
    params: InviterParams<'_>,
    clock: &(dyn Clock + Sync),
    verify: V,
    decide: D,
    record: R,
) -> Result<LinkOutcome, LinkExchangeError>
where
    V: FnOnce(LinkAttestationRequest) -> VFut,
    VFut: Future<Output = Result<AccountId, String>>,
    D: FnOnce(LinkProposal) -> DFut,
    DFut: Future<Output = LinkDecision>,
    R: FnOnce(Link, LinkSecret) -> Result<(), String>,
{
    let invite = params.invite;

    // Step 1: an unknown invite is refused before anything else runs, and
    // nothing is written or verified (docs/11: an unknown invite is not
    // among the decline reasons).
    if params.reply.invite_id() != invite.invite_id() {
        return Err(LinkExchangeError::UnknownInvite);
    }

    // Step 2: the inviter enforces its own window with no skew allowance,
    // since it is both its own clock and its own invite.
    if invite.is_expired(clock.now(), 0) {
        return decline(
            send,
            invite,
            Some(LinkDeclineReason::InviteExpired),
            params.max_frame_size,
        )
        .await;
    }

    // Step 3: verify over the reply's own token and both keys, against the
    // DeviceId the channel authenticated -- never one recomputed from the
    // message.
    let request = LinkAttestationRequest {
        token: params.reply.attestation_token().to_string(),
        identity_pub: params.reply.identity_pub().clone(),
        agreement_pub: params.reply.agreement_pub().clone(),
        authenticated_peer: params.authenticated_peer,
    };
    let peer_account = match verify(request).await {
        Ok(account) => account,
        Err(_) => {
            return decline(
                send,
                invite,
                Some(LinkDeclineReason::VerificationFailed),
                params.max_frame_size,
            )
            .await;
        }
    };

    // Step 4: half_A is the inviter's own half and half_B the replier's,
    // in that fixed order -- never sorted or normalised.
    let secret = derive_link_secret(invite.half_secret(), params.reply.half_secret());
    let link_id = derive_link_id(&secret);

    // Step 5: the proposal carries what a person decides from.
    let peer_label = params
        .reply
        .display_name()
        .map(|name| name.as_str().to_string());
    let proposal = LinkProposal {
        peer_account: peer_account.clone(),
        peer_fingerprint: device_fingerprint(
            params.reply.identity_pub(),
            params.reply.agreement_pub(),
        ),
        peer_label,
        link_id,
    };
    if matches!(decide(proposal).await, LinkDecision::Decline) {
        return decline(
            send,
            invite,
            Some(LinkDeclineReason::UserDeclined),
            params.max_frame_size,
        )
        .await;
    }

    // Step 6: nothing in this exchange compares Fingerprints, so
    // fingerprint_verified is left at its default of false.
    let mut link = Link::new(link_id, peer_account, clock.now());
    if let Some(name) = params.reply.display_name() {
        link = link.with_label(name.as_str());
    }
    if record(link, secret).is_err() {
        return decline(send, invite, None, params.max_frame_size).await;
    }

    // Step 7: only now, so LinkApprove never asserts a link that does not
    // yet exist on this side (docs/11).
    let approve = LinkApprove::new(*invite.invite_id(), link_id);
    let frame_bytes = encode_link_approve_frame(&approve, params.max_frame_size)
        .map_err(LinkExchangeError::Frame)?;
    send.write_all(&frame_bytes)
        .await
        .map_err(LinkExchangeError::Transport)?;
    Ok(LinkOutcome::Linked(link_id))
}

// Reads exactly one frame: the four length bytes, then exactly the
// announced payload, through a decoder built and dropped here -- the same
// technique listener.rs's own `read_frame` uses, so this stream buffers
// nothing past the one frame it reads.
async fn read_one_frame(
    recv: &mut dyn RecvStream,
    max_frame_size: u32,
) -> Result<Frame, LinkExchangeError> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv, &mut len_bytes).await?;
    let announced = u32::from_be_bytes(len_bytes);
    if announced == 0 {
        return Err(LinkExchangeError::Framing(FrameError::Empty));
    }
    if announced > max_frame_size {
        return Err(LinkExchangeError::Framing(FrameError::Oversized {
            announced: announced as u64,
            limit: max_frame_size,
        }));
    }

    let mut raw = vec![0u8; 4 + announced as usize];
    raw[..4].copy_from_slice(&len_bytes);
    read_exact(recv, &mut raw[4..]).await?;

    let mut decoder = FrameDecoder::new(max_frame_size);
    decoder.feed(&raw);
    decoder
        .next_frame()
        .map_err(LinkExchangeError::Framing)?
        .ok_or_else(|| {
            LinkExchangeError::ProtocolViolation("incomplete frame in buffer".to_string())
        })
}

async fn read_exact(
    recv: &mut dyn RecvStream,
    mut buf: &mut [u8],
) -> Result<(), LinkExchangeError> {
    while !buf.is_empty() {
        let n = recv.read(buf).await.map_err(LinkExchangeError::Transport)?;
        if n == 0 {
            return Err(LinkExchangeError::Transport(TransportError::Closed));
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Sends a `LinkReply` as the replier and reads the inviter's answer
/// (docs/11, "How Bob's reply reaches Alice"). Runs docs/11's checks in
/// the fixed order the design gives them.
pub async fn send_link_reply<V, VFut, R>(
    send: &mut dyn SendStream,
    recv: &mut dyn RecvStream,
    params: ReplierParams<'_>,
    rng: &(dyn Rng + Sync),
    clock: &(dyn Clock + Sync),
    verify: V,
    record: R,
) -> Result<LinkOutcome, LinkExchangeError>
where
    V: FnOnce(LinkAttestationRequest) -> VFut,
    VFut: Future<Output = Result<AccountId, String>>,
    R: FnOnce(Link, LinkSecret) -> Result<(), String>,
{
    let invite = params.invite;

    // Step 1: the reader takes its allowance from the caller and bakes in
    // no allowance of its own.
    if invite.is_expired(clock.now(), params.invite_skew_secs) {
        return Err(LinkExchangeError::InviteExpired);
    }

    // Step 2: verify over the invite's own token and both keys.
    let request = LinkAttestationRequest {
        token: invite.attestation_token().to_string(),
        identity_pub: invite.identity_pub().clone(),
        agreement_pub: invite.agreement_pub().clone(),
        authenticated_peer: params.authenticated_peer,
    };
    let peer_account = verify(request)
        .await
        .map_err(LinkExchangeError::VerificationFailed)?;

    // Step 3: our half of the prospective Link Secret.
    let mut half_bytes = [0u8; HALF_SECRET_LEN];
    rng.fill_bytes(&mut half_bytes)
        .map_err(LinkExchangeError::Rng)?;
    let our_half =
        HalfSecret::from_bytes(&half_bytes).expect("HALF_SECRET_LEN bytes always fit a HalfSecret");

    // Step 4: build and send our reply.
    let mut reply = LinkReply::new(
        *invite.invite_id(),
        params.our_identity.identity_pub().clone(),
        params.our_identity.agreement_pub().clone(),
        params.our_attestation_token,
        our_half,
    );
    if let Some(name) = params.our_display_name {
        reply = reply.with_display_name(name);
    }
    let frame_bytes =
        encode_link_reply_frame(&reply, params.max_frame_size).map_err(LinkExchangeError::Frame)?;
    send.write_all(&frame_bytes)
        .await
        .map_err(LinkExchangeError::Transport)?;

    // Step 5: exactly one frame, classified on Control, refusing anything
    // that is not LinkApprove or LinkDecline -- Classification::Ignorable
    // included, since the three linking codes are the only ones this
    // stream carries (docs/04, "Deciding which of the two a stream is").
    let frame = read_one_frame(recv, params.max_frame_size).await?;
    match classify(frame.type_code(), Plane::Control) {
        Classification::Known(MessageType::LinkApprove) => {
            let approve = decode_link_approve_frame(&frame).map_err(LinkExchangeError::Frame)?;
            if approve.invite_id() != invite.invite_id() {
                return Err(LinkExchangeError::UnknownInvite);
            }
            let our_link_id = derive_link_id(&derive_link_secret(invite.half_secret(), &our_half));
            if approve.link_id() != our_link_id {
                return Err(LinkExchangeError::LinkIdMismatch);
            }

            let mut link = Link::new(our_link_id, peer_account, clock.now());
            if let Some(name) = invite.display_name() {
                link = link.with_label(name.as_str());
            }
            let secret = derive_link_secret(invite.half_secret(), &our_half);
            record(link, secret).map_err(LinkExchangeError::RecordFailed)?;
            Ok(LinkOutcome::Linked(our_link_id))
        }
        Classification::Known(MessageType::LinkDecline) => {
            let decline = decode_link_decline_frame(&frame).map_err(LinkExchangeError::Frame)?;
            if decline.invite_id() != invite.invite_id() {
                return Err(LinkExchangeError::UnknownInvite);
            }
            Ok(LinkOutcome::Declined(decline.reason()))
        }
        other => Err(LinkExchangeError::ProtocolViolation(format!(
            "unexpected frame on link stream: {other}"
        ))),
    }
}

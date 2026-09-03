//! The composition root for the account-linking exchange (WI-M6-006e):
//! the invite window a person's device holds open, and the `LinkService`
//! that runs `serve_link_reply` against it. Everything here is reachable
//! from a test; the four Tauri commands that open a window and answer a
//! decision from a person are `WI-M6-006f` (docs/11-account-linking.md).

use std::fmt;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::oneshot;

use tradr_core::{
    BoxFuture, Clock, DeviceId, Invite, InviteId, LinkReply, LinkSecret, SecretStore, SendStream,
};
use tradr_identity::{Link, LinkRegistry};

use crate::link_exchange::{
    InviterParams, LinkDecision, LinkExchangeError, LinkOutcome, LinkProposal, serve_link_reply,
};
use crate::listener::LinkStreamService;
use crate::peer_trust::PeerTrust;

/// What the inviter's device shows a person for one replier, and what
/// `WI-M6-006f`'s command surface serializes to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct LinkProposalDto {
    /// The replier's account issuer.
    pub peer_iss: String,
    /// The replier's account subject.
    pub peer_sub: String,
    /// The replier's Fingerprint, as its twelve words.
    pub peer_fingerprint: Vec<String>,
    /// The name the replier published about itself, if any.
    pub peer_label: Option<String>,
    /// The `LinkId` both sides will derive, as lowercase hex.
    pub link_id: String,
}

fn proposal_dto(proposal: &LinkProposal) -> LinkProposalDto {
    LinkProposalDto {
        peer_iss: proposal.peer_account.iss().to_string(),
        peer_sub: proposal.peer_account.sub().to_string(),
        peer_fingerprint: proposal
            .peer_fingerprint
            .words()
            .iter()
            .map(|word| word.to_string())
            .collect(),
        peer_label: proposal.peer_label.clone(),
        link_id: proposal.link_id.to_string(),
    }
}

/// Announces a `LinkProposal` to a person, on whatever channel this
/// device's frontend listens on. `WI-M6-006f`'s Tauri event is the
/// production implementation; a test double is what the pinned test file
/// answers a decision from.
pub trait ProposalSink: Send + Sync {
    /// Announces `proposal`, or the reason it could not be delivered. An
    /// `Err` here is not a decline: the proposal stays parked and the
    /// exchange keeps waiting on its own deadline.
    fn announce(&self, proposal: &LinkProposalDto) -> Result<(), String>;
}

/// Why `LinkInviteState::open` or `LinkInviteState::answer` refused.
#[derive(Debug)]
pub enum InviteWindowError {
    /// `open` was called while a decision from a person is still parked.
    /// Discarding that decision to show a fresh invite would drop the
    /// exchange it belongs to on the floor mid-read.
    DecisionPending,
    /// `answer` was called with nothing parked, or with a receiver no
    /// exchange is listening on any more.
    NoPendingDecision,
}

impl fmt::Display for InviteWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionPending => {
                write!(
                    f,
                    "a decision from a person is still waiting to be answered"
                )
            }
            Self::NoPendingDecision => write!(f, "no decision is waiting to be answered"),
        }
    }
}

impl std::error::Error for InviteWindowError {}

// The decision a person has not yet answered: the proposal it belongs to,
// beside the one-shot sender `answer` sends on.
struct Parked {
    proposal: LinkProposalDto,
    sender: oneshot::Sender<LinkDecision>,
}

#[derive(Default)]
struct Inner {
    open: Option<Invite>,
    pending: Option<Parked>,
}

/// This device's invite window (docs/11, DCR-076): the invite currently
/// offered, single-use, and the one decision from a person it may be
/// waiting on at a time. One `std::sync::Mutex` over both slots: showing
/// a fresh invite must never discard a proposal someone is still reading,
/// and closing the window on a `LinkReply` must never race anything else.
pub struct LinkInviteState {
    inner: Mutex<Inner>,
}

impl LinkInviteState {
    /// Builds an empty window: nothing open, nothing pending.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    // A poisoned mutex still holds a usable window; recovering it here
    // keeps a panic in one caller from locking every later one out.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Opens `invite`, replacing whatever was open. Refused while a
    /// decision from a person is still parked (docs/11, DCR-076):
    /// answering it, one way or the other, is what frees this window to
    /// be opened again.
    pub fn open(&self, invite: Invite) -> Result<(), InviteWindowError> {
        let mut inner = self.lock();
        if inner.pending.is_some() {
            return Err(InviteWindowError::DecisionPending);
        }
        inner.open = Some(invite);
        Ok(())
    }

    /// The invite currently open, if any.
    pub fn open_invite(&self) -> Option<Invite> {
        self.lock().open.clone()
    }

    /// Takes and closes the window, but only when the invite it holds
    /// carries `id`; leaves it exactly as it was otherwise. A `LinkReply`
    /// is the first frame on a stream with no session, so closing on an
    /// unnamed invite would let a stranger close someone else's window for
    /// one connection (docs/11). Expiry is `serve_link_reply`'s own job.
    pub fn take_if(&self, id: &InviteId) -> Option<Invite> {
        let mut inner = self.lock();
        match &inner.open {
            Some(invite) if invite.invite_id() == id => inner.open.take(),
            _ => None,
        }
    }

    /// Parks `proposal` and a fresh channel for a person's decision on it,
    /// replacing anything parked before -- which `clear_pending` on every
    /// exit of `LinkService::serve` ensures is never a decision still
    /// awaited by a live exchange.
    pub fn park(&self, proposal: LinkProposalDto) -> oneshot::Receiver<LinkDecision> {
        let (sender, receiver) = oneshot::channel();
        self.lock().pending = Some(Parked { proposal, sender });
        receiver
    }

    /// The proposal currently waiting on a person, if any.
    pub fn pending(&self) -> Option<LinkProposalDto> {
        self.lock()
            .pending
            .as_ref()
            .map(|parked| parked.proposal.clone())
    }

    /// Takes the parked decision and sends `decision` on it. The first
    /// answer takes the parked place with it, so a second call finds
    /// nothing to answer rather than being held for whichever exchange
    /// parks next -- which would be a different peer approved by a press
    /// meant for this one.
    pub fn answer(&self, decision: LinkDecision) -> Result<(), InviteWindowError> {
        let sender = self
            .lock()
            .pending
            .take()
            .ok_or(InviteWindowError::NoPendingDecision)?
            .sender;
        sender
            .send(decision)
            .map_err(|_| InviteWindowError::NoPendingDecision)
    }

    /// Drops any parked decision. Called on every exit of
    /// `LinkService::serve`, including its error paths: an exchange that
    /// ended with its deadline firing leaves `decide`'s future cancelled
    /// and nothing sent, and without this the slot it left behind would
    /// refuse every later `open` forever.
    pub fn clear_pending(&self) {
        self.lock().pending = None;
    }
}

impl Default for LinkInviteState {
    fn default() -> Self {
        Self::new()
    }
}

/// The three things `LinkService` needs, each carrying its own build
/// failure rather than a shared one: a device whose Link registry could
/// not load must still classify ordinary connections through `PeerTrust`,
/// so failing all three together would understate what still works.
pub struct LinkServiceParts {
    /// This device's `PeerTrust`, for `verify_link`.
    pub trust: Result<Arc<PeerTrust>, String>,
    /// This device's Link registry, for `LinkRegistry::add`.
    pub registry: Result<Arc<Mutex<LinkRegistry>>, String>,
    /// This device's secret store, for the Link Secret `add` stores.
    pub secrets: Result<Arc<dyn SecretStore + Send + Sync>, String>,
}

/// Runs the inviter's side of the account-linking exchange against this
/// device's invite window (docs/11). Takes no `AppHandle`: a `ProposalSink`
/// is how it reaches a person, which is what keeps it reachable from every
/// test in this workspace (DF-35).
pub struct LinkService {
    invites: Arc<LinkInviteState>,
    parts: LinkServiceParts,
    sink: Arc<dyn ProposalSink>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl LinkService {
    /// Builds a `LinkService` over `invites`, announcing proposals through
    /// `sink` and reading time through `clock`.
    pub fn new(
        invites: Arc<LinkInviteState>,
        parts: LinkServiceParts,
        sink: Arc<dyn ProposalSink>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            invites,
            parts,
            sink,
            clock,
        }
    }
}

impl LinkStreamService for LinkService {
    fn serve<'a>(
        &'a self,
        send: &'a mut dyn SendStream,
        reply: LinkReply,
        authenticated_peer: DeviceId,
        max_frame_size: u32,
    ) -> BoxFuture<'a, Result<LinkOutcome, LinkExchangeError>> {
        Box::pin(async move {
            // Step 0, ahead of docs/11's own numbering: an unrecognised
            // invite id is refused here, before verification or a person
            // is ever reached, and the window belonging to a live exchange
            // is never disturbed by a reply naming a different one.
            let invite = match self.invites.take_if(reply.invite_id()) {
                Some(invite) => invite,
                None => return Err(LinkExchangeError::UnknownInvite),
            };

            let trust = self.parts.trust.clone();
            let clock_for_verify = self.clock.clone();
            let verify = move |request: crate::link_exchange::LinkAttestationRequest| async move {
                let trust = trust?;
                trust
                    .verify_link(
                        &request.token,
                        &request.identity_pub,
                        &request.agreement_pub,
                        request.authenticated_peer,
                        clock_for_verify.as_ref(),
                    )
                    .await
            };

            let invites_for_decide = self.invites.clone();
            let sink = self.sink.clone();
            let decide = move |proposal: LinkProposal| {
                let dto = proposal_dto(&proposal);
                async move {
                    // Parked before announced: an answer may arrive during
                    // the announce call itself, and the window's lock is
                    // never held while it runs.
                    let receiver = invites_for_decide.park(dto.clone());
                    if let Err(e) = sink.announce(&dto) {
                        eprintln!("link proposal announce failed: {e}");
                    }
                    match receiver.await {
                        Ok(decision) => decision,
                        // The only thing that drops a parked sender
                        // unanswered is this device going away, where no
                        // wire is left to write to.
                        Err(_) => LinkDecision::Decline,
                    }
                }
            };

            let registry = self.parts.registry.clone();
            let secrets = self.parts.secrets.clone();
            let record = move |link: Link, secret: LinkSecret| -> Result<(), String> {
                let registry = registry?;
                let secrets = secrets?;
                registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .add(link, &secret, secrets.as_ref())
                    .map_err(|e| e.to_string())
            };

            let outcome = serve_link_reply(
                send,
                InviterParams {
                    invite: &invite,
                    reply,
                    authenticated_peer,
                    max_frame_size,
                },
                self.clock.as_ref(),
                verify,
                decide,
                record,
            )
            .await;

            self.invites.clear_pending();
            outcome
        })
    }
}

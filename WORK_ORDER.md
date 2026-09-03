# Work Order WI-M6-006f — The linking exchange becomes reachable from a person

## Role

You are the **Implementer**. `CLAUDE.md` §3 and §4 bind you exactly.

- **Never edit** `docs/`, `STATE.md`, `RECORD.md`, `CLAUDE.md`, `AGENTS.md`, or this file.
- **Never commit, push, branch, stash, checkout or reset.** Leave the work in the working tree. You may run read-only git commands (`git status`, `git diff`).
- **Never change the design.** If implementation reveals a design problem, **stop and report a Design Change Request** naming the document and the line. Do not work around it.
- **Add nothing beyond the Definition of Done** (rule F3). A helpful extra is a `REVISE`.
- **Every comment in English**, one line for a line comment, five lines at most for a block comment, saying *why* and never *what*. No comment that excuses a shape (`for now`, `workaround`, `unfortunately`, `TODO: refactor`, …). Doc comments on public API only.
- No `unwrap()`/`expect()` where failure is possible (F5). No swallowed errors — no `let _ =`, no empty catch (F6).

## Target

The four Tauri commands that make the account-linking exchange reachable from a person, and the replier's dial. **Everything underneath them already exists, is complete and is tested.** This Work Item is the command surface, the dial, and the registration that permits the commands to be called.

## Design

Read before writing anything:

- `docs/11-account-linking.md` — "How Bob's reply reaches Alice, and what authorises the connection", "What an invite's expiry decides, and what it does not", "The same expiry bounds the wait on a person", "What the window survives, and where the wait on a person is parked", "What each side verifies, and the order the inviter's two acts go in".
- `docs/04-protocol.md` — "A Control stream may open with `LinkReply` instead of `Hello`". **Both bounds on that stream stay the channel's own `max_frame_size` for its whole life**, since no `HelloAck` ever arrives to replace them.

Three sentences from those documents decide this Work Item:

1. **The QR is the pin.** The replier computes `BLAKE3(invite.identity_pub)[0..16]`, finds *that* Device ID in its own Peer List, and dials under `PeerExpectation::Device(that_id)` — **never an expectation read from the Static Peer registry, and never `Unpinned`.**
2. **A Device ID in no observation is "the peer cannot be found", which is a different sentence from a dial that failed.** Two distinct error messages.
3. **The reader's clock-skew allowance comes from the caller.** Pass `crate::attestation::FUTURE_SKEW_LIMIT_SECS`.

## What already exists — use it, do not reimplement it

| Item | Where |
|---|---|
| `create_invite(rng, clock, identity_pub, agreement_pub, attestation_token, display_name)` | `tradr_identity` |
| `invite_to_blob`, `invite_from_blob` | `tradr_proto::invite` |
| `device_fingerprint(identity_pub, agreement_pub) -> Fingerprint`, `Fingerprint::words()` | `tradr_identity`, `tradr_core` |
| `LinkInviteState::{open, open_invite, answer, pending}`, `InviteWindowError` | `crate::link_invite` |
| `send_link_reply`, `ReplierParams`, `LinkAttestationRequest`, `LinkDecision`, `LinkOutcome`, `LinkExchangeError` | `crate::link_exchange` |
| `PeerTrust::verify_link` | `crate::peer_trust` |
| `LinkRegistry::add(link, &secret, secret_store)` | `tradr_identity` |
| `IdentityState::{public_identity, secret_store}` | `crate::identity` |
| `LinkRegistryState::registry`, `PeerTrustState::peer_trust`, `SignInState::id_token` | `crate::link_registry`, `crate::peer_trust`, `crate::sign_in` |
| `drain_peer_sources`, `pick_candidate` | `crate::commands` (private today; see DoD 6) |
| `FUTURE_SKEW_LIMIT_SECS` | `crate::attestation` |

**This device publishes no display name** — `lifecycle.rs` passes `None` to `TxtRecord::new`. So the invite and the reply both carry `None`, and you invent no source for one.

## Definition of Done

### 1. A new module `crates/tauri-plugin-tradr/src/link_commands.rs`

Declared `pub mod link_commands;` in `lib.rs`. The four commands and the one testable core live here. Nothing moves out of `commands.rs`.

### 2. `open_link_invite` — show an invite

```rust
#[tauri::command]
pub fn open_link_invite(
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
    invites: State<'_, Arc<LinkInviteState>>,
) -> Result<LinkInviteDto, String>
```

- Builds the invite with `create_invite(&OsRng, &SystemClock, identity.identity_pub().clone(), identity.agreement_pub().clone(), token, None)`.
- **Opens it in the window before handing the blob back.** A blob handed to a person for an invite this device is not holding is a QR nothing can answer. An `InviteWindowError::DecisionPending` is returned as its `Display` and **no blob is produced**.
- No `id_token` → `Err("sign in on this device before showing an invite")`.
- Returns exactly:

```rust
/// What a person is shown when an invite opens: the blob the QR encodes,
/// and this device's own Fingerprint to read aloud.
#[derive(Debug, Clone, Serialize)]
pub struct LinkInviteDto {
    /// The base64url invite blob, exactly what the QR encodes.
    pub blob: String,
    /// This device's own Fingerprint, as its twelve words.
    pub fingerprint: Vec<String>,
}
```

### 3. `reply_to_link_invite` — answer one

```rust
#[tauri::command]
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
) -> Result<LinkReplyDto, String>
```

In order:

1. `invite_from_blob(&blob)`, its error reported as its `Display`.
2. Drain both peer sources into the peer list (`drain_peer_sources`), the way `download_file` and `list_peer_directory` already do.
3. Resolve the dial target through the helper in DoD 4.
4. `transport.connect(&candidate, &PeerExpectation::Device(inviter_device_id))`, its error reported as **a dial failure naming the address** — a different sentence from "not found".
5. `channel.open_bi()`, then `execute_send_link_reply` (DoD 5).
6. Map the `LinkOutcome` into:

```rust
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
```

`decline_reason` is `"user-declined"`, `"invite-expired"` or `"verification-failed"`, and `None` for a decline that carried no reason. `peer_fingerprint` is filled on **both** outcomes.

### 4. The dial target, and the two sentences it distinguishes

A helper in `link_commands.rs`, public so a test can drive it:

```rust
pub fn dial_target(invite: &Invite, list: &PeerList) -> Result<(DeviceId, Candidate), String>
```

- Computes the inviter's `DeviceId` as `DeviceId::from_identity_digest(blake3::hash(invite.identity_pub().as_bytes()).as_bytes())`.
- Scans `list.peers()` for the peer whose `device_id()` is `Some(that id)` and returns `crate::commands::pick_candidate(&peer, &id.to_string())` beside it.
- **A Device ID no observation carries is its own message**, naming the id, and says the device that showed this invite has not been discovered — never "connection failed".
- It reads no Static Peer registry and produces no `PeerExpectation` of its own; the caller dials under `Device(id)` unconditionally.

### 5. `execute_send_link_reply` — the testable core

```rust
/// What the replier's side of the exchange needs beyond the channel.
pub struct ReplierDeps<'a> {
    pub invite: &'a Invite,
    pub our_identity: &'a PublicIdentity,
    pub our_attestation_token: String,
    pub trust: Arc<PeerTrust>,
    pub registry: Arc<std::sync::Mutex<LinkRegistry>>,
    pub secrets: Arc<dyn SecretStore + Send + Sync>,
}

pub async fn execute_send_link_reply(
    channel: &dyn SecureChannel,
    deps: ReplierDeps<'_>,
    clock: &(dyn Clock + Sync),
    rng: &(dyn Rng + Sync),
) -> Result<LinkOutcome, LinkExchangeError>
```

- Opens the bidirectional stream off `channel` and passes `channel.max_frame_size()` as `ReplierParams::max_frame_size` and `channel.peer()` as `ReplierParams::authenticated_peer`. **`authenticated_peer` is the channel's own value and never one recomputed from the invite.**
- `invite_skew_secs` is `FUTURE_SKEW_LIMIT_SECS`.
- `verify` calls `PeerTrust::verify_link` with the request's four fields and `clock`.
- `record` locks the registry, calls `add(link, &secret, deps.secrets.as_ref())` and maps the error to its `Display`. It must not hold the lock across any `await` — the closure is synchronous, so this is already true; do not make it otherwise.
- A params struct rather than a long argument list: **`execute_send_link_reply` must not carry `#[allow(clippy::too_many_arguments)]`**, because a params struct is available to it and is the better shape.

**Amended after the first dispatch, and the fault was this Work Order's.** The prohibition above originally read "anywhere in this Work Item", and DoD 3 mandates a nine-parameter `#[tauri::command]` in the same breath. **A `#[tauri::command]` cannot group its `State<'_, T>` extractors into a params struct** — Tauri's macro injects each one as its own parameter — so the two instructions could not both be obeyed, and the Implementer correctly stopped rather than picking a side. `reply_to_link_invite` therefore carries `#[allow(clippy::too_many_arguments)]`, which is what `download_file`, `list_peer_directory` and `send_files` already carry for the identical shape. The prohibition stands everywhere a params struct is possible, which is everywhere except a Tauri command.

### 6. `pick_candidate` and `drain_peer_sources` become `pub(crate)`

Those two lines in `commands.rs` are **the only edit that file receives.** Reuse rather than a second copy (DF-27's lesson).

### 7. Registration, in all three places

- `crates/tauri-plugin-tradr/build.rs` — four entries in `COMMANDS`.
- `crates/tauri-plugin-tradr/src/lib.rs` — four entries in `generate_handler!`.
- `apps/tradr/src-tauri/capabilities/default.json` — `tradr:allow-open-link-invite`, `tradr:allow-reply-to-link-invite`, `tradr:allow-approve-link`, `tradr:allow-decline-link`.

`ci/plugin-permissions.sh` refuses any of the three being missed; run it.

### 8. `approve_link` and `decline_link`

```rust
#[tauri::command]
pub fn approve_link(invites: State<'_, Arc<LinkInviteState>>) -> Result<(), String>
#[tauri::command]
pub fn decline_link(invites: State<'_, Arc<LinkInviteState>>) -> Result<(), String>
```

Each calls `LinkInviteState::answer` with `LinkDecision::Approve` / `LinkDecision::Decline` and reports `InviteWindowError` as its `Display`. Nothing else.

### 9. Tests — `crates/tauri-plugin-tradr/tests/link_commands.rs`

Model the fixtures on `crates/tauri-plugin-tradr/tests/link_service.rs` and the mock channel on `crates/tauri-plugin-tradr/tests/link_stream.rs`. Five tests, and **each must genuinely fail when the thing it names is broken — verify that by breaking it and watching that test and no other fail** (rule E1). No `sleep`, no wall-clock wait (E3).

1. **An approve on the wire links, and the secret is stored.** The mock channel's recv yields a `LinkApprove` frame carrying the `link_id` derived from the two halves; assert `LinkOutcome::Linked`, that the registry holds the record, and that the secret store holds it under `link_secret_slot(link_id)`.
2. **A decline on the wire stores nothing.** Assert `LinkOutcome::Declined` with the wire reason, and that the registry and the secret store are both untouched.
3. **An invite already past its window is refused before a byte is written.** Assert `LinkExchangeError::InviteExpired` and that the mock send stream recorded nothing at all.
4. **Verification is asked about the channel's `DeviceId` and never one recomputed from the invite.** The mock channel's `peer()` must be a **third** device's id, distinct from both the inviter's and this device's. Capture what `verify_link` was asked and `assert_eq!` it against the channel's id **and `assert_ne!` it against `BLAKE3(invite.identity_pub)[0..16]`**, so a fixture that later collapses the two fails rather than silently disarming this test.
5. **A Device ID no observation carries is its own sentence.** `dial_target` against an empty `PeerList` returns an error naming the id and reading as "not discovered", distinguishable from a dial failure.

### 10. Gates — all four pass, and you report the output

```
cargo fmt --all -- --check
sh ci/run-all.sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Use the **check** form of `fmt` above; format files you created or edited with `rustfmt --edition 2024 <path>` per file.

**Report the commands' actual output, never an assertion about it.** A gate you did not run is reported as NOT RUN. A claim that a suite passed, made without the output, is a `DISCARD`.

## Constraints

- No new crates and no change to any `Cargo.toml`.
- `crates/tauri-plugin-tradr` is Layer 2/3; the layer rules in `CLAUDE.md` §4-B are unchanged and `ci/layer-deps.sh` enforces them.
- No `SystemTime::now()` and no direct RNG: time is `SystemClock`, randomness is `OsRng`, both already imported in this crate (B6, B7).
- No secret, token, `HalfSecret` or `LinkSecret` in any log line, error message or `Debug` output (F4).

## Prohibitions

- **Do not edit** `link_exchange.rs`, `link_invite.rs`, `listener.rs`, `peer_trust.rs`, `link_registry.rs`, `identity.rs`, `lifecycle.rs`, or anything under `crates/tradr-*`. They are complete for this Work Item.
- **The only edit `commands.rs` receives is DoD 6's two visibility changes.**
- Do not add a fourth `LinkDeclineReason`, a `TrustTier` variant, or any field to a wire message.
- Do not add an `#[allow(...)]` attribute anywhere a params struct would remove the need for one. **The single exception is `reply_to_link_invite`**, for the reason recorded under DoD 5.

## Report back

State, in this order: the files you changed; each Definition of Done item and whether it is met; the verbatim tail of each of the four gate commands; and any Design Change Request you are raising. If something in this Work Order was impossible, say so plainly rather than working around it — the last four Work Items each found a defect in the Supervisor's own instruction, and reporting it is what the review turned on.

# STATE

> **Only the Supervisor edits this file.** Update it after each review, before anything else.
> **`last_commit` is the commit this file was reconciled against, not `HEAD`.** A commit cannot name its own hash inside itself, so whenever the newest commit is the one that edited this file, the field lags it by exactly one and `git log <last_commit>..HEAD` shows that commit. That is correct and expected; **`last_commit == HEAD` is not an invariant and must not be "fixed"**. `ci/state-sync.sh` checks that the hash exists, which is the property that matters.
>**Everything a session needs after it has arrived is in [RECORD.md](RECORD.md)**, its peer at the repository root: the Review record, the Design Changes register, closed milestones, and findings whose repairs have landed. `ci/state-sync.sh` reads both files, so moving a section there does not take it out of any check. **When this file grows past its ceiling, the answer is to move a closed section across, never to shorten one.**
> An arriving Supervisor reads this first, then runs `git log --oneline -20` to see what happened after `last_updated`.
> **Commits newer than `last_updated` mean the first job is reconciling this file.**

```yaml
last_updated: 2026-08-29
phase: implementing
current_milestone: M1
branch: wi-m1-031-graceful-close
implementation_started: true
work_items_landed: 92
last_commit: 8bf1b71
repo_initialized: true (pushed to git@github.com:prokosna/tradr)
```

---

## Where we are

> **Everything below this line is derivable from somewhere else, so it is not written here.** What exists is the Work Item table. How many crates there are is `ls crates/`. Which rules hold is `ci/run-all.sh`. **A prose inventory in this spot has now gone stale four times, the last time while carrying a warning that said it goes stale** -- so the inventory is gone rather than corrected a fifth time, and what remains is the two things nothing else records.

**M1 is under way. Nothing is blocked, and nothing is in flight unless the In flight block below says so.**

**Six Work Items landed on 2026-08-26 and five of them were instruments, not product.** That was not the plan for the session and it is the finding: reading CI for M0's own merge showed `ci/comment-lang.sh` printing `passed` once per file its awk had refused to run, and `ci/state-sync.sh` making `main` permanently red. Pulling that thread found three more of the same shape -- a count that had stopped counting, a scan reading build output, and an install asking a cache whether a binary exists. **Every one of them reported success while measuring nothing**, and none was found by review; all five were found by reading a CI run that nobody had looked at.

**The trust root works, end to end, on a real machine.** On 2026-08-25 the user ran the built desktop app, pressed sign in, and got back an account and `TrustTier::SameAccount`. That tier is the load-bearing part rather than the account name: it comes back only when the `id_token`'s nonce equals `BLAKE3(identity_pub || agreement_pub)` over **this device's** two keys and its `aud` is in the deployment's client set. A device now demonstrably proves which account it belongs to **with no Tradr backend anywhere in the path**. Steps 2 to 16 of that flow had never run before that moment.

**M0's completion criterion is met.** On 2026-08-25 a Linux desktop and a MacBook exchanged Attestations by hand and each verified the other, both returning `SameAccount`. **No Tradr backend is anywhere in that path** -- each device checked the other's `id_token` against Google's published JWKS, checked `aud` against the deployment's client set, and recomputed `BLAKE3(identity_pub || agreement_pub)` over the keys the peer supplied. ADR-0005 and ADR-0010 stopped being design documents.

**The first bulk transport (`direct-quic`) is complete.** `QuicTransport`, `QuicIncoming` and `QuicChannel` wrap `quinn` behind `tradr-core`'s traits with mutual TLS and Device ID verification.

**The single most useful thing to read next is the Review record.** It carries why each Work Item went the way it did, and most of its `REVISE` entries were caused by an error in the Supervisor's own Work Order rather than by the Implementer. That ratio is the main finding of M0 so far, and the `DISCARD` entry is the sharpest instance of it.

## Next three actions

1. **ADR-0004's "To verify", still the user's to start**: LAN throughput against 35 MB/s, on two machines. Unchanged by the audit and displaced by it.
2. (Begin M2 setup or next feature block based on roadmap)

**`ble-gatt`'s data path stood here as action 2 and is displaced rather than dropped**, and ADR-0016 records it as open: 20.5% overhead on a transport docs/03 limits to 20-100 KB/s. It needs settling before the BLE data path is cut, not while it is being written -- and M7 is where that path is cut, so nothing in M1 waits on it.

## In flight

```yaml
work_items: []
blocked: []
```

**The old action 3 stands and is still the user's to start -- ADR-0004's "To verify"**: measure LAN throughput against 35 MB/s, and if it falls short tune GSO, GRO and receive-buffer sizes **before** comparing against TCP. QUIC runs in user space and will not match TCP, so a comparison run before the tuning answers a question nobody asked. **It needs two machines; loopback cannot produce the number.**

**`WI-M1-000f`, the `pre-push` hook, stood here as action 1 and has been moved into the Work Item table rather than dropped.** It is the second of the two rules with no instrument: `.githooks/pre-commit` refuses a *commit* made on `main` and **nothing refuses a push to it**, so `git push origin HEAD:main` from any branch still works, which is the exact motion that put 73 commits there. Branch protection cannot cover it -- see decision 2 below -- so a hook is the only enforcement a private repository can have. It is displaced rather than deprioritised: the transport is what M1 is judged on.

**Every pull request this project has opened is resolved and `main` is green on every job.** #3, #4 and #5 merged, #1 and #2 were closed, and #9 merged on 2026-08-26. The `tauri-cli` defect that made `main` red between the first and the last is fixed and on `main`, which is what the row for `WI-M1-000c` predicted would unblock the rest.

**The transport goes before discovery, and that ordering is now decided.** It was the one thing the session that closed M0 said this file should carry before either was cut. Four reasons, in the order they carry weight:

- **A candidate can be supplied by hand and a transport cannot.** docs/03's Static Peer is an address the user typed, needing no discovery at all, so the QUIC work is provable end to end with `tradr-discovery` still empty. The reverse is not true: mDNS with no transport produces a peer list that leads nowhere and nothing about it can be demonstrated.
- **M1's completion criterion is a file moving and an interrupted transfer resuming.** Both are transport-side. Discovery makes the product pleasant; it is not what the milestone is judged on.
- **The transport is the first thing other than a pasted string to use the trust root M0 finished.** An Attestation verified against a peer that a certificate already authenticated is the join M0 stopped one step short of.
- **And the ordering has already paid for itself.** Cutting the certificate work turned up a design change before a line was written. Under the other order it would have surfaced three Work Items later, with `KeyStore` call sites already written against a trait that cannot sign for TLS.

**The Work Item table for M1 is below.** It is a plan and not a promise; every entry after `WI-M1-004` is likely to be re-cut once the transport exists.

**The three most useful things M0 learned, for whoever cuts M1's first Work Item:**

- **Three Work Orders in a row had the specification as the defect, not the implementation.** All three described the happy path precisely and left the surrounding state unstated. The Definition of Done sections that caught them named **a state to construct** rather than a property to confirm. M1 is networking, where the surrounding state is far wider than M0's: a peer that vanishes, a path that switches, a transfer stopped partway.
- **Choosing evidence that cannot be faked leaves the fakeable part unverified**, and that is where the defect will be.
- **Every rule here with no instrument behind it has been broken at least once**, `main` and rule A5 among them.

## In flight

```yaml
work_items: []
blocked: []
```




**The question `WI-M1-022` left open is closed, and DCR-059 closed it: an offered item a `TransferAccept` does not name is declined.** `TransferAccept::for_offer` was already right not to require an answer per item; what was missing was any statement of what silence meant, so `WI-M1-024`'s listener would have had to invent one. It is now in [docs/04](docs/04-protocol.md#what-reading-a-transferoffer-may-drop-and-what-it-may-not) and `WI-M1-024` inherits it rather than deciding it.

**DCR-059 settled two more things `WI-M1-023` would otherwise have invented**, and both are cases where the wrong answer is the one a reasonable implementation reaches for. `chunk_size` of `0` is refused rather than read as the 1 MiB default -- `control.proto`'s own comment says "1 MiB by default" and proto3 gives an omitted `uint32` a `0`, so the comment actively invites the reinterpretation DCR-058 forbids. And `OfferOrigin` and `RejectReason` became `Option`, `None` for an unspecified or unknown wire value: they decorate, so DCR-058's own rule says they must not refuse, and there was no variant for them to become. **Both were settled before the Work Item was cut**, which is the whole of what section 7's ordering asks for, and DCR-058 was settled the same way before `WI-M1-022`.

**`WI-M1-023`'s two REVISE rounds were caused by its own Work Order and by nothing else.** It told the Implementer it had no shell and to report the gates as NOT RUN, on the strength of a Build environment paragraph that was stale; `agy` runs `cargo` unprompted, as a probe now shows. All three findings -- an unresolved `fmt::Result`, eleven rustfmt violations, three unused imports -- would have been caught by the Implementer had the Work Order not disabled the instrument. **That is the ninth time here that the Work Order was the defect rather than the implementation, and the first where the Supervisor turned off the check that would have prevented it.** The Supervisor also ran `cargo fmt --all` rather than dispatch a third whitespace round, recorded because section 2-3 is the rule it brushes against: running the project's formatter authors no line and decides nothing, where writing the fix would have done both.

## Decisions

**Settled decisions are in [RECORD.md](RECORD.md).** What is here is what is still open.

### Open

| # | Decision | Needed by | Who decides |
|---|---|---|---|
| 6 | Implementer model tier | **After eighteen Work Items: ten REVISE cycles, eight of them caused by my Work Order rather than by the model.** That ratio is the finding. The constraint on throughput is the precision of the instruction, not the capability of the implementer, so a cheaper model saves less than it looks like it should. What `sonnet` has supplied every time is the behaviour a cheap model may not: it stopped and reported when an instruction was impossible rather than working around it, on `@types/node`, on `layer-deps` rule 4, on the workspace-wide gates during a parallel Work Item, and on my own spec file failing my own CI checks. **Gemini 3.7 Flash is now available through `agy`** (see Build environment) and is worth measuring against that behaviour, not against output quality. First trial: the `--locked` CI Work Item, chosen because it is small, mechanical, and cannot fail quietly. **Three Work Items in now -- both halves of `WI-M1-018` and `WI-M1-023` -- and the finding has changed shape.** Design fidelity is not the constraint: `WI-M1-023` implemented every rule DCR-058 and DCR-059 name, correctly, first time, and four mutations in review each failed exactly the test that named them and no other. **The two REVISE rounds it took cost nothing to a model that can run `cargo`** -- a `fmt::Result` that does not resolve, eleven rustfmt violations, three unused imports; none a judgement, all a compiler's or a formatter's opinion. **And `agy` can run `cargo`, which the user pointed out the same day.** The Work Order told it it could not, on the strength of a stale Build environment paragraph, so **both rounds were self-inflicted and neither measures the model.** **What survives as a real observation is one line.** Told it had no shell, it correctly reported the gates as NOT RUN; then, unprompted, its next report claimed "the workspace compiles cleanly and all workspace tests pass", about commands it had just said it could not run. **The claim was false as a report even though the capability existed**, and it is the failure this file records for `ci/comment-lang.sh`. **So decision 6 is still unmeasured**, and the first trial that tests judgement rather than instruction is the next Work Item -- dispatched with the gates in its Definition of Done and nothing suppressing them | Measured per Work Item; settle at M1's end | Supervisor |
| 7 | Distribution channels: Play Store, F-Droid, direct APK, and **whether Linux ships AppImage at all**. AppImage bundling downloads unpinned executables at build time; `deb` and `rpm` do not. See [docs/09](docs/09-roadmap-and-risks.md#risks) R11. Also affects how Android permissions must be justified | M2 | User |
| 8 | Code-signing certificates: Apple Developer Program and Authenticode. Procurement takes weeks | M2 start | User |
| 9 | Whether same-account transfers auto-accept by default | M1 | Decide from how it feels |
| 10 | Whether one device may hold several Google accounts | M6 | User |
| 11 | Transfer history retention, and the default write limit for a writable Share | M3 | Open |
| 16 | **Whether a new transport can be added within Change Drill D10's budget.** **Settled by DCR-042: the budget was wrong, and the capability bit is in it.** Enumerating transports on the wire is deliberate -- a closed set means a peer declares membership rather than naming a transport in a string, so nothing parses an open-ended value -- and bits 7 to 15 are reserved precisely so a new transport has one to take. Naming a reserved value rewrites no existing line, which is why it belongs inside the budget rather than counting against it | Settled 2026-08-26 | Supervisor, settled |
| 18 | **How a transport learns which `DeviceId` it is dialling, and what it is told.** **Settled: option B, an argument to `connect`, carrying a `#[non_exhaustive] PeerExpectation` with three variants** -- `Unpinned`, `Device(DeviceId)`, `Identity(PublicIdentity)`. Three facts killed option A, a field on `Candidate`: a Static Peer's first connection has no `DeviceId` at all, since docs/03 pins it *on* that connection; `Candidate` derives `PartialEq`, `Eq` and `Hash` and is what several discovery sources collapse into one peer, so a per-attempt field would silently make one address two candidates; and mDNS carries an **8-byte fingerprint** of the agreement key where `Noise_IK` needs the whole key, so a candidate could not carry the expectation `ble-gatt` needs even if it wanted to. **Option C dies on `SecureChannel::peer`**, whose doc comment says it cannot fail because authentication has already happened -- C makes that false and completes a handshake with an impostor before anyone compares. **Three variants and not one is the domain's own shape**, not a guess: those are the three states of identity knowledge this design has. A transport needing something that is not identity knowledge, a pairing code say, takes it at construction rather than per connect. DCR-042 settles that a fourth variant would still be within D10 | Settled 2026-08-26 | Supervisor, settled |
| 19 | **What the certificate's subject and issuer carry.** **Settled: a constant, identical on every device**, issuer equal to subject. Putting the `DeviceId` in the common name is the obvious move and it is wrong -- it creates a second place a device's identity appears, and **a verifier reading the wrong one is a defect the most likely test, a device verifying itself, cannot expose**, since both fields would agree. docs/05 says verification asks whether the public key equals the expected Device ID; a constant name is what keeps the SPKI the only place identity lives. Needs a docs commit before WI-M1-002b | Before WI-M1-002b | Supervisor, settled |
| 20 | **What the certificate's validity window says.** **Settled: a fixed past `notBefore` and RFC 5280's `99991231235959Z`, so it never expires and `build_self_signed` needs no `Clock`.** Nothing validates this certificate as a chain -- docs/05: no chain and no CA -- so a window is a field nothing reads, and **a narrow one is a field nothing reads until it silently starts refusing connections.** The Device Key's lifetime is already governed by the Attestation staleness rule in docs/05 step 5, against a different clock; two expiry dates that can disagree is worse than one that is never consulted | Before WI-M1-002b | Supervisor, settled |
| 21 | **Which crates encode and parse the certificate DER.** **Settled: `x509-cert` 0.2 with `der` 0.7**, because the workspace already carries `der` 0.7 through `p256` 0.13 and `x509-cert` 0.3 pairs with `der` 0.8 -- taking the newer one would put two DER parsers in a security path for no gain. `rcgen` was rejected: it does support an external signer, and it brings its own crypto backend, its own time handling and a signature-algorithm registry, which is a large surface to confine inside Change Drill D3's `quic/` budget for a certificate whose whole content is one public key and a constant name | Before WI-M1-002b | Supervisor, settled |
| 22 | **How a test waits for a network handshake, given rule E3.** **Settled: it does not wait, it awaits.** A test drives the future it is testing to completion and consults no clock on the success path -- a passing test finishes the instant the handshake does. The only clock permitted is one `tokio::time::timeout` around the whole test body, whose sole job is to turn a handshake that will never complete into a failure rather than a CI job that hangs forever. **A sleep and an unfinished handshake look identical from outside, which is exactly why the sleep is banned and the bound is not**: the bound never decides that something succeeded. Two supporting rules make the sleep unnecessary rather than merely forbidden -- bind `127.0.0.1:0` and read the assigned port back, never a fixed one, so concurrent tests cannot collide; and construct the listener and read its address **before** spawning the dialling task, so "not listening yet" is impossible by construction. What stays forbidden is what E3 names: a sleep used to make one side ready, and any assertion whose truth depends on how long something took | Before WI-M1-004c | Supervisor, settled |

#### Going public: checked against the repository on 2026-08-28, and it is clear

**The secret-scanning dilemma that stood here is gone, and DCR-028 removed it rather than answering it.** The block that occupied this spot weighed whether GitHub would report a committed `google_oauth_client_secret` to Google, whether a revocation would follow, and whether rclone's `obscure.MustReveal()` trick was defensible. **None of it applies any more**: DCR-028 made the client id and the secret configuration a deployer supplies, `build.rs` reads `TRADR_OAUTH_CLIENT_SECRET` from the environment, and DF-15 purged the value from history on 2026-08-24. It is kept out of this file rather than summarised because a settled question re-read as an open one costs a session.

**Four checks were run rather than reasoned about, and all four are clean:**

- **The real secret appears in no reachable git object.** `git grep -q "$SECRET" $(git rev-list --all)` exits 1, over every commit on every ref. So does a search for `GOCSPX`.
- **The raw downloads were never committed.** `git log --all -- 'client_secret_*.json'` is empty; both files sit in the repository root, gitignored, and `.tradr-deployment.env` beside them holds the live value the same way.
- **No other credential shape is in the tracked tree** -- no AWS key, no GitHub token, no Slack token, no OpenAI key. The two `-----BEGIN PRIVATE KEY-----` hits are `tradr-identity`'s test fixtures, a fixed 2048-bit RSA key whose own comment says it is fixed so the suite is deterministic. It authenticates nothing.
- **The client IDs are public values by design**, and [docs/05](docs/05-security.md#why-step-4-compares-against-a-set) says why every device carries both.

**One thing is missing and it is a prerequisite rather than a risk: there is no `LICENSE` file.** Decision 2 settled Apache-2.0 on 2026-08-22 and nothing ever wrote it down, so publishing today publishes an all-rights-reserved repository that says Apache-2.0 nowhere. **Add the file before flipping visibility**, not after.

**What going public buys is three instruments this file records as having none.** GitHub Actions is free for public repositories, which clears the spending limit blocking CI; branch protection stops answering `403`, which is the only enforcement `main` has ever lacked; and required status checks make the `no checks reported` merge hole impossible. **Three rules, one unexecuted decision.**

#### What WI-M1-003 must build against, checked against rustls 0.23.43 on 2026-08-26

`rustls` 0.23.43 and `quinn` 0.11.11 are already in `Cargo.lock`, so no version decision is open. Four findings, each of which changes what the Work Order has to say:

- **`Signer::sign` is handed RFC 8446's whole `CertificateVerify` buffer and told not to hash it.** Its doc says "message is not hashed; the implementer must hash it using the hash function implicit in `scheme()`", and for `ECDSA_NISTP256_SHA256` the returned signature must be **DER**. `KeyStore::sign` already hashes with SHA-256, and `DomainTag::TlsCertificateVerify`'s `Required(64 spaces || "TLS 1.3, ")` separation accepts exactly the two spellings that buffer can begin with and prepends nothing. **DCR-037 was built for this and fits it without adjustment**; what is left is the same raw `r || s` to DER conversion WI-M1-002b already does.
- **Both verifiers take the certificate as an opaque `CertificateDer` and parse none of it.** `verify_server_cert` is additionally handed a `server_name` and a `now` that this design ignores by construction -- the name because DCR-038 puts identity only in the `SubjectPublicKeyInfo`, the clock because decision 20 makes the validity window unread. **This confirms DCR-039's "no extensions" against the real API** rather than against an expectation of it: nothing in either trait reads `basicConstraints`, `keyUsage` or a subject alternative name.
- **`intermediates` must be required to be empty.** docs/05 says no chain and no CA; a non-empty chain is not merely unvalidated, it is a peer presenting something this design has no rule for.
- **`verify_tls12_signature` must reject.** It is a required method on both traits and this deployment is TLS 1.3 only.

**Two things were checked by running them rather than by reading, and both could have cost a `REDESIGN`.**

- **`rustls::crypto::verify_tls13_signature` runs the peer's certificate through `webpki`**, so DCR-039's "no extensions" is not merely unread by rustls, it has to survive a second parser. It does: `webpki::EndEntityCert::try_from` accepts the 288-byte certificate `build_self_signed` produces, and `verify_signature` under `ECDSA_P256_SHA256` verifies a signature made through `KeyStore::sign` against it. **The certificate WI-M1-002b builds is usable by the crate that will consume it, end to end**, and that was an assumption until it was run.
- **The crypto provider is `ring`, and the lock already decided it.** `tradr-oidc`'s `reqwest` resolves `rustls` with `ring` and no `aws-lc-rs` anywhere in `Cargo.lock`. A `tradr-transport` that declared `rustls = "0.23"` with default features would pull `aws-lc-rs` back in -- a second crypto backend, a C toolchain on every build machine, and the four Android targets to cross-compile it for -- so the dependency must be `default-features = false, features = ["ring", "std"]`. Same shape as decision 21: the workspace already carries one, and taking a second buys nothing.

**The certificate's own self-signature is still not what authenticates anyone**, which is why WI-M1-002b deliberately does not check it: `verify_tls13_signature` against the same `SubjectPublicKeyInfo` is the step that prevents impersonation.

#### What WI-M1-004c must build against, checked by running it on 2026-08-26

**Six questions the Work Order rested on, answered by a loopback QUIC handshake rather than by reading `quinn`'s documentation.** The probe stood two `Endpoint`s up against each other using **this repository's own `tls::client_config` and `tls::server_config`**, unmodified, and it is the first time anything in this project has completed a handshake over a real socket. It ran outside the repository, in a scratch crate; nothing was added to `crates/`.

- **`quinn` accepts both configs as they are built today.** `QuicClientConfig::try_from` and `QuicServerConfig::try_from` both succeed against a TLS-1.3-only `ring` config carrying a dangerous custom verifier, a `SingleCertAndKey` resolver and **no ALPN**. That was the largest single risk in the Work Item: a rejection here would have meant `WI-M1-003`'s two configs could not be reused and the whole shape was wrong.
- **An endpoint bound to `127.0.0.1:0` reports its assigned port through `local_addr()`.** Decision 22's "read the port back, never fix one" is therefore implementable, and the test can construct the listener and read its address **before** spawning the dialler, which is what makes the sleep unnecessary rather than merely forbidden.
- **The mutual handshake completes and the pinning verifier is genuinely in the path** -- the dialler pinned the listener's `DeviceId` and the connection established, reporting an RTT of about 4 ms over loopback.
- **Both sides recover the peer's certificate from `Connection::peer_identity()`**, downcast to `Vec<CertificateDer>`, and `tls::peer_device_id` turns it into the right `DeviceId` in **both** directions. **This is what makes `SecureChannel::peer()` implementable with the infallible signature its doc comment promises**: the certificate is already in hand when the connection object exists, so nothing is deferred to a later failure point.
- **`Connection::rtt()` exists and maps straight onto `SecureChannel::rtt()`**, which docs/03's Phase 5 needs as a live value rather than one fixed at connect time.
- **`max_datagram_size()` reported 1288 bytes and is not `max_frame_size`.** docs/04 negotiates `max_frame_size` in `Hello` at 1 MiB, carried over QUIC *streams*; the datagram figure is a different quantity and a transport that reported it would silently shrink every frame. Worth naming because the two are one autocomplete apart.

**A second run answered the error mapping, and it is DCR-045.** Five more findings, every one of them a place a Work Order written from documentation would have been wrong:

- **`quinn`'s default features pull `aws-lc-rs` back in.** The dependency must be `default-features = false, features = ["runtime-tokio", "rustls-ring"]` -- the same trap, and the same answer, as `rustls` in `WI-M1-003`. A second crypto backend means a C toolchain on every build machine and four Android targets to cross-compile it for.
- **`quinn::RecvStream::read` returns `Result<Option<usize>, ReadError>`, and `Ok(None)` means the peer finished writing.** `tradr_core::RecvStream::read` spells that same event `Ok(0)`. **The two are one keystroke apart and a wrong mapping is silent**: `Ok(None)` mishandled as an error turns every clean end-of-stream into a transfer failure.
- **`quinn::SendStream::finish` is synchronous** and returns `Result<(), ClosedStream>`, while Layer 1's `finish` returns a future. Nothing awaits inside it.
- **A peer closing an established connection is not symmetric.** The reader gets `Ok(None)`, an ordinary end of stream; the writer gets `WriteError::ConnectionLost(ApplicationClosed)`. A mapping that assumed both sides see an error would report a clean close as a failure on one side only.
- **`TransportErrorCode` exposes no "is this crypto" predicate.** `u64::from(code)` against `0x100..=0x1ff` is the test, confirmed by construction: `crypto(31)` is `0x11f` and `crypto(42)` is `0x12a`, while `PROTOCOL_VIOLATION` is `0xa`. `TransportErrorCode::crypto(u8)` builds one, so a test can construct the case without a handshake.

**What no probe can answer, and the Work Items still must.** Whether an `Incoming` built on `Endpoint::accept` fits the `&mut self` the trait declares; and ADR-0004's throughput number, which needs two machines rather than loopback and is therefore the user's to start.

#### What WI-M1-006 must build against, checked against mdns-sd 0.21.0 on 2026-08-27

**`mdns-sd` is in no `Cargo.lock` here**, so this was established by fetching 0.21.0 and reading it, not from memory. Six findings, and four of them change what the Work Order has to say.

- **`flume/async` is on by default**, so no runtime bridge is needed. `ServiceDaemon::browse` returns a `flume::Receiver<ServiceEvent>` re-exported from `mdns-sd`, and 0.21.0's `default = ["async", "logging"]` turns on `flume/async`, which is what gives that receiver `recv_async()`. **`DiscoverySource::next_event` can therefore await it directly**: no `spawn_blocking`, and `tradr-discovery` does not need `tokio` for this. A Work Order that assumed a blocking receiver would have specified a bridge that is not needed and a dependency that is not either.
- **`ServiceEvent` has five variants and is `#[non_exhaustive]`, and only two map to a `DiscoveryEvent`.** `ServiceResolved` becomes `Observed`, `ServiceRemoved` becomes `Lost`, and `SearchStarted`, `ServiceFound` and `SearchStopped` have no counterpart at all. **So `next_event` must loop and await again rather than return**, and the `_` arm that `#[non_exhaustive]` forces must continue that loop too. Returning an error for an event the design simply has no word for would make a source die the first time the daemon says it started searching. This is a filter and not a swallowed error under rule F6, and the Work Order has to say which.
- **The `ObservationKey` is the fullname, and this is now checked rather than assumed.** `ServiceRemoved(ty_domain, fullname)` and `ResolvedService.fullname` carry the same string, so removal and resolution agree on the key without the source keeping a table to translate between them.
- **`ResolvedService.addresses` is a `HashSet<ScopedIp>` and the port is separate**, so one resolution yields several candidates and their iteration order is nondeterministic. **`PeerObservation::new` already sorts and deduplicates**, so WI-M1-005's canonicalisation absorbs this exactly; the source must not sort them itself.
- **The IPv6 trap, and it is the one that would reach production.** `ScopedIp`'s `Display` writes `fe80::1%eth0` with **no brackets**, so the obvious `format!("{addr}:{port}")` produces `fe80::1%eth0:51820` -- ambiguous, unparseable, and **it passes `Candidate::new`**, which rejects only an empty address and a control character by design. The failure would surface inside the QUIC transport at dial time, far from where the string was built. `ScopedIp::to_ip_addr()` composes with `SocketAddr`, whose `Display` does bracket, but it **drops the scope**, and link-local is precisely the case mDNS exists to serve.
- **`ResolvedService::is_valid()` exists** and reports whether a resolution is ready to use. Worth calling rather than reimplementing.

**The question this block left open is now answered, and the premise it was framed on was wrong.** It read that `std`'s `SocketAddr` parser handles no scope at all, so the choice was between `%eth0` and RFC 6874's `%25eth0` and only a dial could settle it. **The parser does handle a scope -- a numeric one** -- and running it settled the question without a dial: `[fe80::1%2]:51820` parses, both named forms are rejected. See DCR-048. **The lesson is not that the guess was wrong but that it was reachable**: an hour was budgeted for a two-machine experiment to answer something a four-line probe answered, because the block asserted what the parser does instead of running it. That is the same failure this file records for `ci/comment-lang.sh` and for the `tauri-cli` cache, one layer up.

### Build environment, Ubuntu 24.04.4 LTS

**Linux desktop: ready.** The user installed the WebKitGTK stack on 2026-08-22 at 22:34. `pkg-config` reports `webkit2gtk-4.1` 2.52.3, `javascriptcoregtk-4.1` 2.52.3, `libsoup-3.0` 3.4.4 and `gtk+-3.0` 3.24.41, and `patchelf` is on the path. `WI-M0-003` is unblocked.

**Android: ready.** The SDK lives at `/home/prokosna/android-sdk` with `build-tools;35.0.0`, `platform-tools` 37.0.1, `platforms;android-35`, `cmdline-tools/latest`, and `ndk/27.3.13750724`. The four Android Rust targets were added on 2026-08-22: `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android`. OpenJDK 25.0.3 is present.

**The Android build needs JDK 21, not the system's JDK 25.** Gradle 8.14.3, which Tauri scaffolds, cannot read Java 25 class files and fails with `Unsupported class file major version 69` — a message that names neither Java nor the version that would work. The Android Gradle Plugin does not support Java 25 either, so raising Gradle is not the fix; a supported JDK is.

The user installed OpenJDK 21 on 2026-08-22, and it lives beside the 25 that remains the default:

```
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
```

**The default `java` on the path is still 25**, so `JAVA_HOME` has to be set explicitly on every Android command rather than relied upon. Confirmed working: `./gradlew --version` reports Gradle 8.14.3 on Launcher JVM 21.0.11.

**CI must pin the same major version.** A runner defaulting to a newer JDK reproduces this failure exactly, and the message it produces names neither Java nor a version that would work.

**An emulator is available.** Installed 2026-08-22: the `emulator` package and `system-images;android-35;google_apis;x86_64`. AVD `tradr-test` boots headless and reaches `sys.boot_completed`, reporting Android 15, API 35, ABI `x86_64`. KVM is present and the user is in the `kvm` group.

```
$ANDROID_HOME/emulator/emulator -avd tradr-test -no-window -no-audio -no-boot-anim \
    -gpu swiftshader_indirect -no-snapshot
```

**An APK for this emulator needs the `x86_64` ABI, not only `arm64-v8a`.** A build restricted to arm64 produces something that cannot be installed here at all.

**The phantom `adb` device is gone as of 2026-08-23, and the note stays because it can return.** A Docker container published `0.0.0.0:5555->5560/tcp`, and `adb` probes 5555 looking for an emulator's adb port; finding a listener that never completed the handshake, it inferred a console port of 5554 and listed `emulator-5554 offline` beside the real device. Any bare `adb` command then failed with `more than one device/emulator`, which does not hint at the cause. The user stopped the container.

**Keep passing `-s emulator-5556` or setting `ANDROID_SERIAL` in every Work Order anyway.** It costs a flag, and republishing that container reproduces the whole thing.

Recognising it if it comes back: a real emulator binds `127.0.0.1` only, never `0.0.0.0`, and holds a **pair** of ports, an even console port and the odd one above it -- the AVD here holds `127.0.0.1:5556` and `127.0.0.1:5557`. `ss -ltnp` run as the developer shows a Docker-published port with **no owning process**, since `docker-proxy` runs as root, which is what made it read as an unidentified listener for a day.

**Check it with `adb kill-server` first, then `adb get-state`.** A running daemon drops the stale entry for a while and picks it up again, so a settled daemon answers correctly while a fresh one fails; `adb devices` alone was enough to mistake it for fixed once already.

**`ANDROID_HOME` and `NDK_HOME` are not exported into a non-interactive shell.** A Work Order that needs them must set them explicitly, or the build fails with a message that does not name the cause:

```
ANDROID_HOME=/home/prokosna/android-sdk
NDK_HOME=/home/prokosna/android-sdk/ndk/27.3.13750724
```

**Rust's stdout and stderr reach logcat under the tag `RustStdoutStderr`.** WI-M0-004b captured Chromium's own `variations_seed_loader.cc` and GL lines under that tag, which proves the redirection is live even though the app prints nothing of its own yet. **There is no `tauri`- or `wry`-tagged output at all**, so `println!` from Rust is the observation channel on Android. WI-M0-005 needs that, since a Kotlin-to-Rust call has no other visible effect.

**The NDK version is a decision: r27.** r28 and r29 are available and 30 is at release candidate, but r27 is the series Tauri 2's Android tooling has been exercised against. Newest-available buys nothing here; if r27 proves too old, moving up is one `sdkmanager` invocation.

**A lesson about checking an environment.** The first check used `dpkg -s` and `pkg-config` and reported the WebKitGTK stack missing, which was true at the time. But `pkg-config` was itself absent in that same check, so every `pkg-config --exists` line in it was meaningless rather than negative — a tool reporting on its own absence. **Probe for the artifact, not for a package manager's opinion of it**: `pkg-config --modversion`, or the `.pc` file on disk, answers the question that matters and cannot answer it wrongly for that reason.

#### A second Implementer is available: `agy`, Gemini 3.7 Flash

`/home/prokosna/.local/bin/agy` v1.1.18 runs a non-interactive agent against Gemini 3.7 Flash, among other models (`agy models` lists them). Verified working on 2026-08-23: it reads and writes files and exits 0.

```
agy --model gemini-3.7-flash-high --add-dir /home/prokosna/dev/trader --print='<work order>'
```

**The prompt must be attached to the flag with `=`.** Splitting them makes `--print` swallow `--model` as its prompt, and the CLI says so rather than failing quietly. Writing files needs no `--dangerously-skip-permissions`; print mode auto-approves.

**This paragraph said shell commands were not auto-approved, and on 2026-08-28 that was wrong at a cost of two REVISE rounds.** It read: a Work Order running `cargo` needs `--dangerously-skip-permissions`, and this session's classifier blocks that invocation. **The classifier does block that flag** -- that half is still true and was re-confirmed. **What was false is the premise it existed to work around**: `agy` runs shell commands without it. A four-line probe settles it and now has -- `--print='run cargo --version'` returned `cargo 1.98.0`, and nothing asked for approval.

**So `agy` can run every gate in its own Work Order, and `WI-M1-023`'s Work Order told it it could not.** **This is the failure this file records for `pkg-config` and for the `tauri-cli` cache, committed by the Supervisor against its own written warning**: the paragraph asserted a capability instead of probing for one, and the assertion outlived whatever made it true. Probe for the artifact, not for a document's opinion of it.

**It runs outside this session, so §3's "the Implementer never commits" is held up by the prompt alone.** A subagent's tool use is visible and subject to the session's permission mode; a plain subprocess is not. **Record `git rev-parse HEAD` before dispatching and compare after.** That detects a violation; it does not prevent one.

#### Toolchain present on the development machine

Checked 2026-08-22: `cargo` and `rustc` 1.98.0, `pnpm` 10.20.0, `node` v24.11.0. **Neither `protoc` nor `buf` is installed as a system binary.**

The registry currently serves **TypeScript 7.0.2** and **Biome 2.5.10** as latest, and both are pinned in `package.json`. TypeScript 7 is a major version ahead of the 5.x era most published guidance describes, so **treat advice about `tsconfig` and compiler behaviour as possibly stale**. It was verified working rather than assumed: `tsc` was fed an unchecked index access and produced `TS2322`, so `noUncheckedIndexedAccess` and the rest of the strict set are genuinely in force.

WI-M0-001c therefore drives code generation without one: `protox`, a pure-Rust protobuf compiler, feeds `prost` on the Rust side, and the npm-distributed `buf` runs `ts-proto` on the TypeScript side. Both arrive through `cargo` and `pnpm`. **No CI step installs a system protobuf compiler**, which is the point — a toolchain the lockfiles do not pin is a reproducibility hole.

`docs/02` names `prost` and `ts-proto` as the generators, and both remain in use. Only how they are invoked is settled here.

#### OAuth client IDs

```
Android : 475695468283-v4q25lmqo6kjova3crhiutnl59jnrckk.apps.googleusercontent.com
Desktop : 475695468283-shsoa7f59bdbta9jlubfs49jonv1m7ng.apps.googleusercontent.com
```

Both are public values and belong in the repository. Attestation verification accepts `aud` from this set, so **every device carries both** — see [docs/05](docs/05-security.md#why-step-4-compares-against-a-set).

The desktop client also has a client secret, which Google's token endpoint requires for Desktop-type clients even under PKCE. It is committed alongside the IDs and overridable at runtime — see [docs/05](docs/05-security.md#oauth-client-configuration) for the handling and for why an override has to be applied to every device of an account at once.

Both raw downloads from Google Cloud Console sit in the repository root as
`client_secret_*.apps.googleusercontent.com.json`. They are gitignored, since the values they carry belong in committed config rather than in Google's file wherever it happened to land.

**Extract them during WI-M0-008** into the OAuth configuration, then delete the downloads. Until that config location exists, the files are the only copy on this machine.

Android-type clients have no secret at all.

#### The consent screen stays in Testing

Publishing to Production requires an authorized domain the developer owns and has verified in Search Console, plus a privacy policy hosted on it. No domain exists yet, and one is not needed before release.

Testing status expires refresh tokens after 7 days, which the 30-day staleness window largely absorbs:

```
day 0     sign in, refresh token issued
day 1-7   Attestation renewed every 24 hours, succeeding
day 7     refresh token expires; renewal stops
          the last Attestation carries iat = day 7
day 37    the 30-day staleness limit is reached, and only now
          does re-authentication become necessary
```

Roughly one re-authentication every five weeks, which is fine for the whole development period. Publish to Production before public release, when a distribution site has to exist anyway.

Test users must be added while in Testing; only they can sign in.

#### Note on Android signing fingerprints

A debug keystore is machine-local, so the SHA-1 a GitHub Actions runner produces differs from the one on a developer machine and OAuth will refuse it. **It did not surface during WI-M0-004**, because that build ran here and `apksigner` confirmed the APK carries the fingerprint below. **It surfaces the first time CI builds an APK**, which is why `WI-M0-004a` exists.

The local development fingerprint, from `~/.android/debug.keystore`, is:

```
9C:95:33:2F:9B:D8:E7:F4:7F:2D:5B:76:3A:4D:68:8C:33:62:3A:1B
```

Register additional SHA-1 values on the same Android OAuth client rather than committing a shared debug keystore. Google Cloud Console permits several fingerprints per client, and keeping keystores out of a public repository removes a route to confusing a debug keystore with a release one. The release keystore's fingerprint joins the same list at M4.

---

## Milestones

From [docs/09-roadmap-and-risks.md](docs/09-roadmap-and-risks.md).

| # | Content | Estimate | Status |
|---|---|---|---|
| **M0** | **Skeleton** — monorepo, Tauri launching on Linux and Android, Google sign-in, key generation, Attestation issue and verify | 2 weeks | **done 2026-08-25** |
| M1 | **LAN transfer**, the most important — mDNS, QUIC, transfer, resumption, drag-and-drop send | 4 weeks | **in progress** |
| M2 | Android integration — share sheet, Sharing Shortcuts, SAF, permissions | 3 weeks | todo |
| M3 | Share browsing — VFS, boundary enforcement, the Browse plane | 3 weeks | todo |
| M4 | Windows and macOS — builds, signing, auto-update, tray | 3 weeks | todo |
| M5 | Static Peers and overlay networks — direct over Tailscale | 1 week | todo |
| M6 | Account linking — QR, Link Secret, Fingerprint | 2 weeks | todo |
| M7 | BLE, the largest estimation risk — advertising and scanning on four platforms, EIDs, Noise over GATT | 4-5 weeks | todo |
| M8 | Brokr — presence, rendezvous, relay, FCM, revocation list | 3 weeks | todo |
| M9 | Finishing — security review, store submission, packaging, i18n | ongoing | todo |

### Current milestone: M1, LAN transfer

**Design**: [docs/03-discovery-and-transport.md](docs/03-discovery-and-transport.md), [docs/04-protocol.md](docs/04-protocol.md)

**Done when**: a file moves between two devices over the LAN and a transfer interrupted partway resumes.

**Nothing has ever moved between two devices.** `Transport`, `SecureChannel` and the stream traits are declared in `tradr-core` and implemented nowhere; `tradr-transport` and `tradr-discovery` hold no implementation at all. The trust root M0 finished is what a transport authenticates against, and that is the whole of what M0 hands over.

**[ADR-0004](docs/adr/0004-quic-as-the-bulk-transport.md) carries a "To verify" that falls due in this milestone and nothing else records**: confirm measured LAN throughput reaches 35 MB/s, and if it does not, tune GSO, GRO and receive buffer sizes **before** re-measuring against TCP. That ordering is the point of it -- QUIC runs in user space and will not match TCP, so a comparison run before the tuning answers a question nobody asked.

**Invariant I1 becomes enforced here**: CI's `no-brokr` job is required from M1, and every Tier 0 and Tier 1 feature must work with no Brokr. [ADR-0005](docs/adr/0005-brokr-is-optional.md) becomes a fiction the first time it does not.

**Two things carry over and are not M1 work.** `WI-M0-015b`, the 41-minute Android job, wants doing before M1's push frequency rises. `WI-M0-017`, the Mac being told a Linux-shaped reason its key is in a file, is small and is the kind of thing that never gets done once a milestone moves on.

#### Work Items

**`work_items_landed` counts these from `WI-M1-000b` onward.** It read 52 while M1 landed work, because Check 2 matched `^| WI-M0-` and nothing else.

| ID | Content | Status | Critical |
|---|---|---|---|
| WI-M1-000 | **Two instruments that do not instrument.** `ci/comment-lang.sh`'s awk was rejected by GNU awk under a UTF-8 locale and the script reported `passed` anyway; `ci/state-sync.sh` Check 5 made `main` permanently red | **done** -- PASS, no REVISE | |
| WI-M1-000b | **Check 2 counted `WI-M0-` rows only**, so `work_items_landed` stopped meaning anything the moment M1 opened, while continuing to agree with itself. Also `comment-lang` scanning `packages/*/dist` | **done** -- PASS, no REVISE | |
| WI-M1-000c | **The tauri-cli install asked a cache whether a binary exists.** `Swatinem/rust-cache` restores `~/.cargo/bin` too, so the dedicated cache step reporting a miss did not mean `cargo-tauri` was absent, and `cargo install` walked into a file already there. Every desktop and Android job failed on a warm cache, which is why the first run of a branch passed and the second did not | **done** -- PASS, no REVISE | |
| WI-M1-000d | **Two findings from tonight with no instrument behind them.** Rule A2 has never covered `ci/*.sh` -- those scripts scan `crates` and `packages` for `.rs` and `.ts` -- and the files have drifted well past five lines, `state-sync`'s Check 3 comment to nine. And Check 4 skips any reference whose **first** path component is missing, so a typo in a top-level name is not merely unchecked, it is invisible: only a wrong path *below* a real directory is ever reported | todo | |

**`WI-M1-000d` needs a decision before it is cut, and it is a Supervisor's.** Extending A2 to `ci/*.sh` is not the mechanical change it looks like: `ci/layer-deps.sh`'s header comment runs fifteen lines and `.githooks/pre-commit`'s twelve, and every one of those lines is why a gate exists rather than what it does. Three answers -- compress them and lose the reasoning, move the reasoning into a README beside the scripts that each header points at, or record that A2 does not govern shell scripts and say why. **The second is the only one that keeps the reasoning findable**, but it puts design rationale in a file an Implementer authors, so the move is the Supervisor's and the check extension is the Work Item. The second finding is confirmed: `ci/state-sync.sh` Check 4 skips any inline reference whose leading component is not a real top-level entry, so a typo in the word crates makes a whole path invisible, while a wrong file name *below* a real directory is reported. A token containing a `/` is a path reference and should have to resolve whatever its first component is; a token without one keeps today's rule, which is what holds `KeyStore` and `_tradr._udp.local` out.
| WI-M1-000f | **The `pre-push` hook, the second of the two rules with no instrument.** `.githooks/pre-commit` refuses a commit made on `main`; nothing refuses `git push origin HEAD:main`, which is the exact motion that put 73 commits there. Branch protection answers `403` on a private repository, so a hook is the only enforcement available until decision 2 is executed | todo | |
| WI-M1-000e | **The instrument behind rule 2-5.** The reporting half cannot be mechanized -- no check reads a reply -- but its precondition can: `STATE.md` being *current*. `ci/state-sync.sh` checks that `last_commit` exists, that the counts agree and that paths resolve, and **nothing checks that the file was updated at all**, so section 5's "a Work Item commit without its `STATE.md` update" is a prohibition with no gate. A Check 6 comparing `last_updated` against the newest commit's date closes it | **done** -- PASS, no REVISE | |
| WI-M1-000g | **Restrict CI triggers to `pull_request` and `workflow_dispatch`.** Remove push-to-main and scheduled cron triggers so CI only runs on pull requests and manual dispatches | **done** -- PASS, no REVISE | |
| WI-M1-000h | **`STATE.md` was 313 KB and 90% of it was never read on arrival.** The Review record was 36% and Design changes 20%, both append-only history growing one long row per Work Item forever; what an arriving Supervisor must read before acting measured 31 KB. **Split rather than shortened**, the answer `WI-M1-000d` reached for the same question about `ci/*.sh` headers: the reasoning moves to [RECORD.md](RECORD.md) where it stays findable. Carries the instruments the split needs -- Checks 2, 3 and 4 following the content across, Check 7's 96 KiB ceiling, and Check 8 gating duplicate DCR numbers | **done** -- PASS after one REVISE, and the finding was the Work Order's own path | |
| WI-M1-001 | **A `DomainTag` names a separation** (DCR-037). `CertificateTbs` and `TlsCertificateVerify` require a prefix the message already carries instead of prepending one, so the QUIC handshake signs through `KeyStore` and ADR-0011's hardware backing survives. Critical Module, Supervisor tests first | **done** -- PASS, no REVISE | Yes |
| WI-M1-002a | **The `DeviceId` derivation moves to Layer 0.** `DeviceId::from_identity_digest`: the caller hashes, because Layer 0 has no hash function and may not acquire one, and Layer 0 owns which bytes count. Cut out of `WI-M1-002` because the QUIC verifier needs the same derivation and `tradr-transport` may not reach `tradr-identity`. Critical Module, Supervisor tests first | **done** -- PASS, no REVISE | Yes |
| WI-M1-002b | **The self-signed certificate**: a DER `TBSCertificate` whose SPKI is the identity public key, signed through `KeyStore` under `CertificateTbs`, and the reverse -- reading a peer's identity point back out. DCR-038 settled its name and validity, DCR-039 the two fields DCR-038 left an encoder to invent. Critical Module, Supervisor tests first | **done** -- PASS after one REVISE, and the finding was the Work Order's | Yes |
| WI-M1-003 | **`rustls` against `KeyStore`**: the external signer, and the certificate verifiers that pin on the peer's SPKI rather than validating a chain. Mutual TLS in both directions. DCR-040 split the two directions, DCR-041 made `KeyStore` shareable. Critical Module, Supervisor tests first | **done** -- PASS after one stop-and-report and one REVISE, both the Work Order's fault | Yes |
| WI-M1-004a | **`PeerExpectation` and the second argument to `Transport::connect`** (DCR-044). Decision 18's type, in Layer 1, with no transport yet in existence to pay for the trait change | **done** -- PASS after one REVISE, and the finding was a docs sentence DCR-044 had introduced hours earlier | |
| WI-M1-004b | **The dialling verifier's unpinned mode.** `client_config` takes a `PeerExpectation` instead of a bare `DeviceId`; `Unpinned` makes it accept a well-formed certificate and report the `DeviceId` it derives, which is what a Static Peer's first connection needs. **A pinning verifier that stops pinning fails nothing else**, so Critical Module, Supervisor tests first | **done** -- PASS after one REVISE, and the finding was a module doc that still stated the old rule | Yes |
| WI-M1-004c | **The `quinn` stream wrappers and the `TransportError` mapping.** `SendStream` and `RecvStream` over `quinn`'s own, and the one place a `quinn` error becomes a `TransportError`. Bottom half of the transport, testable against a loopback pair with no `Transport` in sight. **`tradr-transport` gains `quinn` and `tokio` here**, its first runtime dependency | **done** -- PASS after one REVISE, and the Implementer raised two conflicts rather than working around them. See DF-20 | |
| WI-M1-004d | **`QuicTransport`, `QuicIncoming` and `QuicChannel`**: the three Layer 1 traits composed out of `WI-M1-004c`'s pieces (DF-20). Carries ADR-0004's throughput measurement | **done** -- PASS after one REVISE | |
| WI-M1-005 | **Layer 1's `DiscoverySource`, and the peer list that collapses one `DeviceId` arriving from several sources into one peer holding several candidates.** DCR-046 settled the event model, the observation key, and the source-forgery refusal before a line was written | **done** -- PASS after one REVISE, and three of the four findings were the Work Order's | |
| WI-M1-006a | **The mDNS TXT record codec**, both directions, pure and with no daemon in sight: build the six values docs/03 lists from a device's own facts, and parse a peer's into the fields `PeerObservation` carries. **This is where an untrusted LAN's bytes are first read**, so it is where the hostile cases are tested. DCR-047 pinned `id`'s padding and named the Agreement Key Tag; the caller supplies the tag's 8 bytes already hashed, the way `DeviceId::from_identity_digest` takes a digest | **done** -- PASS after one REVISE, and all three findings were the Work Order's | |
| WI-M1-006b | **`MdnsSource` and the advertiser**, wiring WI-M1-006a's codec to `mdns-sd`'s `ServiceDaemon`. DCR-048 settled the IPv6 scope form before it was cut | **done** -- PASS after one REVISE, and the Implementer corrected the review's own arithmetic | |
| WI-M1-007 | The framing codec, `[u32 len][u8 type][payload]`, bounded by the `max_frame_size` the channel reports. DCR-049 settled which direction that bound governs before it was cut | **done** -- PASS after one REVISE, and two of the three findings came from the sweep | |
| WI-M1-008a | **The message-type registry in code**: `0x00` never valid, a code's plane, and the three refusals DCR-050 separated from the ignore rule. Pure, exhaustively testable over 256 values, and the thing `WI-M1-008b` dispatches on | **done** -- PASS after one REVISE, and neither finding was a missing test | |
| WI-M1-008b | **The exchange's vocabulary in `tradr-core`**: `PeerHello`, `PeerHelloAck`, and version negotiation as a pure function. Layer 0 data with invariants -- a 16-byte nonce, a sane version range -- and no key material anywhere in it, which is why it is not Critical and `008c` is | **done** -- PASS after one REVISE, and the Implementer found the F4 finding itself | |
| WI-M1-008c | **The exchange itself, in `tradr-identity`**: the five checks DCR-051 ordered, the `KeyBinding` and nonce signatures, and the Trust Tier settled from a verification outcome handed in rather than fetched. Critical Module, Supervisor tests first | **done** -- PASS, no REVISE, and the only surviving mutation was the Supervisor's missing test | Yes |
| WI-M1-008d | **The wire conversion in `tradr-proto`**, between `Hello`/`HelloAck` and `008b`'s native types. **Where an untrusted peer's protobuf is first read**, so it is where the hostile cases live: absent fields, wrong-length keys, a nonce that is not 16 bytes. DCR-053 settled the two places the wire and Layer 0 disagree. **Marked Critical when the split was cut and downgraded on inspection** -- see below | **done** -- PASS, no REVISE | |
| WI-M1-008e | **Driving the exchange over a real `SecureChannel`**, with the framing codec between them. **The first time a frame crosses a socket.** Needs `tradr-identity` and `tradr-proto` together, which `ci/layer-deps.sh` reaches only from the composition root | **done** -- PASS, no REVISE | |
| WI-M1-009 | **Chunk resumption.** The module [CLAUDE.md](CLAUDE.md) section 6 says collapses path selection when it is wrong. Critical Module, Supervisor tests first | **done** -- PASS, no REVISE | Yes |
| WI-M1-010 | **The Data plane**: receiver-driven `ChunkRequest` and `ChunkData`, verified against the BLAKE3 root as chunks arrive | **reopened** -- the verification half was never implemented. See F-A; re-cut as `WI-M1-014` | Yes |
| WI-M1-011 | Partial files and progress: the receiver-assigned ordinal, the SQLite mapping, and the `fsync`-then-record ordering | **reopened** -- the deny list and the boundary discipline both diverge from docs/06. See F-B and F-C; re-cut as `WI-M1-015` and `WI-M1-016` | Yes |
| WI-M1-012 | Drag and drop, and a file arriving on the other machine | **reopened** -- a file arrives, and nothing checks that it is the file that was sent. See F-A; re-cut as `WI-M1-014` | |
| WI-M1-013 | **CI's `no-brokr` job**, required from M1 (invariant I1) | **reopened** -- the job cannot fail. See F-D; re-cut as `WI-M1-017` | |
| WI-M1-014a | **`ContentVerifier` in `tradr-core` and `tradr-integrity` behind it.** The trait, and DCR-055's slice verification against a `content_hash` at an absolute offset. Pure: no transport, no filesystem, no wire. Critical Module, Supervisor tests first | **done** -- PASS, no REVISE | Yes |
| WI-M1-014b | **The wire half of DCR-055** -- and the home of the range check `014a`'s trait deliberately cannot make: field 5 reserved in `proto/`, the slice payload in `tradr-proto`, and the three bounds `ChunkDataHeader` never checked -- `chunk_index` below the item's chunk count, `offset_in_chunk` below 1 MiB, `payload_len` no larger than what remains. **Where an untrusted peer's sizes are first read** | **folded into `WI-M1-018`** | Yes |
| WI-M1-014c | **Verify before write, in `receive_file`.** The piece goes to `ContentVerifier` and reaches `write_at` only if it passes; `mark_verified` becomes reachable only from a verification outcome, and `ItemComplete.verified` stops being a constant | **folded into `WI-M1-018`** | Yes |
| WI-M1-015 | **The documented deny list**, patterns and globs, exactly what docs/06 lists and nothing besides -- `.git` served and collapsed rather than refused. Critical Module, Supervisor tests first | **done** -- PASS, no REVISE, and DCR-056 is why | Yes |
| WI-M1-016 | **`openat2` with `RESOLVE_BENEATH` in `PosixVfs`**, so validation and opening are one operation, with the `openat`/`O_NOFOLLOW` descent as the fallback path; plus step 2's Unicode normalization and the `RelPath` rebuild that follows it. **Carries one finding neither F-C nor `WI-M1-015` covered**: `list` swallows three `Err(_)` into `continue`, against rule F6, so an entry that cannot be stat-ed silently vanishes from a listing. Critical Module, Supervisor tests first | **folded into `WI-M1-018`** | Yes |
| WI-M1-018 | **The audit's remaining repairs, as one Work Item** (the user's decision, above). The wire half of DCR-055 and `ChunkDataHeader`'s three bounds; verify-before-write in `receive_file` so a piece reaches `write_at` only through `ContentVerifier`; and `openat2` with `RESOLVE_BENEATH` in `PosixVfs` with the Unicode normalization docs/06 step 2 assigns to it. **Closes F-A and F-C together**, which is the whole of what the audit left open. Critical Module throughout, Supervisor tests first | **done** -- PASS, no REVISE. F-A and F-C both closed | Yes |
| WI-M1-017 | **`ci/no-brokr.sh` rewritten to measure something**: a named Tier 0 and Tier 1 integration test set that fails when it is empty or when a listed test has vanished, run with egress sealed to loopback, and a canary that fails the job when the seal is not in effect | **done** -- PASS after one REVISE, and the finding was the canary's own probe failing open | |
| WI-M1-019 | **The rest of the audit repairs.** A-6: Verify `transfer_id` and `item_id` match the session inside `receive_file_inner`. A-7: Remove duplicated `resolve_collision` logic from `transfer.rs` (Invariant I5 violation). A-8: Restore `MessageType::classify` in `transfer.rs`. A-9: Fix hardcoded ordinal `0` in `partial_file_rel_path`, add `.tradr-partial` to `DENY_PATTERNS` in `posix.rs`, enforce 3-attempt limit in `ItemResumption::missing_chunks`/`next_chunk_request`, remove duplicate request loops in `transfer.rs`, and remove `#![allow(clippy::too_many_arguments)]`. | **done** -- PASS, no REVISE | Yes |
| WI-M1-020 | **Remove `review.txt` from the repository root.** Opened as PR #33 and closed unmerged: the file was taken off `main` by amending `902a60f` into `d1e89ed` instead. Recorded so the number is spent rather than free -- see the reconciliation section above | **withdrawn** -- the work happened, by a route section 5 forbids | |
| WI-M1-021 | **`ItemComplete` back onto the Control stream, and `classify` onto the receiving side.** F-E and F-F: `send_file` and `receive_file` take the Control stream pair alongside the Data pair, `ItemComplete` is written to and read from Control, and the `Refused(WrongPlane)` guard at `transfer.rs:283` is deleted rather than moved. `receive_file_inner` dispatches through `classify(_, Plane::Data)` so `Ignorable` is skipped and the three refusals stay separate. **The deliverable is the negative tests**: a peer that puts `ItemComplete` on the Data stream is refused, and an unassigned Data-plane code is skipped | **done** -- PASS, no REVISE. F-E and F-F both closed | |
| WI-M1-022 | **The Offer exchange's vocabulary in `tradr-core`.** `TransferOffer`, `OfferItem`, `TransferAccept`, `ItemAcceptance`, `TransferReject`, and the two enums `OfferOrigin` and `RejectReason`, as Layer 0 data with invariants and no wire type anywhere in them. The direct mirror of `WI-M1-008b`, which is why it is not Critical and `WI-M1-023` is where the hostile cases go | **done** -- PASS after one REVISE, and the finding was a duplicated public accessor | |
| WI-M1-023 | **The Offer exchange's wire conversion in `tradr-proto`**, between `control.proto`'s five messages and `WI-M1-022`'s native types. **Where an untrusted peer's Offer is first read**, so it is where the hostile cases live: a `relative_path` that escapes, a `content_hash` of the wrong length, a `size` that disagrees with `total_bytes`, an `item_id` repeated. The direct mirror of `WI-M1-008d`. Carries DCR-059's Layer 0 change, `OfferOrigin` and `RejectReason` becoming `Option` | **done** -- PASS after two REVISE, both of them gates the Implementer could not run | DCR-059 |
| WI-M1-024 | **The listener half of the composition root.** A task that accepts a channel from `Incoming`, runs `perform_handshake` on the Control pair, reads a `TransferOffer`, answers with a `TransferAccept` carrying the resume position `ItemResumption` derives from what is already on disk, and drives `receive_file` per Item. **Provable against a hand-driven sender with no UI in existence**, which is why it goes before the sending half | **done** -- PASS after one REVISE, fixing stream polarity and VFS permissions | |
| WI-M1-025 | **The sending half and the command surface.** Dial, offer, send; the Tauri commands `lib.rs` does not yet register; the peer list from `MdnsSource` surfaced to the UI; progress events; and the drag-and-drop target that makes M1's first criterion something a user can perform | **done** -- PASS after one REVISE. Tests pass on local loopback | |
| WI-M1-026 | **The UI surface and M1 completion.** The frontend React code invoking `get_peers` and `send_files`; progress events hooked into the UI; and a drag-and-drop target over the main window | **done** -- PASS. React tests and Rust pass cleanly | |
| WI-M1-027 | **macOS build fix in `PosixVfs`.** `openat2` and `ResolveFlags` conditionally compiled for `target_os = "linux"` with `cfg`, and `rt` feature added to `tokio` to enable `spawn_blocking`. | **done** -- PASS | |
| WI-M1-028 | **macOS CI workflow and `OFlags::PATH` fix.** Replaced `OFlags::PATH` with `resolve_dir_fd` and `statat` to avoid macOS build failures, and added a macOS build job to `.github/workflows/ci.yml`. | **done** -- PASS | |
| WI-M1-029 | **Fix QUIC transport initialization outside tokio runtime.** `quinn::Endpoint::server` fails with "no async runtime found" because Tauri `setup` hook is synchronous. Wrap `QuicTransport::new` in `tauri::async_runtime::block_on` in `lifecycle.rs`. Also modify `QuicTransportError::Io` to wrap `std::io::Error` instead of `ErrorKind` to preserve error messages like "invalid TLS config" or "no async runtime found". | **done** -- PASS | |
| WI-M1-030 | **Filter Docker and virtual bridge interfaces in `mdns-sd`.** A host with Docker/Libvirt creates hundreds of `veth` and `br-` interfaces. `mdns-sd` tries to join the multicast group on all of them, which hits Linux's `igmp_max_memberships` limit (default 20), preventing it from joining the physical LAN interface and receiving external mDNS packets. Add `mdns_sd::IfPredicate` to `ServiceDaemon::new` in `lifecycle.rs` to filter out `veth`, `br-`, `docker`, `vnet`, and `virbr`. | **done** -- PASS | |
| WI-M1-031 | **Graceful stream closure in `listener.rs` and `commands.rs`.** Dropping a `quinn::SendStream` without calling `finish().await` aborts the stream (sends `RESET_STREAM`). This causes the sender to receive a stream reset before it can read the `ItemComplete` message, resulting in `TransferSessionError::StreamClosed` ("stream closed unexpectedly"). Add `control_send.finish().await` before returning in `handle_incoming_channel` and `execute_send_files_with_progress`. | **done** -- PASS | |

**Everything from `WI-M1-005` down is a sketch.** It is here so the shape of the milestone is visible, not because those Work Orders are written.

## Deferred

Things consciously postponed. **These live here, not in TODO comments in the code.**

| # | Content | When | Source |
|---|---|---|---|
| DF-23 | **A skipped frame costs nothing to send and the receiver will skip them forever.** `WI-M1-021` made `Classification::Ignorable` skip and read the next frame, which is what [docs/04](docs/04-protocol.md#what-unknown-message-types-are-ignored-actually-covers) specifies -- and neither side bounds how many times in a row it will do so, so an authenticated peer holds a transfer open indefinitely with `0x24` frames. **This is the design's own rule implemented faithfully, not an implementation liberty**, so bounding it is a Supervisor's decision and not a `REVISE`: docs/04 says what is skipped and is silent on how often. It bites only a peer that already cleared a Trust Tier, which is why it is deferred rather than cut | Before M9's security review | [docs/04](docs/04-protocol.md#what-unknown-message-types-are-ignored-actually-covers) |
| DF-21 | **`QuicTransport` accepts only a candidate that parses as a `SocketAddr`; a DNS name is refused as `Unreachable`.** docs/03's Static Peer names `desktop.tail9f3c.ts.net:51820` as a primary example and says resolution is left to the system resolver, so this is a real gap rather than an oversight. **It does not block M1**, whose completion criterion is a file moving over the LAN: mDNS yields addresses, and a Static Peer with a literal IP works. Resolution needs `tokio::net::lookup_host` and a decision about what a test that resolves a name is allowed to depend on, which is why it is not smuggled into `WI-M1-004d` | Before a Static Peer is usable by name, M2 at the latest | Review of WI-M1-004c |
| DF-22 | **Nothing stops a second `#![allow(...)]` from appearing.** DF-20 is legitimate and recorded, but the only thing that will remove it is a Supervisor remembering to look. `ci/excuse-grep.sh` already greps source for prose that papers over a design problem, and an `allow` attribute is the same act performed in the language rather than in a comment. **An allowlist-backed check over `#[allow]` and `#![allow]` would make DF-20 self-closing**, and every later one visible | After WI-M1-004d closes DF-20 | Review of WI-M1-004c |
| ~~DF-20~~ | **Resolved by WI-M1-004d.** **`crates/tradr-transport/src/quic/mod.rs` carried `#![allow(dead_code)]`.** Removed in `WI-M1-004d` upon implementing `QuicTransport`, `QuicIncoming` and `QuicChannel`, with zero dead-code warnings remaining under `-D warnings` | Done 2026-08-26 | Review of WI-M1-004c |
| DF-19 | **Resolved by WI-M1-000b.** **`ci/comment-lang.sh` scans build output.** Its `find` excludes `node_modules`, `target` and the generated protobuf output under `packages/protocol`, but not `packages/*/dist`, so generated `.d.ts` files are held to a rule about hand-written comments. Harmless today because the generators emit ASCII; it becomes a false failure the first time one does not, and the fix is one more `-not -path` | With the next work in `ci/` | WI-M1-000 |
| DF-1 | Desktop drag-out, pulling a peer's file into a file manager. A download button substitutes | After M9 | [docs/08](docs/08-platform-integration.md) |
| DF-2 | Shell integration: Windows context menu, macOS share menu, Linux `.desktop` | Phase 3 | [docs/08](docs/08-platform-integration.md) |
| DF-3 | Post-quantum migration. Write an ADR once `rustls` X25519MLKEM768 and hybrid Noise are both stable | Undecided | [docs/05](docs/05-security.md) |
| DF-4 | Android 14+ `ChooserAction` custom actions. Sharing Shortcuts suffice for v1 | Undecided | [docs/08](docs/08-platform-integration.md) |
| DF-15 | **Closed. Removed from source by DCR-028, then purged from history on 2026-08-24.** `git filter-branch` over `7e7b97f^..HEAD` rewrote the 13 commits that carried the value, `refs/original` was deleted, the reflog expired and the repository repacked. Verified three ways: `HEAD^{tree}` is byte-identical before and after, so no content changed; the value appears in no reachable object; and 318 tests pass on the rewritten branch. **The commit hashes from `7e7b97f` onward all changed, which `ci/state-sync.sh` caught immediately** by refusing a `last_commit` naming a commit that no longer exists. The desktop client secret in `google.rs` was a placeholder, `DESKTOP_CLIENT_SECRET_PLACEHOLDER_NOT_A_REAL_SECRET`. Nothing before the token exchange needs the real value, so WI-M0-008a landed without it. The value sits in `client_secret_475695468283-shsoa7f59bdbta9jlubfs49jonv1m7ng.apps.googleusercontent.com.json` in the repository root, gitignored, **and that file is the only copy on this machine** -- it is also re-downloadable from the Google Cloud Console. Decision 12 settled that it is committed rather than kept out. **A permission classifier refused the command that would have copied it into source**, which is the right refusal and was left standing rather than worked around | With WI-M0-008c | WI-M0-008a |
| DF-16 | **`ProviderProfile` still has no `renewal` field**, the last one docs/05's table lists. It carries real weight -- docs/05's 24-hour silent renewal assumes a refresh token and a `prompt=none` path, and a provider offering neither changes that account's whole revocation story. Left out of WI-M0-008a deliberately rather than landing unused (rule F3), since nothing reads it until renewal exists | With the silent-renewal work | WI-M0-008a, DCR-027 |
| DF-14 | **`Jwk.algorithm` is compared but the comparison is unreachable.** `SignatureAlgorithm` has one variant, so `key.algorithm != algorithm` is always false and the branch survives its own mutation. It is there because a JWKS entry publishes what a key is *for*, and RS256 and PS256 can share one RSA modulus, so nothing but that field would stop a key published for one being used for the other. **It becomes testable the day a second algorithm lands, and a test must arrive with it.** Recorded rather than covered by a test that would only appear to exercise it | With the second `SignatureAlgorithm` | WI-M0-011b |
| DF-13 | **`VerifiedClaims` names its contract but does not enforce it.** WI-M0-011's Work Order claimed "a caller cannot build one without having gone through step 2", and **that is false as built**: the fields are public, so anything can construct one. The Implementer said as much. Enforcing it means private fields with a `pub(crate)` constructor, which the 22 tests cannot use from `tests/`; the fix is to move them to unit tests inside the module when WI-M0-011b puts the real constructor in the same crate | With WI-M0-011b | WI-M0-011 |
| DF-12 | **A candidate address may carry a bidirectional override; a `RelPath` may not.** DCR-013 rejects `U+202A`-`U+202E` and the isolates in a filename, because a name is shown at an accept-or-decline prompt and `report\u{202E}fdp.exe` renders as `reportexe.pdf`. DCR-017 gives a candidate address only the `item_id` rules, empty and control characters, so `\u{202E}evil.example:443` is accepted — confirmed by probe. The asymmetry is deliberate today: path selection is automatic and no user approves a candidate, so there is no prompt to spoof. **It stops being deliberate the moment the UI shows a peer's address**, which device details plausibly will | When the UI displays a peer address, M4 at the latest | WI-M0-006g |
| DF-11 | **Two `Vfs` contracts are stated but not tested.** `open_write` creates if absent and **never truncates** — a truncating implementation silently destroys everything a resumed transfer already received. `remove` takes a file or an already-empty directory and **never recurses** — a `RelPath` is peer-influenced, and recursion on the far end of one is more power than any caller needs. Both are contracts on implementations that do not exist yet, so M3's `tradr-vfs` Work Order carries the tests. **Both are Critical Module adjacent**, so the Supervisor writes those tests first | M3, with `tradr-vfs` | WI-M0-006f |
| DF-10 | **A colon in a component opens an NTFS alternate data stream.** `RelPath` rejects `C:` only in the drive position, because rejecting `:` outright would make ordinary Linux filenames such as `2026-08-22T10:00:00.log` unbrowsable — a cost on every platform to defend one. The Windows `Vfs` must handle it the way docs/04 handles reserved names, by transforming rather than rejecting | Before M4's Windows build | WI-M0-006d |
| DF-18 | **`ci/state-sync.sh`'s branch check cannot run in CI.** `actions/checkout` checks out a commit SHA for both push and pull request, leaving a detached HEAD, and WI-M0-013b's check deliberately skips there -- a runner has no branch to compare. The rule it guards, [CLAUDE.md](CLAUDE.md) section 5's "never commit directly to `main`", was broken for 73 commits before anyone noticed, so leaving it enforced only by a Supervisor who remembers to run `ci/run-all.sh` is the situation that produced the incident. **The instrument that fits is a pre-push hook or a GitHub branch protection rule, not a job**, since both act where the branch still exists | Before the next milestone opens | WI-M0-015 |
| DF-17 | **`serve_one_callback` still cannot bound its own `accept()`.** WI-M0-014b bounds the wait from the composition root, by timing out and then connecting to its own port to wake the parked call. That works and was measured, but the bound lives at the call site rather than in the function whose contract it is, so every future caller has to know to build it again. Moving it inside means changing a Critical Module with 22 Supervisor-written tests, which needs its tests written first | With the next work touching `tradr-oidc` | WI-M0-014b |
| DF-9 | **`KeyStore` is synchronous and two of its operations block.** An Android Keystore `sign` is an IPC to `keystore2`, and `agree` runs once per Noise connection; both occupy a runtime worker for milliseconds. [ADR-0013](docs/adr/0013-layer-1-async-traits-return-boxed-futures.md) left `KeyStore` sync rather than reopening [ADR-0011](docs/adr/0011-keystore-exposes-operations.md) with no implementation to measure against. Resolving it means either `BoxFuture` on `KeyStore` too, or `spawn_blocking` at every Layer 3 call site | Before M1's Noise work | ADR-0013 |
| DF-7 | **`SharedSecret` is not zeroized on drop.** It cannot be, in `tradr-core`: `zeroize` is a dependency the crate may not have, and a hand-written `Drop` needs `write_volatile`, which needs `unsafe`, which `#![forbid(unsafe_code)]` rules out. An ECDH secret therefore lingers in freed memory until overwritten. Resolving it means either letting a Layer 3 type own the zeroizing and having `KeyStore::agree` return something it implements, or accepting the exposure and saying so | Before M1's Noise work | WI-M0-006c |
| DF-6 | `useExactTypes=false` in `buf.gen.yaml`. ts-proto's `Exact<DeepPartial<T>, I>` signature does not resolve under TypeScript 7.0.2, so `fromPartial` and `create` lose excess-property checking. Revisit when ts-proto supports TypeScript 7 | Undecided | WI-M0-001c |
| DF-8 | **The Android WebView renders under the status bar.** The `<h1>` in WI-M0-004b's screenshot sits on top of the system clock: no `viewport-fit=cover`, no `env(safe-area-inset-*)`, no edge-to-edge handling anywhere. Harmless at one heading and wrong for every screen after it | Before M2's Android integration | WI-M0-004b |
| ~~DF-5~~ | ~~TypeScript packages have no build step~~ — **resolved by WI-M0-001d.** Packages emit declarations and JavaScript into `dist/`, and `main` and `types` point there | Done 2026-08-22 | WI-M0-001b |

---

## Risk status

From [docs/09](docs/09-roadmap-and-risks.md). Update as implementation proceeds.

| # | Risk | Likelihood | Status |
|---|---|---|---|
| R1 | BLE peripheral role means four separate implementations | High | Not started. M7's first week goes to connectivity checks |
| R2 | Tauri 2's Android maturity | **Low** | **Two of three conditions met, and the third is the only one left.** WI-M0-004 built a correctly signed APK with all four ABIs and WI-M0-004b ran it; WI-M0-005 proved both call directions and WI-M0-005b proved `ACTION_SEND` on both launch paths, the two conditions most likely to have failed. **Only condition one remains, and it is not about capability**: the build works here, and "reliably" is what CI measures, so it stays unchecked until CI has run it |
| R8 | Brokr-free operation breaks as features are added | High | Make CI's `no-brokr` job required from M1 |
| R9 | macOS and Windows signing procurement takes weeks | Medium | Needs starting before M4. Re-check at the start of M2 |
| R11 | The AppImage bundler downloads unpinned executables at build time | Medium | **Observed at M0.** Five artifacts fetched with no hash pinning; `deb` and `rpm` need none. Folded into open decision 7 — either drop AppImage or vendor and pin, before M2 |

R9 has a procurement lead time, so it cannot wait for M4. Revisit when M2 begins.

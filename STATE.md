# STATE

> **Only the Supervisor edits this file.** Update it after each review, before anything else.
> **Everything a session needs after it has arrived is in [RECORD.md](RECORD.md)**, its peer at the repository root: the Review record, the Design Changes register, closed milestones, and findings whose repairs have landed. `ci/state-sync.sh` reads both files, so moving a section there does not take it out of any check. **When this file grows past its ceiling, the answer is to move a closed section across, never to shorten one.**
> An arriving Supervisor reads this first, then runs `git log --oneline -20` to see what happened after `last_updated`.
> **Commits newer than `last_updated` mean the first job is reconciling this file.** `branch`, `work_items_landed`, and `last_commit` are no longer declared here — see [docs/10](docs/10-implementation-process.md#the-yaml-header--what-is-in-it-and-what-was-removed-dcr-060) for the one-command equivalents.

```yaml
last_updated: 2026-09-02
phase: implementing
current_milestone: M6
implementation_started: true
repo_initialized: true (pushed to git@github.com:prokosna/tradr)
```

---

## Where we are

> **Everything below this line is derivable from somewhere else, so it is not written here.** What exists is the Work Item table. How many crates there are is `ls crates/`. Which rules hold is `ci/run-all.sh`. **A prose inventory in this spot has now gone stale four times, the last time while carrying a warning that said it goes stale** -- so the inventory is gone rather than corrected a fifth time, and what remains is the two things nothing else records.

**M5's completion criterion is met.** On 2026-08-31 a file went from a Windows machine to a MacBook through a Static Peer entry naming the MacBook's MagicDNS name, over a tailnet, **with the MacBook on phone tethering so the two were on different networks and mDNS could see nothing at all**. That configuration is what makes it worth recording: no LAN candidate could have substituted for the tailnet one, which is the substitution that would have made the result vacuous. A MagicDNS name does not parse as a `SocketAddr`, so DCR-062's resolver ran; MagicDNS answers with an `fd7a::` AAAA beside the `100.x` A and the endpoint binds `0.0.0.0`, so **DCR-062's family filter chose the address, against a real answer for the first time** -- that rule had only ever been exercised against a probe. Trust on first use ran the whole way: dialled under `Unpinned`, authenticated, pinned, re-reported, merged.

**M3's completion criterion is met.** On 2026-08-30, a device browsed files exposed by a peer's configured Share and successfully downloaded a file over the Browse plane.

**M2's completion criterion is met.** On 2026-08-30, the user chose a photo in the Android gallery and successfully delivered it to a PC via Tradr's share sheet integration.

**M1's completion criterion is met.** A file moved between two devices over the LAN and an interrupted transfer resumed (WI-M1-026).

**Six Work Items landed on 2026-08-26 and five of them were instruments, not product.** That was not the plan for the session and it is the finding: reading CI for M0's own merge showed `ci/comment-lang.sh` printing `passed` once per file its awk had refused to run, and `ci/state-sync.sh` making `main` permanently red. Pulling that thread found three more of the same shape -- a count that had stopped counting, a scan reading build output, and an install asking a cache whether a binary exists. **Every one of them reported success while measuring nothing**, and none was found by review; all five were found by reading a CI run that nobody had looked at.

**The trust root works, end to end, on a real machine.** On 2026-08-25 the user ran the built desktop app, pressed sign in, and got back an account and `TrustTier::SameAccount`. That tier is the load-bearing part rather than the account name: it comes back only when the `id_token`'s nonce equals `BLAKE3(identity_pub || agreement_pub)` over **this device's** two keys and its `aud` is in the deployment's client set. A device now demonstrably proves which account it belongs to **with no Tradr backend anywhere in the path**. Steps 2 to 16 of that flow had never run before that moment.

**M0's completion criterion is met.** On 2026-08-25 a Linux desktop and a MacBook exchanged Attestations by hand and each verified the other, both returning `SameAccount`. **No Tradr backend is anywhere in that path** -- each device checked the other's `id_token` against Google's published JWKS, checked `aud` against the deployment's client set, and recomputed `BLAKE3(identity_pub || agreement_pub)` over the keys the peer supplied. ADR-0005 and ADR-0010 stopped being design documents.

**The first bulk transport (`direct-quic`) is complete.** `QuicTransport`, `QuicIncoming` and `QuicChannel` wrap `quinn` behind `tradr-core`'s traits with mutual TLS and Device ID verification.

**ADR-0004's throughput requirement is verified.** On 2026-08-29, the user ran the test on two real machines and confirmed that the LAN throughput reaches the 35 MB/s target with no issues. GSO/GRO tuning is not needed.

**The Trust Tier on every live connection was a constant until 2026-09-01, and `WI-M6-001` is what changed that.** All four live call sites handed the handshake `|_| async { Ok(TrustTier::SameAccount) }`, so any device completing the QUIC handshake held the top tier and the peer's Attestation was read off the wire and discarded. **Five milestones shipped that way** and no review, test or CI job noticed; `verify_attestation` was complete, tested, and reachable only from the hand-pasted bundle screen. The full account is in [RECORD.md](RECORD.md).

**The single most useful thing to read next is the Review record.** It carries why each Work Item went the way it did, and most of its `REVISE` entries were caused by an error in the Supervisor's own Work Order rather than by the Implementer. That ratio is the main finding of M0 so far, and the `DISCARD` entry is the sharpest instance of it.

### Rule F6 has never been enforced in `tauri-plugin-tradr`, found 2026-08-31

**Twenty-two `let _ =` bindings sit in `crates/tauri-plugin-tradr/src/`, and rule F6 admits no exceptions.** Found while reading `commands.rs` to cut `WI-M5-003`, not by any gate: `ci/run-all.sh` has eight checks and none of them greps for a discarded `Result`, which is the shape of gap this file records five times over -- a rule with no instrument. Every one of these passed a review.

**Three of them discard something that decides behaviour, and those are the finding rather than the count.**

- **`listener.rs:384` discards the whole result of `handle_browse_stream`.** That call is where a Browse request is served, and [docs/06](docs/06-shares-and-browsing.md) puts the Share's audience and the requester's Trust Tier check inside it. **A refusal and a success are therefore indistinguishable at the call site**, and a peer denied a Share leaves exactly the same trace as one served.
- **`listener.rs:234`, `235`, `241` and `242` discard `record_piece` and `mark_verified`.** Chunk resumption is one of [CLAUDE.md](CLAUDE.md#6-critical-modules--tests-come-first)'s named Critical Modules, on the grounds that if it is wrong "the entire path-selection design collapses". A `record_piece` that failed and said so into a discarded `Result` produces a resume offset computed from a state the code believes it wrote and did not.
- **`commands.rs:655`, `735`, `809` and `889` discard `PeerList::apply`.** Its only error is `SourceMismatch`, which exists because [docs/03](docs/03-discovery-and-transport.md) does not trust a Brokr to label an observation `mdns`. Discarding it makes the one check that rule exists for unobservable. **`WI-M5-003` touches all four lines and fixes them there**; the rest are `WI-M5-005`.

**The instrument matters more than the repair.** A rule that survives twenty-two violations across four milestones is not being enforced by review, and the answer this repository has reached five times before is a check in `ci/` rather than a resolution to look harder.

### Three defects found by running the Windows build, 2026-08-31

**None of these is reachable from Linux or from CI**, and all three were found in the first hour of using a real Windows machine. `cargo test --workspace` passes on `windows-latest`, so this is the gap between a green matrix and a working application.

**F-W1. `send_files` asks "is this absolute?" as `name.starts_with('/')`.** `crates/tauri-plugin-tradr/src/commands.rs` branches on that to decide whether to register a temporary VFS root for the file's parent directory, and on Windows an absolute path is `C:\Users\...`, which does not start with `/`. So the whole absolute path falls into the relative branch and reaches `RelPath::new`, which refuses it correctly and for the wrong-looking reason: `invalid relative path 'C:\Users\prokosna\Downloads\...': relative path contains a backslash`. **The message is accurate and the diagnosis it invites is wrong** -- nothing is wrong with the path, it was never recognised as absolute. `std::path::Path::is_absolute` is the platform-correct test and handles `C:\`, UNC and `\\?\` as well as `/`. **Drag-and-drop is the only way to send a file on Windows today, and it is the one that fails.**

**F-W2. The `dialog` plugin is initialised and permitted nowhere, so `Select Files` does nothing.** `apps/tradr/src-tauri/src/lib.rs` registers `tauri_plugin_dialog::init()`, and `apps/tradr/src-tauri/capabilities/default.json` grants no `dialog:` permission at all, so the IPC ACL refuses `open()`. **This is the same defect the `WI-M5-004` DCR found, in another plugin**, which widens `WI-M5-006`: the instrument has to cover every plugin the frontend calls, not only `tauri-plugin-tradr`'s own `COMMANDS`. **A second fault makes it invisible rather than merely broken**: the handler ends in `catch (e) { console.error(...) }`, so an ACL refusal reaches no part of the interface and the button silently does nothing. That is rule F6's shape on the frontend, where no check looks. **The permission half landed with `WI-M5-006`** -- `dialog:allow-open` is granted and a check now refuses a frontend plugin import that is not; the swallowed `catch` is still `WI-M5-009`.

**F-W3. A registered Static Peer is not selectable where a user looks for it, and that is an affordance rather than a defect -- settled by observation on 2026-08-31.** The entry does reach the Discovered Peers list; the user confirmed it appears there after adding. The Static Peers section lists entries with a Remove button and no way to act on one, and the Discovered Peers section's empty text reads "No peers discovered on local network yet", **which tells a reader that a hand-registered peer does not belong there.** So the plumbing is right and the interface hides it. The repair is labelling and placement, not the source or the drain.

### Trust on first use works on real machines, 2026-08-31

**A Static Peer registered by hand on Windows was dialled, authenticated, and pinned, against a real MacBook.** The user pressed send and watched the entry change from "Unidentified" to carrying the peer's identity -- which is the whole of docs/03's "Trust on first use needs no operation of its own" running for the first time outside a loopback test: the dial went out under `PeerExpectation::Unpinned`, the channel authenticated, `connect_and_pin` wrote the `DeviceId` back, the source re-reported the same `ObservationId` with it present, and the peer list merged it.

**This is stronger evidence than it looks, because of how the candidate was chosen.** An unidentified peer holds exactly one observation, so the only candidates that could have been dialled are the static entry's own. **Whatever address the user typed is what was dialled and what authenticated** -- no mDNS candidate could have substituted for it.

**The transfer that followed failed on F-W1**, so what is proven is the connection, the authentication and the pin, and not yet a file arriving. **The endpoint was a MagicDNS name, and the MacBook was moved onto phone tethering to run it** -- reported by the user on 2026-08-31. That combination is what makes the observation worth what it is:

- **The two machines were on different networks, so mDNS could not see the peer at all.** Nothing could have substituted a LAN candidate for the tailnet one, which is the substitution that would have made the whole test vacuous.
- **A MagicDNS name does not parse as a `SocketAddr`, so DCR-062's resolver path ran for real** -- the first time outside a `localhost` test.
- **MagicDNS answers with both an `fd7a::` AAAA and a `100.x` A**, and the endpoint binds `0.0.0.0`, so DCR-062's family filter is what selected the address that could be dialled. **That rule was written from a probe and had never run against a real answer.**

**So every part of M5's completion criterion is now demonstrated except the file arriving**: a hostname, resolved, over an overlay network, with no mDNS anywhere in the path, authenticated and pinned. The transfer itself failed on F-W1, which `WI-M5-008` fixes.

## Next three actions
1. **`WI-M6-003b`, the Link Secret in the OS key store, and the operation `SecretStore` lacks.** It has to land inside M6 rather than wait for M7's EIDs: the two half secrets are ephemeral, so a Link stored without its secret can never recover one and re-linking is the only repair. **It is also the first Layer 1 trait change since M1**, so what it costs is the three implementations and the test doubles, and that count is the thing to check before cutting it
2. **`WI-M6-005`, the invite: generated, rendered as a QR and as a base64 blob, parsed back, and expired.** `WI-M6-004b` closed the wire half of the exchange, so what an invite has to carry is now fixed by a codec rather than by docs/11's sketch. **`WI-M6-003` closed the other half it depended on**: `derive_link_secret` and `derive_link_id` exist, so the invite's `half_secret` now has something to join into
3. **`WI-M5-005`, `WI-M5-009` and `WI-M5-010` still ride alongside.** Unchanged and still blocking nobody. **`WI-M5-005` reads differently after `WI-M6-001`, though** -- it is the ninth CI check over a rule review did not enforce, and a constant Trust Tier was an eleventh rule with no instrument, so whatever `WI-M5-005` builds is the shape the answer to both takes

## In flight

(none)

**`845b52a` is on `main` and on no other branch, which means WI-M4-004 landed with no pull request.** Reconciled on 2026-08-31: the previous entry here said to wait for that pull request to merge and there has never been one -- `gh pr list` reports none open, and the branch `wi-m4-004-code-signing` was merged as PR #70 the day before, so the commit at the tip is a second, later piece of the same Work Item committed straight to `main`. **Section 5 forbids exactly this and `ci/state-sync.sh` Check 5 catches it**, which means the commit was made with the gate bypassed or from a state the gate could not see. It is recorded rather than reverted: the work itself passed review and CI, and rewriting published history is forbidden too. **DF-18 is what would have prevented it** -- a `pre-push` hook is still the only instrument a private repository can have, and this is now the second incident it would have stopped.

**The old action 3 stands and is still the user's to start -- ADR-0004's "To verify"**: measure LAN throughput against 35 MB/s, and if it falls short tune GSO, GRO and receive-buffer sizes **before** comparing against TCP. QUIC runs in user space and will not match TCP, so a comparison run before the tuning answers a question nobody asked. **It needs two machines; loopback cannot produce the number.**

**`WI-M1-000f`, the `pre-push` hook, stood here as action 1 and has been moved into the Work Item table rather than dropped.** It is the second of the two rules with no instrument: `.githooks/pre-commit` refuses a *commit* made on `main` and **nothing refuses a push to it**, so `git push origin HEAD:main` from any branch still works, which is the exact motion that put 73 commits there. Branch protection cannot cover it -- see decision 2 below -- so a hook is the only enforcement a private repository can have. It is displaced rather than deprioritised: the transport is what M1 is judged on.
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
| M1 | **LAN transfer**, the most important — mDNS, QUIC, transfer, resumption, drag-and-drop send | 4 weeks | **done 2026-08-29** |
| M2 | Android integration — share sheet, Sharing Shortcuts, SAF, permissions | 3 weeks | **done 2026-08-30** |
| M3 | Share browsing — VFS, boundary enforcement, the Browse plane | 3 weeks | **done 2026-08-30** |
| M4 | Windows and macOS — builds, signing, auto-update, tray | 3 weeks | **done 2026-08-30** |
| M5 | Static Peers and overlay networks — direct over Tailscale | 1 week | **done 2026-08-31** |
| M6 | Account linking — QR, Link Secret, Fingerprint | 2 weeks | **current** |
| M7 | BLE, the largest estimation risk — advertising and scanning on four platforms, EIDs, Noise over GATT | 4-5 weeks | todo |
| M8 | Brokr — presence, rendezvous, relay, FCM, revocation list | 3 weeks | todo |
| M9 | Finishing — security review, store submission, packaging, i18n | ongoing | todo |

### Current milestone: M6, Account linking
**Design**: [docs/11-account-linking.md](docs/11-account-linking.md)
**Done when**: two devices on different accounts link by QR, transfer both ways, and removal takes effect immediately.

**M6 does not start from nothing, and the first hour of reading it found the reason it looked as though it did.** `grep` finds no `Fingerprint` and no `link_id` in `crates/*/src`, which is what the last session recorded -- and `AttestationPolicy` has carried a `linked_accounts` field since M0, `TrustTier::Linked` has been on the wire since M1, and `classify_with_profile` already returns it for an account in that list. **Every call site passes `linked_accounts: &[]`, and none of the four live ones reaches that function at all.** So M6's real first move is not building the tier, it is making the tier reachable. See the finding at the top of this file.

#### Four gaps M6's design had, all four closed on 2026-09-01

**They were recorded before any of them was settled**, so this table can now say what was decided against what was assumed. Three were arithmetic or naming a primitive; the fourth was a design decision.

| # | Gap | Settled by | Where |
|---|---|---|---|
| G1 | **The Fingerprint's bit arithmetic did not close.** 15 bytes split into three groups of 5, each encoded as 4 words from a list of 2048 -- 40 bits against 44. **120 and 132 were both defensible and the doc named neither** | **DCR-065: 132 bits**, twelve 11-bit indices taken most-significant-bit first from the digest's first 17 bytes. It is the number that keeps the three rows of four the document already displays | [docs/05](docs/05-security.md#why-132-bits-when-the-words-were-always-twelve) |
| G2 | **The word list had no source.** "A BIP-39-style list of 2048" names a shape and not a file, and a Layer 0 crate may not depend on a crate that carries one | **DCR-065: BIP-39's English wordlist, vendored**, with URL, SHA-256 `2f5eed53...` and its MIT notice recorded in docs/05. Chosen for a property the shape never stated -- no two words share their first four letters | [docs/05](docs/05-security.md#where-the-word-list-comes-from) |
| G3 | **`HKDF(half_A \|\| half_B, "tradr-link-v1")` named no hash, no salt, and no output length** | **DCR-066: `BLAKE3::derive_key("tradr-link-v1", half_A \|\| half_B)`**, 32 bytes. The salt had no source, which is why it could not be named; `derive_key`'s context string is the role `info` was playing | [docs/11](docs/11-account-linking.md#deriving-the-link-secret) |
| G4 | **The reply reaches a peer that is not linked yet, and after `WI-M6-001` that connection is refused.** The handshake classifies it `UntrustedAccount` and the connection never opens | **DCR-067: a stream, not a tier.** While an invite is open, a Control stream whose first frame is `LinkReply` is accepted, carries no session, and carries only the three linking codes. Steps 1-5 and the key join still run; step 6 is the only one left out, and it is the one the link exists to change. `classify` is untouched and `TrustTier` gains no variant | [docs/11](docs/11-account-linking.md#how-bobs-reply-reaches-alice-and-what-authorises-the-connection), [docs/04](docs/04-protocol.md#a-control-stream-may-open-with-linkreply-instead-of-hello) |

**One thing outside the four turned up while writing them, and it is the kind that reaches code.** docs/11's "State after linking" example rendered `link_id` as `"01J8YM..."`, which reads as a ULID, while the diagram four lines above derives it as `BLAKE3(Link Secret)[0..16]`. An implementer reading the example rather than the diagram would have built a `ShareId`-shaped type. The example is now hex and says so.

#### Work Items

**`WI-M6-001`, `WI-M6-002`, `WI-M6-004a` and `WI-M6-004b` have landed; the rest are not cut yet.** They are the shape M6 is expected to take, listed so the order is on record; each is cut properly when its turn comes, and any of them may change then. **Two of the four were re-cut at dispatch and the table records why in its own rows**, which is the reason a row is worth more than the order it sits in.

| ID | Content | Status | Critical |
|---|---|---|---|
| WI-M6-001 | **The live Trust Tier stops being a constant.** The four `\|_\| async { Ok(TrustTier::SameAccount) }` closures call `verify_attestation` against a policy built from this device's own sign-in, sharing one warm `JwksCache` across connections, and the listener reads its own `id_token` at connection time rather than capturing it at startup | **done** | **yes** |
| WI-M6-002 | Layer 0 link domain in `tradr-core`: `LinkId`, `LinkSecret`, `HalfSecret`, `InviteId`, and the `Fingerprint` word encoding with its vendored list. No hashing -- `DeviceId::from_identity_digest`'s precedent is that Layer 0 receives a digest and never computes one. **Re-cut when it was dispatched: the `Link` record moved to `WI-M6-003`**, because it must carry the peer's account and `AccountId` lives in `tradr-identity`, so a Layer 0 `Link` would have had to hold a loose `iss`/`sub` pair and duplicate a type that already exists one layer up | **done** | **yes -- the Fingerprint encoding, by section 6's own test** |
| WI-M6-003 | `tradr-identity`: the hashing half of the above, the `Link` record `WI-M6-002` handed over, and the persisted Link registry that feeds `AttestationPolicy::linked_accounts`. `StaticPeerRegistry` is the precedent for the file, the whole-file rewrite and the temporary-file rename. **DCR-069 had to run first**: docs/11's state block is the third payload in that document read as a specification and found unimplementable, and three of its six fields have nothing that could write them | **done** | **yes -- `linked_accounts` decides step 6, and a wrong answer grants `Linked` to a stranger** |
| WI-M6-003b | **The Link Secret in the OS key store, and the operation `SecretStore` lacks.** The trait declares `store` and `load` and nothing that empties a slot, so docs/11's "removal discards the Link Secret" is true as design and false as code. It must land inside M6 rather than wait for M7's EIDs: the two half secrets are ephemeral, so a Link stored without its secret can never recover one, and re-linking is the only repair | planned | |
| WI-M6-004a | The three linking messages, first half: `link.proto` under `proto/tradr/v1/`, the three type bytes in `tradr-proto`'s registry, and the Layer 0 `LinkReply`, `LinkApprove` and `LinkDecline` in `tradr-core`. **Re-cut when it was dispatched, in two ways.** DCR-068 had to settle what the messages carry before any of it could be written -- docs/11's sketch omitted `agreement_pub`, which step 3 reads, and carried `sub`, which is a second answer to a question the token already answers. And `tradr-core` was not in the original scope at all: `hello.rs` and `control.rs` are the precedent, and both convert a wire message into a validated Layer 0 type rather than handing the generated one out, so the native types have to exist before a codec can produce them | **done** | |
| WI-M6-004b | The three linking messages, second half: the codec in `link.rs` under `crates/tradr-proto/src/`, converting each message both ways and framing it under its type byte. `hello.rs` is the precedent for the two error types and for what a `from_wire` refuses. **It refuses an empty `attestation.id_token` where `peer_hello_from_wire` does not**, because docs/11 says that field refuses the message when absent and proto3 cannot tell an absent string from an empty one | **done** | |
| WI-M6-005 | The invite: generated, rendered as a QR and as a base64 blob, parsed back, and expired | planned | |
| WI-M6-006 | The exchange in the plugin: the window an invite opens, the reply, the approval, and both sides storing the Link | planned | |
| WI-M6-007 | The interface: show the QR, scan or paste one, show both Fingerprints, approve or decline, list Links and remove one | planned | |
| WI-M6-008 | Removal takes effect at once, and a transfer runs both ways at `TrustTier::Linked`. M6's completion criterion, and the Work Item that measures it | planned | |

**M5's three carried Work Items are still open and still ride alongside M6.**

| ID | Content | Status | Critical |
|---|---|---|---|
| WI-M5-005 | **Rule F6 in `tauri-plugin-tradr`, and the instrument that would have caught it**: the eighteen `let _ =` bindings `WI-M5-003` does not touch, and a ninth check in `ci/` over a discarded `Result`. See the finding above | todo | |
| WI-M5-009 | **A refusal the frontend swallows reaches nobody** (F-W2's second half): `Select Files` ends in `catch (e) { console.error(...) }`, so the ACL refusal that broke it produced no visible symptom at all. Rule F6's shape on the side of the codebase no check looks at. The permission itself is `WI-M5-006` | todo | |
| WI-M5-010 | **Where a Static Peer appears, said in the interface** (F-W3): the Discovered Peers section claims to list what is on the local network, and a hand-registered peer arrives there with no explanation | todo | |


## Deferred

Things consciously postponed. **These live here, not in TODO comments in the code.**

| # | Content | When | Source |
|---|---|---|---|
| DF-30 | **A Supervisor test file is dispatched without ever having been run through the gates it will be judged by, and `WI-M6-003`'s failed one.** `crates/tradr-identity/tests/link_registry.rs` was not rustfmt-clean, and `.githooks/pre-commit` runs `cargo fmt --check` over the whole workspace -- **so the file protecting the Work Item would have refused the commit landing it.** The hash that stops an Implementer editing the file also stops it fixing the file, which is correct and is what makes this the Supervisor's to catch. **This is the second instance, after `WI-M5-002`'s six-line module doc breached rule A2 in the file written to enforce the rules**, so it is a pattern and not an accident. The instrument is one command before dispatch -- `rustfmt` the file and run `sh ci/run-all.sh` -- and the entry exists because a resolution to remember is what failed the first time | Before the next Critical Module Work Item is dispatched | Review of WI-M6-003 |
| DF-29 | **The atomic-write registry pattern is now duplicated byte-identically across two crates, and the layer rules make it unsharable.** `temp_path_for`, the prospective-then-persist-then-commit order and the separate on-disk record type appear in `crates/tradr-discovery/src/static_peer.rs` and `crates/tradr-identity/src/link.rs` in the same shape, comments included. **Unlike DF-27 this is structural rather than lazy**: `ci/layer-deps.sh` rule 4 lets an implementation crate depend internally only on `tradr-core` and `tradr-proto`, `tradr-core` may depend on nothing (B1) and must need no real filesystem (I4, B5), so a helper that calls `fs::rename` has no legal home in this dependency graph. **The exit is a decision and not a refactor** -- either a small Layer 3 crate both may depend on, which means widening rule 4 and saying why, or accepting the duplication and recording that it is deliberate. A third copy is what makes it urgent, and a third registry is plausible | Before a third registry is written | Review of WI-M6-003 |
| DF-28 | **Three fields of docs/11's Link record are left out rather than landed empty** (DCR-069). `peer_email` has no source at all -- `VerifiedClaims` carries no `email` claim and no linking message carries one -- and `policy` and `known_devices` are read by nothing. **`ProviderProfile::renewal` is the precedent and DF-16 is its entry**: a field nothing writes is worse than an absent one, because it looks like state that is being kept. `policy` additionally waits on open decision 9, which has not settled whether a same-account transfer auto-accepts, let alone a linked one | With whatever first reads one of them | DCR-069 |
| DF-27 | **Layer 0 now parses hex in two places with byte-identical code, comment included.** `link.rs`'s `hex_byte` and the three-line note about `from_str_radix` accepting a leading sign are a verbatim copy of `device_id.rs`'s, because a shared helper would have meant editing `device_id.rs`, which `WI-M6-002`'s Definition of Done did not name (rule F3). **It is duplication of the kind that diverges rather than the kind that stays put**: the sign trap is a real one and a future third copy is likelier to be written from memory than from this one. `share_id.rs` parses a UUID and does not share the shape, so the consolidation is two types wide, not three | With the next work touching Layer 0's identifier types | Review of WI-M6-002 |
| DF-26 | **`ci/plugin-permissions.sh`'s dynamic-import refusal is scoped to one line, and a hand-wrapped one slips past it.** Found by probe while reviewing `WI-M5-006`, after the refusal itself was added: `await import("@tauri-apps/plugin-fs")` is refused, and the same call written with its argument on its own line exits 0. **The bound is honest rather than hidden** -- the check reads a line at a time, so a construct split across lines is neither parsed nor refused, and the README's "what it cannot parse is refused" overclaims by that much. It is Deferred rather than a third `REVISE` because no formatter produces that shape: the whole call is well under any line width, so wrapping it takes a deliberate hand. **The fix is to accumulate a dynamic import the way a static one is accumulated**, which is the same statement-region machinery rule 3 already has | With the next work in `ci/`, before M9's security review | Review of WI-M5-006 |
| DF-25 | **`UnixTime::elapsed_since` subtracts two `i64`s and can overflow, which panics in a debug build.** Found while reviewing `WI-M5-007`, and it is pre-existing rather than introduced -- the new future-direction call has exactly the shape the staleness one already had. **Reachable only behind a provider signature**, which is what keeps it a Deferred entry and not a `REVISE`: `require_i64` accepts any `i64` the payload carries, so an `iat` near `i64::MAX` against an ordinary `now` overflows, but `parse_claims` runs after step 2 and Google will not sign that. **`VerifiedClaims`'s fields are public, though** (DF-13), so anything in-process can build one, and a Layer 0 primitive that panics on values its own type admits is the wrong thing to leave in a Critical Module's path. The fix is `checked_sub` and a second `UnixTimeError` variant, with its tests written first | With the next work touching `tradr-core`'s clock, before M9's security review | Review of WI-M5-007 |
| DF-24 | **Every IPv6 candidate is refused before a packet leaves, and nothing reports why.** The endpoint binds `0.0.0.0`, and `quinn` answers an IPv6 remote on an IPv4 socket with `InvalidRemoteAddress` -- measured 2026-08-31. So an mDNS peer that publishes only an IPv6 address, and an overlay network that hands out no IPv4, are both unreachable today; DCR-062's family filter makes that visible rather than fixing it. **The exit is a dual-stack bind and it is not free**: `[::]` accepts both families on Linux, where `bindv6only` is 0, and Windows defaults that socket option the other way, so a `[::]` bind there stops receiving IPv4 entirely. Doing it properly means setting `IPV6_V6ONLY` explicitly and handing `quinn` a socket rather than an address, which is a change to how the listener is built and not to how a candidate is dialled | When an IPv6-only path is needed, M7 at the latest | DCR-062 |
| DF-23 | **A skipped frame costs nothing to send and the receiver will skip them forever.** `WI-M1-021` made `Classification::Ignorable` skip and read the next frame, which is what [docs/04](docs/04-protocol.md#what-unknown-message-types-are-ignored-actually-covers) specifies -- and neither side bounds how many times in a row it will do so, so an authenticated peer holds a transfer open indefinitely with `0x24` frames. **This is the design's own rule implemented faithfully, not an implementation liberty**, so bounding it is a Supervisor's decision and not a `REVISE`: docs/04 says what is skipped and is silent on how often. It bites only a peer that already cleared a Trust Tier, which is why it is deferred rather than cut | Before M9's security review | [docs/04](docs/04-protocol.md#what-unknown-message-types-are-ignored-actually-covers) |
| ~~DF-21~~ | **Resolved by WI-M5-001 and DCR-062.** `QuicTransport` accepted only a candidate that parsed as a `SocketAddr`, so docs/03's own Static Peer example, `desktop.tail9f3c.ts.net:51820`, was unreachable by construction -- and M5's completion criterion names connecting by hostname, so the milestone could not have been met while this stood. The transport now parses first and reaches `tokio::net::lookup_host` only when that parse fails | Done 2026-08-31 | Review of WI-M1-004c |
| DF-22 | **Nothing stops a second `#![allow(...)]` from appearing.** DF-20 is legitimate and recorded, but the only thing that will remove it is a Supervisor remembering to look. `ci/excuse-grep.sh` already greps source for prose that papers over a design problem, and an `allow` attribute is the same act performed in the language rather than in a comment. **An allowlist-backed check over `#[allow]` and `#![allow]` would make DF-20 self-closing**, and every later one visible | After WI-M1-004d closes DF-20 | Review of WI-M1-004c |
| ~~DF-20~~ | **Resolved by WI-M1-004d.** **`crates/tradr-transport/src/quic/mod.rs` carried `#![allow(dead_code)]`.** Removed in `WI-M1-004d` upon implementing `QuicTransport`, `QuicIncoming` and `QuicChannel`, with zero dead-code warnings remaining under `-D warnings` | Done 2026-08-26 | Review of WI-M1-004c |
| DF-19 | **Resolved by WI-M1-000b.** **`ci/comment-lang.sh` scans build output.** Its `find` excludes `node_modules`, `target` and the generated protobuf output under `packages/protocol`, but not `packages/*/dist`, so generated `.d.ts` files are held to a rule about hand-written comments. Harmless today because the generators emit ASCII; it becomes a false failure the first time one does not, and the fix is one more `-not -path` | With the next work in `ci/` | WI-M1-000 |
| DF-1 | Desktop drag-out, pulling a peer's file into a file manager. A download button substitutes | After M9 | [docs/08](docs/08-platform-integration.md) |
| DF-2 | Shell integration: Windows context menu, macOS share menu, Linux `.desktop` | Phase 3 | [docs/08](docs/08-platform-integration.md) |
| DF-3 | Post-quantum migration. Write an ADR once `rustls` X25519MLKEM768 and hybrid Noise are both stable | Undecided | [docs/05](docs/05-security.md) |
| DF-4 | Android 14+ `ChooserAction` custom actions. Sharing Shortcuts suffice for v1 | Undecided | [docs/08](docs/08-platform-integration.md) |
| DF-15 | **Closed. Removed from source by DCR-028, then purged from history on 2026-08-24.** `git filter-branch` over `7e7b97f^..HEAD` rewrote the 13 commits that carried the value, `refs/original` was deleted, the reflog expired and the repository repacked. Verified three ways: `HEAD^{tree}` is byte-identical before and after, so no content changed; the value appears in no reachable object; and 318 tests pass on the rewritten branch. **The commit hashes from `7e7b97f` onward all changed, which `ci/state-sync.sh` caught immediately** by refusing a `last_commit` naming a commit that no longer exists. The desktop client secret in `google.rs` was a placeholder, `DESKTOP_CLIENT_SECRET_PLACEHOLDER_NOT_A_REAL_SECRET`. Nothing before the token exchange needs the real value, so WI-M0-008a landed without it. The value sits in `client_secret_475695468283-shsoa7f59bdbta9jlubfs49jonv1m7ng.apps.googleusercontent.com.json` in the repository root, gitignored, **and that file is the only copy on this machine** -- it is also re-downloadable from the Google Cloud Console. Decision 12 settled that it is committed rather than kept out. **A permission classifier refused the command that would have copied it into source**, which is the right refusal and was left standing rather than worked around | With WI-M0-008c | WI-M0-008a |
| DF-16 | **`ProviderProfile` still has no `renewal` field**, the last one docs/05's table lists. It carries real weight -- docs/05's 24-hour silent renewal assumes a refresh token and a `prompt=none` path, and a provider offering neither changes that account's whole revocation story. Left out of WI-M0-008a deliberately rather than landing unused (rule F3), since nothing reads it until renewal exists | With the silent-renewal work | WI-M0-008a, DCR-027 |
| DF-14 | **`Jwk.algorithm` is compared but the comparison is unreachable.** `SignatureAlgorithm` has one variant, so `key.algorithm != algorithm` is always false and the branch is clean. It is there because a JWKS entry publishes what a key is *for*, and RS256 and PS256 can share one RSA modulus, so nothing but that field would stop a key published for one being used for the other. **It becomes testable the day a second algorithm lands, and a test must arrive with it.** Recorded rather than covered by a test that would only appear to exercise it | With the second `SignatureAlgorithm` | WI-M0-011b |
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

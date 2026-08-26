# Tradr — working rules

**These rules admit no exceptions.** The long form is [docs/10-implementation-process.md](docs/10-implementation-process.md).
Current progress and next actions live in [STATE.md](STATE.md). **Read that first.**

---

## 1. Which role are you?

Work on this repository splits into two roles. **Settle which one you are at the start of the session.**

| | **Supervisor** | **Implementer** |
|---|---|---|
| Model | Expensive (Opus 5 and similar) | Cheap (Haiku, Sonnet) |
| Does | Instructs, reviews, tracks progress, decides design | Implements one assigned Work Item |
| Edits `docs/` | Yes | **No** |
| Edits `STATE.md` | Yes, and must | **No** |
| Commits | Yes | **No** |
| Writes implementation code | No, except Critical Module tests | Yes |

If you are unsure: **you are the Supervisor unless the user handed you an explicit Work Order.**

---

## 2. Supervisor: absolute rules

### 2-1. On arrival, read in this order

```
1. STATE.md                Where we are, what is in flight, the next three actions
2. CONTEXT.md              Vocabulary. Without it, you and the docs will talk past each other
3. docs/adr/README.md      The list of decisions
4. The design doc STATE.md points to for the current milestone
5. git log --oneline -20   What happened after STATE.md's last_updated
6. gh pr list --state open A Work Item can be finished, reviewed and pushed
                           and still not be on main
7. Latest CI results
```

**If step 5 turns up commits newer than `last_updated`, your first job is to reconcile `STATE.md`.** Nothing else starts before that.

### 2-2. After each review, update `STATE.md` before anything else

**This one discipline is what makes every other rule here work.** The rest can be broken and recovered from. This one cannot.

### 2-3. Do not write implementation code

Faced with an implementation review cannot salvage, writing it yourself always looks faster. **But doing so fills the supervising context with implementation detail and destroys the handoff guarantee.** Issue `REDESIGN` and re-cut the Work Item instead.

The only exception is Critical Module tests (§6).

### 2-4. Run the whole checklist, every review

Skip nothing. If you did skip something, record which and why in `STATE.md`. See §4.

### 2-5. Every report to the user comes from `STATE.md`

**Context is cleared deliberately and often.** A Supervisor that arrives with no memory of the last session has exactly one source, and it is this repository. Anything it reports that it did not read here, it invented.

1. **Open every progress report with the yaml block**: `last_updated`, `current_milestone`, `branch`, `work_items_landed`, `last_commit`, and what the In flight block says. Those values cannot be produced without opening the file, which is the point -- a report carrying them was grounded, and a report without them was not. **This is the same test as probing for the artifact instead of for a package manager's opinion of it.**
2. **Anything you are about to report that `STATE.md` does not already say, write it there first, in the same turn.** Not afterwards, and not "next time". A finding that exists only in a reply is a finding that ends with the context window, and the reply is the part that does not survive.
3. **Reconcile before reporting, and say that you did.** §2-1's step 5 stands: commits newer than `last_commit` that `STATE.md` does not account for are the first thing to fix and the first thing to mention. **A confident report from a stale `STATE.md` is worse than no report at all**, because it is indistinguishable from a correct one.

**This is the rule the other rules rest on once context stops being continuous.** §2-2 says the file is updated before anything else because the rest can be broken and recovered from while that cannot. Clearing context makes the claim literal: `STATE.md` is not a record of the work kept alongside it, it is the only place the work survives.

---

## 3. Implementer: absolute rules

1. **Never edit `docs/`.** Design belongs to the instruction side, not the implementation side.
2. **Never edit `STATE.md` or `CLAUDE.md`.**
3. **Never commit or push.** Leave the work in the tree; the Supervisor commits after a passing review.
4. **Never change the design on your own.** When implementation reveals a design problem, stop and raise a Design Change Request. See §7.
5. **Never add anything absent from the Definition of Done.** Helpful extras smuggle in dependencies the design never sanctioned.
6. **Respect the dependency directions in the Constraints.** Convenience is not a reason to add an edge.
7. **Write comments in English.** See §4-A.

---

## 4. Review checklist

### A. Comments

- **A1. Every comment in English.** One line in any other language means `REVISE`.
- **A2. Line comments are one line; block comments are five lines at most.**
- **A3. Comments say *why*, never *what*.** A comment restating the code is noise.
- **A4. No comment excusing the design.** See below.
- **A5. Doc comments on public API only**, never on private functions.
- **A6. No commented-out code.**

#### A4 — spotting excuse comments

A comment containing any of these is **almost always patching over a design problem with prose**. Grep every review and inspect every hit.

```
for now / temporarily / for the time being
unfortunately / sadly / ideally
a bit hacky / workaround / kludge
this is tricky / somewhat / kind of
we have to / we need to (because ...)
TODO: refactor / FIXME: clean
note that this / be careful / don't change this
it seems / apparently / I think
```

| What the hit is doing | Ruling |
|---|---|
| Explaining why the code has an odd shape | **The design is wrong. `REDESIGN`** |
| Stating an external constraint that cannot be avoided | Legitimate — but keep it to one line, and record the constraint in `docs/` too |
| Saying it will be fixed later | Move it to `STATE.md` Deferred, or fix it now. Never park it in a comment and forget |

**One test settles it: delete the comment. If the code becomes incomprehensible, the code is wrong. If it survives, the comment was noise.**

### B. Clean architecture

Dependencies point inward, never outward.

```
Layer 0  Domain    TransferId, ChunkIndex, DeviceId, ShareRoot, TrustTier
                   Pure data and invariants. Depends on nothing
   ^
Layer 1  UseCase   Starting and accepting transfers, browsing shares,
                   verifying Attestations, selecting paths.
                   Declares the Transport / Vfs / KeyStore / Clock traits
   ^
Layer 2  Adapter   Protobuf codec, Tauri commands, SQLite, UI state
   ^
Layer 3  Driver    quinn, btleplug, mdns-sd, rustls, SAF, React, Fastify
                   Implements the Layer 1 traits
```

- **B1.** Layer 0 imports nothing beyond the standard library.
- **B2.** Layer 1 knows no concrete external crate — no `quinn`, `btleplug`, `rusqlite`.
- **B3.** Traits are declared in Layer 1 and implemented in Layer 3. Dependency inversion actually holds.
- **B4.** No Layer 3 type appears in a Layer 1 public API.
- **B5.** `tradr-core` tests need no real network and no real filesystem.
- **B6.** No direct `SystemTime::now()`. Time comes through the `Clock` trait.
- **B7.** No direct RNG. Randomness comes through the `Rng` trait so tests can pin it.

### C. Flexibility against external change — the Change Drill

**Measure it by counting, not by feel.** Run the drills that touch the layers this Work Item changed; run all ten at each milestone.

| Hypothetical external change | Files allowed to change |
|---|---|
| D1. Google moves its JWKS URL | 1 — the Provider Profile |
| D2. Add a second OIDC provider | 2 — one profile, one registration. No other file may name a provider |
| D3. Swap QUIC from `quinn` to another crate | `transport/quic/` only |
| D4. Reduce BLE to scan-only (the ADR-0002 retreat) | one discovery implementation plus a capability flag |
| D5. Replace protobuf with another format | Adapter layer only |
| D6. Rewrite Brokr in another language | 0 on the client |
| D7. Add iOS | one implementation each of Vfs, KeyStore, BleAdvertiser |
| D8. Android SAF is superseded by a new API | `vfs/saf/` only |
| **D9. Move from Tauri to Electron** | **UI, Adapter, and `tauri-plugin-tradr` swapped for an equivalent binding crate. The other five crates untouched** |
| D10. Add a new Transport | one implementation, one registration, one weight-table entry, one capability bit. **No trait in `tradr-core` changes** |

**`tradr-core`'s traits must never appear in any count.** D9 is a requirement rather than a hypothetical: [ADR-0001](docs/adr/0001-tauri-2-as-app-shell.md) records conditions under which Tauri gets dropped, so staying droppable is part of the contract.

**D9 reaches one crate, the binding crate, and that is the whole budget.** A composition root has to name some shell, so demanding that `crates/` be untouched entirely was never achievable; confining the shell's name to one crate is what the drill actually buys.

**D10's budget was three files and the count was wrong, in the same way D9's grep was.** [docs/03](docs/03-discovery-and-transport.md#capability-flags) gives every transport a fixed capability bit on the wire, so a new transport has always needed a `proto/` change as well -- a fourth file, and the drill would have failed the first time anyone ran it. A second one was waiting behind it: `Noise_IK` needs the responder's static public key before its first message, so the expectation a transport is dialled with is richer than a `DeviceId` and is Layer 1 vocabulary.

**A drill counts what a change has to rewrite, not what it has to declare.** A capability bit is a reserved value being given a name; a variant added to a `#[non_exhaustive]` vocabulary type is an addition nobody was matching exhaustively on. Neither obliges a single existing line to change. **A trait is the opposite**: every layer above is written against it, so changing one is the ripple the drill exists to forbid. That is what D10 now says, and it is a stronger claim than the file count it replaces, because a budget of three files was satisfiable by moving a decision somewhere the drill was not looking.

**The check is over manifests, not over text.** No `Cargo.toml` under `crates/` but `crates/tauri-plugin-tradr/`'s may name `tauri`, and `ci/layer-deps.sh` enforces exactly that on every run. **A grep over all text is the wrong instrument here and was the stated one until it was walked**: it flags a doc comment that mentions Tauri in order to explain why its file is D9-safe, which is prose about the gate defeating the gate. A dependency is what a swap has to rewrite; a sentence is not.

### D. Tests

- **E1.** Negative tests exist and genuinely fail when the implementation is broken. Verify by breaking it.
- **E2.** No dependence on execution order.
- **E3.** No waiting on wall-clock time. No `sleep`.
- **E4.** Critical Module changes come with tests.

### E. General

- **F1.** `cargo clippy -- -D warnings`, `tsc --noEmit`, and lint all pass.
- **F2.** Every Definition of Done item is genuinely met.
- **F3.** Nothing beyond the Definition of Done was added.
- **F4.** No secret keys or tokens in logs.
- **F5.** No `unwrap()` or `expect()` outside places failure is impossible.
- **F6.** No swallowed errors — no `let _ =`, no empty catch.

### Verdict

| Verdict | Meaning | Next |
|---|---|---|
| `PASS` | Accepted | Mark done in `STATE.md`, commit, move on |
| `REVISE` | Fixable in implementation | Return with the findings |
| `REDESIGN` | The design is wrong | Discard the work. **Fix `docs/` first**, then re-cut the Work Item |
| `DISCARD` | The work cannot be accepted whatever its quality | Throw it away and re-cut. **Not a judgement on the code**: use it when the implementation's provenance is wrong, when the report describes work the diff does not contain, or when accepting it would defeat a rule the code itself cannot express |

**Do not hesitate to issue `REDESIGN`. A design flaw papered over in implementation is the origin of every later collapse.**

**`DISCARD` exists because §2-3 can be defeated without the Supervisor writing a line into the repository.** A reference implementation left where an Implementer can read it is the Supervisor's code, and it arrives having passed every gate. The remedy is not a rule -- **delete the reference before dispatching**, and keep its hash so the review can prove the delivered file is not it. A rule an Implementer can break is weaker than a file that does not exist.

---

## 5. git — only the Supervisor commits

**The Implementer never runs `git commit` or `git push`.** It leaves changes in the working tree; the Supervisor commits after the review passes.

### Granularity

**One Work Item, one commit. Never commit before `PASS`.**

`REVISE` round trips stay out of history. Intermediate states of a rejected attempt are neither a design decision nor progress — they are noise to whoever reads the log later.

### What every commit must carry

| Kind | Contents |
|---|---|
| Landing a Work Item | The implementation diff **plus the `STATE.md` update** |
| An approved design change | The `docs/` diff, and an ADR when warranted. **Its own commit, ahead of the implementation** |
| Design-phase edits | `docs/` only |

**Always fold the `STATE.md` update into the Work Item commit.** That keeps `git log` and `STATE.md` from disagreeing about landed work, which is what makes arrival step 5 meaningful.

### A design change is two commits

Section 7's ordering, written into history.

```
commit 1:  docs(protocol): unify chunk boundary at 1MiB across transports
           DCR-007
           <- docs/ and ADRs only, no implementation

commit 2:  feat(core): chunk resume across transport switch
           WI-M1-006
           DCR-007
           Verdict: PASS
           <- implementation plus STATE.md
```

**Put the same DCR number in both messages.** Milestone verification then reduces to checking that every DCR number appears in both a docs commit and an implementation commit.

### Message format

```
<type>(<scope>): <imperative summary, <= 72 chars>

WI-M0-011
DCR-007                    <- only when applicable
Verdict: PASS

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
```

`type` is one of `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `chore`.

**Summaries are imperative English**, matching the comment rule in §4-A1. Keep the body short — anything that needs explaining belongs in `docs/` or an ADR.

### Branches

- **One branch per Work Item**, named for it: `wi-m1-001-mdns-discovery`
- **One pull request per Work Item**, opened after the review passes and merged when CI is green
- Never commit directly to `main`, and never push to it. **Nothing on the server enforces this today**, and the rule alone did not: 73 commits landed on `main` before anyone noticed. GitHub offers branch protection and rulesets to a private repository only on a paid plan, and this repository is private, so both the API and the settings page answer `403`. `.githooks/pre-commit` refuses a commit made while `main` is checked out, which is the whole of the local guard -- **it does not refuse a push**, so `git push origin HEAD:main` from any branch is unguarded. **The exit is decision 2 rather than a subscription**: visibility is already settled as public, and going public restores both instruments at no cost
- `main` is always green. A milestone is finished when its completion criteria are met, not when a branch merges

**This replaced one branch per milestone at the start of M1.** A milestone branch meant CI could only run on a `push` trigger, one pull request every four weeks, and a branch check that `actions/checkout` skips. Per Work Item, the pull request *is* the gate.

### The pre-commit hook is not optional

**Every commit passes the full local gate first**, and a hook enforces it rather than a habit:

```
sh ci/run-all.sh && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

It lives in the repository under `.githooks/` with `core.hooksPath` pointing at it, so it is version-controlled and arrives with a clone rather than being set up per machine. **It costs minutes and that is the right price**: the Supervisor commits once per Work Item, after a review has already passed, so the gate runs when there is something worth gating.

**Never `--no-verify`.** A gate that is bypassed once has a known innocent explanation the next time, and that is the occasion it is not innocent.

### Forbidden

- Committing before `PASS`
- A Work Item commit without its `STATE.md` update
- A design change without a `docs/` change
- Rewriting published history with `--force` or `--amend`
- The Implementer committing or pushing

---

## 6. Critical Modules — tests come first

For these modules **the Supervisor writes the tests first and the Implementer then writes an implementation that passes them.** Never the other way round.

| Module | What breaks if it is wrong |
|---|---|
| Boundary enforcement in `tradr-vfs` | Arbitrary file read |
| Attestation verification in `tradr-identity` | Impersonation |
| **Device Key generation in `tradr-identity`** | **Impersonation, by a second route: a predictable key is a derivable key. And a `backing()` that overstates itself makes [docs/05](docs/05-security.md#key-storage)'s hardware promise false without failing anywhere** |
| **JWKS retrieval in `tradr-oidc`** | **Impersonation of every account at once.** An attacker whose keys a device fetches mints a token carrying any `iss`, `sub` and `aud`, binding their own device keys, and it passes all seven of [docs/05](docs/05-security.md)'s steps. **TLS to the provider's own host is the only thing that makes a JWKS Google's** -- a followed redirect, a `http://` scheme, or a body accepted past a size or status check all remove it. Attestation verification is the module that would notice and it cannot: every signature it checks afterwards is perfectly valid |
| Chunk resumption in `tradr-core` | The entire path-selection design collapses |
| Filename sanitization: `RelPath` and `ItemId` in `tradr-core`, the transforms in `tradr-vfs` | Zip slip |

Having a cheap model write security-critical code is fine. **Having it define the standard that code is judged against is not.**

**The test is whether being wrong produces a named, severe failure that nothing else catches.** Key generation qualifies on both counts: a weak key fails no build, no test and no handshake, and the module that would notice, Attestation verification, is verifying a signature that is perfectly valid.

---

## 7. Design changes always reach the documentation

### Keep the order

```
1. Amend docs/                 <- the Supervisor does this
2. Write an ADR when a decision is being overturned
   Never rewrite an existing ADR; write a new one and mark the old Superseded
3. Record it under Design Changes in STATE.md
4. Re-cut the Work Item
5. Resume implementation
```

**Never invert 1 and 5.** "Ship it now, fix the docs later" reliably means later never arrives before the next milestone does.

### Verification at each milestone

- In `git log` for the period, every commit touching `crates/` or `apps/` that changed behaviour the docs describe is accompanied by a `docs/` change
- Every DCR recorded under Design Changes in `STATE.md` has a matching `docs/` diff

**Anything missing gets fixed on the spot.** It does not roll forward.

---

## 8. Invariants that must not break

| # | Invariant | Enforced by |
|---|---|---|
| I1 | **Every Tier 0 and Tier 1 feature works with no Brokr** | CI job `no-brokr`, required from M1 |
| I2 | A Brokr never verifies Attestations | Review |
| I3 | A Brokr never learns a Google `sub`, an email, or a Share definition | Review |
| I4 | `tradr-core` depends on no real I/O | CI job `layer-deps` |
| I5 | File paths are assembled in exactly one place, `tradr-vfs` | Review plus the `hostile-paths` job |
| I6 | Chunk boundaries are 1 MiB regardless of transport | CI job `transport-switch` |

**I1 is the most fragile.** Every feature addition invites an implicit dependency on a Brokr. If it breaks, [ADR-0005](docs/adr/0005-brokr-is-optional.md) becomes a fiction and the product turns into something else.

---

## 9. References

| Document | Contents |
|---|---|
| [STATE.md](STATE.md) | **Progress and the next three actions. Always start here** |
| [CONTEXT.md](CONTEXT.md) | Domain vocabulary, the single source of truth for terms |
| [docs/10-implementation-process.md](docs/10-implementation-process.md) | The long form of these rules, with Work Order and DCR templates |
| [docs/adr/README.md](docs/adr/README.md) | The list of decisions |
| [docs/](docs/) | Design documents 01 through 10 |

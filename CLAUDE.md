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
6. Latest CI results
```

**If step 5 turns up commits newer than `last_updated`, your first job is to reconcile `STATE.md`.** Nothing else starts before that.

### 2-2. After each review, update `STATE.md` before anything else

**This one discipline is what makes every other rule here work.** The rest can be broken and recovered from. This one cannot.

### 2-3. Do not write implementation code

Faced with an implementation review cannot salvage, writing it yourself always looks faster. **But doing so fills the supervising context with implementation detail and destroys the handoff guarantee.** Issue `REDESIGN` and re-cut the Work Item instead.

The only exception is Critical Module tests (§6).

### 2-4. Run the whole checklist, every review

Skip nothing. If you did skip something, record which and why in `STATE.md`. See §4.

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
| **D9. Move from Tauri to Electron** | **UI and Adapter only. `crates/` untouched** |
| D10. Add a new Transport | one implementation, one registration, one weight-table entry |

**`tradr-core` must never appear in any count.** D9 is a requirement rather than a hypothetical: [ADR-0001](docs/adr/0001-tauri-2-as-app-shell.md) records conditions under which Tauri gets dropped, so staying droppable is part of the contract.

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

**Do not hesitate to issue `REDESIGN`. A design flaw papered over in implementation is the origin of every later collapse.**

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

- One branch per milestone: `m0-skeleton`, `m1-lan-transfer`
- Never commit directly to `main`
- Merge to `main` once the milestone's completion criteria are met

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
| Chunk resumption in `tradr-core` | The entire path-selection design collapses |
| Filename sanitization | Zip slip |

Having a cheap model write security-critical code is fine. **Having it define the standard that code is judged against is not.**

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

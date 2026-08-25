# 10. Implementation process

## Premise

Implementation is done by a **cheap model (the Implementer)** and reviewed by an **expensive one (the Supervisor)**. The split admits no exceptions. The Supervisor writes code only when writing a Critical Module's tests first.

This document exists so that **an agent with no context can take over as Supervisor and continue working immediately**. [`STATE.md`](../STATE.md) is the mechanism; this document defines how it is used.

## Roles

| Role | Model | Responsibility | Forbidden |
|---|---|---|---|
| **Supervisor** | Expensive, Opus 5 and similar | Writing work orders, reviewing, updating `STATE.md`, ruling on design changes, writing Critical Module tests, committing | Writing ordinary implementation code |
| **Implementer** | Cheap, Haiku or Sonnet | Implementing the assigned Work Item | Changing the design, editing `docs/`, editing `STATE.md`, committing |

Write access to `docs/` and `STATE.md` is confined to the Supervisor so that design documents cannot quietly change to suit an implementation. **Design belongs to the instruction side, not the implementation side.**

## The unit of work: the Work Item

Instruction, review, and record all take a Work Item as their unit, cut small enough to judge in one review. The guide is **400 changed lines and 8 files at most**. Anything larger gets re-cut.

### Work Order — Supervisor to Implementer

```markdown
## WI-M1-004: QUIC transport with public-key pinning

### Target
crates/tradr-transport/src/quic/

### Design to consult
- docs/03-discovery-and-transport.md, "Transports"
- docs/05-security.md, "Why there are two encryption layers"
- docs/adr/0004-quic-as-the-bulk-transport.md

### Definition of done
- [ ] `QuicTransport` implements the `Transport` trait
- [ ] The self-signed certificate's SPKI carries the P-256 identity public key
- [ ] A peer certificate whose SPKI does not match the expected Device ID is refused
- [ ] Certificates are requested in both directions, giving mutual TLS
- [ ] No CA chain validation, using a rustls custom verifier
- [ ] Test: connection succeeds with the correct key
- [ ] Test: connection is refused with a different key (negative)
- [ ] Test: connection is refused with no certificate (negative)

### Constraints
- Do not modify `tradr-core`. If that becomes necessary, raise a DCR and stop
- The only public API is the `Transport` trait. No quinn type escapes it

### Prohibitions
- Editing docs/
- Editing STATE.md
- Committing
- Anything absent from the definition of done
```

**Always name the design to consult.** Never assume the Implementer has read all the design documents; point at the sections.

**Always state dependency directions in Constraints.** Clean architecture violations happen when an Implementer helpfully adds an edge because it was convenient. Writing the prohibition down prevents it.

### Review Verdict — Supervisor to `STATE.md`

Three values.

| Verdict | Meaning | Next |
|---|---|---|
| `PASS` | Accepted | Mark done in `STATE.md`, commit, move to the next Work Item |
| `REVISE` | Fixable in implementation | Return to the same Implementer with the findings |
| `REDESIGN` | The design is at fault | Discard the work. Amend `docs/` first, then re-cut the Work Item |

Do not hesitate to issue `REDESIGN`. **Deciding to paper over a design flaw in implementation is the origin of every later collapse.**

## Review checklist

**Run every item, every time.** Never skip. If something was skipped, record it in `STATE.md`.

The authoritative list lives in [CLAUDE.md](../CLAUDE.md) §4, since that is what agents load automatically. What follows expands on the parts that need explaining.

### A4 in depth — excuse comments

A comment carrying any of these phrases is **almost always patching a design problem with prose**. Grep mechanically and inspect every hit.

```
for now          temporarily      for the time being
unfortunately    sadly            ideally
a bit hacky      workaround       kludge
this is tricky   somewhat         kind of
we have to       we need to (because ...)
TODO: refactor   FIXME: clean
note that this   be careful       don't change this
it seems         apparently       I think
```

How to rule:

- **It explains why the code has an odd shape** → the design is wrong → `REDESIGN`
- **It states an external constraint that cannot be avoided** → legitimate, but keep it to one line and record the constraint in the design documents too
- **It says this will be fixed later** → register it under Deferred in `STATE.md` or fix it now. Parking it in a comment to be forgotten is not allowed

One test settles all of them: **delete the comment. If the code becomes incomprehensible, the code is wrong. If it survives, the comment was noise.**

This rule is in the standard because generating models tend toward careful explanation, and that tendency surfaces design weakness in the most detectable form available. **Comment volume works as a proxy for design quality.**

### C in depth — the Change Drill

Flexibility is measured by counting rather than by judgement. For each hypothetical external change, the Supervisor counts the files that would have to change. Over the limit means `REDESIGN`.

The table is in [CLAUDE.md](../CLAUDE.md) §4-C. Two notes:

- **`tradr-core` must never appear in any count.** If it does, the dependency inversion has failed somewhere
- **D9, moving from Tauri to Electron, is a requirement rather than a hypothetical.** [ADR-0001](adr/0001-tauri-2-as-app-shell.md) records the conditions for dropping Tauri, so remaining able to drop it is part of the contract. Walk this drill on paper at the end of M0

Run only the drills relevant to the layers a Work Item touched. Run all ten when a milestone completes.

## Critical Modules — tests first

For these, **the Supervisor writes the tests and the Implementer then writes an implementation that passes them.** Never the other way round.

| Module | Why | The tests written first |
|---|---|---|
| Boundary enforcement in `tradr-vfs` | Getting past it means arbitrary file read | Rejection suite for adversarial paths: `..`, symlinks, Unicode normalization, TOCTOU, Windows reserved names |
| Attestation verification in `tradr-identity` | Getting past it means impersonation | A negative test per verification step, each disabling one check |
| Chunk resumption in `tradr-core` | Breaking it collapses the whole path-selection design | A harness injecting disconnections and path switches |
| Filename sanitization | Zip slip | The known attack corpus |

**This is not an exception to the split; it is the premise of it.** Having a cheap model write security-critical code is fine. Having it define the standard that code is judged against is not. With tests already in place, a weak implementation still gets caught.

## Handling design changes

### The rule

**The Implementer cannot change the design.** On finding a design problem mid-implementation, it stops and raises a Design Change Request.

### The DCR

```markdown
## DCR-007: per-path chunk sizes break resumption

### Where found
During WI-M1-006. A partial file received over relay at 256 KiB chunks,
resumed over direct-quic at 1 MiB, leaves the chunk boundaries misaligned
so resume_chunk has no well-defined meaning.

### Design text at issue
docs/04-protocol.md, "Chunk sizes"

### Options
A. Fix 1 MiB everywhere -> incompatible with the 4 KiB BLE constraint
B. Keep 1 MiB as the reference and subdivide on smaller paths
   -> resumption is always 1 MiB granular; slightly more implementation
C. Restart from scratch when the path changes -> unacceptable experience

### Recommended
B

### Now blocked
WI-M1-006
```

### Ruling and reflection

The Supervisor rules. When approving, **follow this order exactly**.

```
1. Amend docs/                     <- the Supervisor does this
2. Write an ADR if a decision is being overturned.
   Never rewrite an existing one; write a new ADR and mark the old Superseded
3. Record it under Design Changes in STATE.md
4. Re-cut the Work Item
5. Resume implementation
```

**Never invert 1 and 5.** "Ship it now, fix the docs later" reliably means later never arrives before the next milestone does.

### Verification

At each milestone the Supervisor checks:

- In `git log` for the period, every commit touching `crates/` or `apps/` that changed behaviour described in the design carries a `docs/` change
- Every DCR under Design Changes in `STATE.md` has a matching `docs/` diff

**Anything missing gets fixed on the spot.** It does not roll forward.

## Handover — how a contextless Supervisor arrives

A new Supervisor reads in this order. Keeping work startable without reading anything else is the reason `STATE.md` exists.

```
1. STATE.md                Where we are, what is in flight, the next three actions
2. CONTEXT.md              Vocabulary. Without it you will talk past the documents
3. docs/adr/README.md      The decision list; read details only as needed
4. The design document STATE.md links for the current milestone
5. git log --oneline -20   What happened after STATE.md's last_updated
6. The latest CI results   Whether the required jobs pass
```

**Step 5 matters most.** Always suspect `STATE.md` of being stale. Commits newer than `last_updated` mean it was not updated, and reconciling it is the first job.

## The `STATE.md` discipline

**The Supervisor updates `STATE.md` after each review, before anything else.**

Letting it slip destroys the handover guarantee at that moment. **This one discipline is what makes the whole document work.** Every other rule can be broken and recovered from; this one cannot.

What gets updated:

- Work Item status: `todo`, `in-progress`, `review`, `done`, `blocked`
- `in_flight` — who is doing what
- `next_actions` — the next three, always three
- `last_updated`
- Design Changes, when a DCR occurred
- Deferred, when something was postponed

## git

Rules are in [CLAUDE.md](../CLAUDE.md) §5. The two that carry design weight:

- **A Work Item commit always carries the `STATE.md` update.** That keeps `git log` and `STATE.md` from disagreeing about landed work, which is what makes handover step 5 meaningful
- **A design change is two commits, docs first, both carrying the same DCR number.** Milestone verification then reduces to checking that every DCR number appears in both

## The cycle

```
+---------------------------------------------------------+
| Supervisor: read STATE.md, choose the next Work Item     |
+----------------------+----------------------------------+
                       v
        Critical Module? ------ yes ---> Supervisor writes the tests first
                       |                          |
                       no                         |
                       v                          v
+---------------------------------------------------------+
| Supervisor: write the Work Order                         |
|   target / design to consult / definition of done /      |
|   constraints / prohibitions                             |
+----------------------+----------------------------------+
                       v
+---------------------------------------------------------+
| Implementer: implement                                   |
|   never touches docs/ or STATE.md, never commits         |
|   raises a DCR and stops on a design problem             |
+----------------------+----------------------------------+
                       v
+---------------------------------------------------------+
| Supervisor: run checklist A through E in full            |
+----------------------+----------------------------------+
                       v
         +-------------+-------------+
         v             v             v
       PASS         REVISE        REDESIGN
         |             |             |
         |             |             v
         |             |      amend docs/ first -> ADR -> re-cut
         |             v
         |      return with findings
         v
+---------------------------------------------------------+
| Supervisor: update STATE.md, then commit                 |
|             both before starting anything else           |
+---------------------------------------------------------+
```

## What CI protects

People and models both forget, so the machine checks. These are required and block merging.

| Job | What it does | From |
|---|---|---|
| `lint` | clippy `-D warnings`, eslint, tsc, rustfmt, prettier | M0 |
| `comment-lang` | Flags non-ASCII characters inside comments, mechanizing A1 | M0 |
| `comment-length` | Lists block comments over five lines | M0 |
| `excuse-grep` | Greps the A4 patterns and lists every hit | M0 |
| `layer-deps` | Checks Layers 0 and 1 import no forbidden crate, and runs the mechanical Change Drills: D5's `prost` confinement and D9's `tauri` confinement | M0 |
| `test` | The whole suite | M0 |
| **`no-brokr`** | **Tier 0 and Tier 1 integration tests pass with no Brokr running** | **M1** |
| `hostile-paths` | The `tradr-vfs` adversarial path suite | M3 |
| `transport-switch` | Forces path switches and confirms transfers resume | M1 |

### Every job fails. False positives go in the allowlist

`comment-lang`, `comment-length`, and `excuse-grep` do produce false positives, and an earlier version of this document had them warn rather than fail for that reason, on the understanding that a warning obliges the Supervisor to inspect every hit.

**That does not survive contact with practice.** A job that cannot fail is not a gate; it is a log line, and it accumulates unread hits until the count is large enough that nobody reads any of them. WI-M0-001b caught exactly this shape in `pnpm lint`, which exited 0 with a real violation present because Biome reports rule hits as warnings.

So every job fails on a hit, and a false positive is retired by naming it in `ci/allowlist.txt` **with a reason**:

```
excuse-grep | crates/tradr-vfs/src/openat.rs | The kernel constant is literally named RESOLVE_NO_MAGICLINKS
```

The difference is that an allowlist entry is a deliberate act, visible in a diff, attributable to whoever added it, and countable. A warning nobody reads is none of those things.

**An allowlist entry with an empty reason fails the job**, so the escape hatch cannot be taken silently.

`no-brokr` is the only thing holding up [ADR-0005](adr/0005-brokr-is-optional.md). Without it that ADR becomes a fiction within months.

## Risks in this arrangement

Stated plainly.

| Risk | Response |
|---|---|
| A cheap model gets security-critical code wrong | Critical Modules get their tests first |
| Review degenerates into mechanical `PASS` | Record checklist results in `STATE.md`; name anything skipped |
| `STATE.md` falls behind and handover breaks | Arrival step 5 reconciles `last_updated` against `git log` |
| No DCR is raised and implementation silently departs from the design | Stated in the Work Order's prohibitions; verified against `git log` at each milestone |
| Work Items grow too large to review | The 400-line, 8-file ceiling. Over it, re-cut |
| The Supervisor starts writing implementation | Stated in the role table; the `reviewer` subagent has no write tools at all |

The last is the likeliest. Faced with an implementation review cannot salvage, writing it yourself always looks faster. **But doing so fills the supervising context with implementation detail and destroys the handover guarantee.** Choose `REDESIGN` and re-cut instead.

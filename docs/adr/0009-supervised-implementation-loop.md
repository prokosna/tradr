# ADR-0009: A cheap model implements, an expensive one reviews

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

This product is implemented by AI agents. Done naively, a single expensive model would design, implement, and review. That carries two problems.

1. **Cost.** Most implementation is routine and does not need an expensive model
2. **Loss of handover.** A session that holds design through implementation cannot continue once its context is gone. Over a long project, context is always eventually gone

The second is the heavy one. **A design that does not assume agent context is finite and will run out breaks within weeks.**

## Decision

**Split into two roles: a cheap model implements, an expensive one instructs, reviews, and tracks progress. No exceptions.**

Further, require that **an agent with no context can take over as Supervisor and continue immediately**, and provide `STATE.md` as the mechanism.

| | Supervisor | Implementer |
|---|---|---|
| Model | Expensive, Opus 5 and similar | Cheap, Sonnet 5 or Haiku 4.5 |
| Responsibility | Instruction, review, progress, design decisions, committing | Implementing a Work Item |
| Edits `docs/` | Yes | No |
| Edits `STATE.md` | Yes, and must | No |
| Commits | Yes | No |
| Writes implementation | No, except Critical Module tests | Yes |

## Reasoning

### Why only the Supervisor edits `docs/`

To stop design documents quietly changing to suit an implementation. **Design belongs to the instruction side, not the implementation side.** If the Implementer could edit design documents, "adjust the design to make this easier to build" would happen and would pass review.

### Why the Supervisor does not write implementation

Faced with an implementation review cannot salvage, writing it yourself always looks faster. But doing so **fills the supervising context with implementation detail and destroys handover**, which is the primary aim of this decision.

Issue `REDESIGN` and re-cut the Work Item instead.

### Why only Critical Modules get their tests first

Having a cheap model write security-critical code is fine. **Having it define the standard that code is judged against is not.** When the same model writes both the implementation and its tests, the tests get written to match the implementation's mistakes and the mistakes go undetected.

With the Supervisor writing the tests first, a weak implementation is still caught mechanically. The set is boundary enforcement in `tradr-vfs`, Attestation verification in `tradr-identity`, chunk resumption in `tradr-core`, and filename sanitization.

### Why `STATE.md` is needed

So that handover does not depend on documents happening to be written helpfully. It fixes the arrival procedure and holds the reading list to six items.

It also builds in **a step that suspects `STATE.md` of being stale** — arrival step 5 reconciles `last_updated` against `git log`. State files always rot, so one is useless without a procedure for detecting the rot.

### Why the Work Item commit carries the `STATE.md` update

So `git log` and `STATE.md` cannot disagree about landed work. Without that, arrival step 5 has nothing to compare against and the handover guarantee becomes decorative.

## What review looks for

The checklist is in [CLAUDE.md](../../CLAUDE.md) §4. Two items get examined every time.

### Excuse comments

A comment containing `for now`, `unfortunately`, `a bit hacky`, `we have to`, or `note that this` is **almost always patching a design problem with prose**.

One test settles it: **delete the comment. If the code becomes incomprehensible, the code is wrong. If it survives, the comment was noise.**

This is in the standard because generating models tend toward careful explanation, and that tendency surfaces design weakness in the most detectable form available. **Comment volume works as a proxy for design quality.**

### The Change Drill

Flexibility is not judged by feel. For each of ten hypothetical external changes, **count the files that would have to change**. Over the limit means `REDESIGN`.

`tradr-core` must never appear in any drill's count.

## Costs

- **More round trips per cycle**, instruct then implement then review. Kept short by cutting Work Items to 400 lines and 8 files
- **Supervisor attention concentrates on design decisions**, which is the intent, but sensitivity to implementation detail drops. Everything a machine can check moves into CI
- **The Implementer has no context.** Every Work Order must name the design to consult; omitting it returns an implementation that has drifted
- **Letting `STATE.md` slip collapses everything.** Every other rule can be broken and recovered from; this one cannot

## What keeps this decision alive

Standards always decay, so machines enforce them.

| Mechanism | What it protects |
|---|---|
| [CLAUDE.md](../../CLAUDE.md) | Claude Code loads it at session start, so no agent can miss the rules |
| [.claude/agents/implementer.md](../../.claude/agents/implementer.md) | Fixes the Implementer's model and tools; burns the `docs/` prohibition into its system prompt |
| [.claude/agents/reviewer.md](../../.claude/agents/reviewer.md) | Restricts the reviewer to read-only tools. **Unable to fix things, it does not fix them** |
| CI `comment-lang`, `comment-length`, `excuse-grep` | Mechanizes the comment standard |
| CI `layer-deps` | The clean-architecture dependency direction |
| CI `no-brokr` | [ADR-0005](0005-brokr-is-optional.md)'s premise |

Withholding write tools from the reviewer is what works best: "faster to just fix it myself" becomes impossible to act on.

## Conditions for withdrawal

- The cheap model's output quality no longer justifying the review round trips. Track the mean number of `REVISE` cycles; consistently above three means raising the Implementer's model
- Conversely, a run of unbroken `PASS` verdicts making review meaningless, which would indicate either a lax checklist or Work Items cut too small

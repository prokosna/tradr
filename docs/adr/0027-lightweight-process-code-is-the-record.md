# ADR-0027: Lightweight process: the code is the record

- **Status**: Accepted
- **Date**: 2026-11-26
- **Supersedes**: [ADR-0009](0009-supervised-implementation-loop.md)

## Context

ADR-0009 required a docs-first commit, a DCR number, a Work Order and a review record for every change, and kept progress in prose (`STATE.md` and `RECORD.md`). By M8 this had grown to about 2.2 MB of process text against about 114k lines of code. An arriving session spent most of its budget reading it, and every small feature waited on a docs commit. The user, now running the software daily, asked for faster feature work.

## Decision

- Code and tests are the record. `docs/` holds contracts (wire format, security rules, invariants, UI behaviour) and short reasons. Git log and PRs hold history.
- A contract change updates its doc **in the same PR** as the code. There is no separate docs-first commit and no DCR numbering.
- `STATE.md` is a short status page (in flight, owed device checks, open decisions, backlog). `RECORD.md`, Work Order files and `ci/state-sync.sh` are removed.
- The main session may implement directly. The implementer and reviewer subagents are optional tools, used for large separable tasks and for Critical Module review.
- What stays: the layer rules and their CI enforcement, Critical Modules written tests-first, invariants I1-I6, ADRs for load-bearing decisions, a branch and PR per change, and no `--no-verify`.
- pre-commit runs only the fast checks. Clippy and tests move to pre-push and CI.

## Consequences

- Faster iteration and smaller session start-up cost.
- Less ceremony around review. Critical Module discipline and mechanically enforced rules carry the quality bar instead.
- Older code comments cite `DCR-NNN`. They resolve through `git log --grep`.

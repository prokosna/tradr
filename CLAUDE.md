# Tradr: working rules

Tradr moves files between one person's devices (and linked accounts) with no required server. Rust core, Tauri 2 shell, React UI, Kotlin for Android-only APIs. Read [STATE.md](STATE.md) for what's in flight and [CONTEXT.md](CONTEXT.md) for vocabulary.

**Principle: the code and tests are the record.** `docs/` holds contracts and the reasons behind them, not history. Git log and PRs hold history. Keep every file short; when a doc grows a narrative, cut it.

## Commands

```sh
sh ci/run-all.sh                                   # repo-specific checks (layering, comments, frontend gate, …)
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
sh ci/windows-target.sh                            # cfg(windows) code type-checks
cargo check --target aarch64-linux-android -p tauri-plugin-tradr   # cfg(android) code; host builds never see it
pnpm lint && pnpm typecheck && pnpm test           # also run inside ci/run-all.sh (frontend-gate)
```

Hooks: `git config core.hooksPath .githooks`. pre-commit refuses commits on `main` and runs `ci/run-all.sh` + `cargo fmt --check`. pre-push refuses pushes to `main` and runs clippy + tests. **Never `--no-verify`.**

## Workflow

1. Branch from up-to-date `main` (`<topic>` or `wi-<short-name>`). Never commit to or push `main`.
2. Make the change. **When it changes a contract** (wire format, a security rule, an invariant, a layer rule, user-visible behaviour in [docs/12](docs/12-user-interface.md)), update the matching doc **in the same PR**. Otherwise don't touch docs.
3. A decision that is hard to reverse or constrains many modules → a short ADR (`docs/adr/NNNN-*.md`: Status, Date, Context, Decision, Consequences). Never rewrite an accepted ADR; supersede it.
4. Gates green → commit (imperative English summary ≤ 72 chars, `type(scope): …`, types `feat fix refactor test docs ci chore`) → push → PR → merge when CI is green. Several commits per PR is fine.
5. Update `STATE.md` in the same PR if what's in flight, an open decision or the backlog changed. Keep it short.

There are no DCR numbers, Work Order files or review records. Older code comments citing `DCR-NNN` refer to history in git (`git log --grep DCR-NNN`).

### Delegating to subagents (optional)

The main session may implement directly. Delegate to the `implementer` subagent when a task is large, well-specified, and separable. Give it a short prompt: the goal and why, the files it may touch, the docs/ADRs that apply, the exact commands that define done, and "don't commit". Then **review the diff, not the report**, and rerun the gates. Use the `reviewer` subagent for Critical Module changes. Never let two parallel agents share files.

## Architecture rules (mechanically enforced unless noted)

```
Layer 0  Domain    tradr-core types: DeviceId, ChunkIndex, RelPath, ItemId, …   std only
Layer 1  UseCase   tradr-core logic + all traits (Transport, Vfs, KeyStore, Clock, Rng, ContentVerifier, …)
Layer 2  Adapter   tradr-proto (codec), tradr-app, tauri-plugin-tradr, UI state
Layer 3  Driver    quinn, mdns-sd, rustls, reqwest, Kotlin, React
```

- `tradr-core` has no dependencies and does no I/O (I4). Implementation crates depend only on `tradr-core` and `tradr-proto`. Only `tradr-app` and `tauri-plugin-tradr` compose. Enforced by `ci/layer-deps.sh`.
- One owner per volatile library: `prost`→tradr-proto, `tauri`→tauri-plugin-tradr + apps/tradr, `reqwest`→tradr-oidc + `tradr-app/src/brokr/http.rs`, `bao`→tradr-integrity, D-Bus→tradr-secrets. `unsafe` only in `tauri-plugin-tradr/src/android_fd.rs`.
- Time comes only through `Clock` and randomness only through `Rng`, never `SystemTime::now()` or a direct RNG. The exception is ECDSA nonces, which follow RFC 6979 and never use `Rng`.
- Ports expose operations, never raw resources: `KeyStore` signs and agrees but never returns key bytes; `Vfs` operates on `(root, RelPath)` and never returns a path.
- Optional features (Brokr) are extra registered implementations, never conditionals.

**Change budget** (what a swap may touch): replace QUIC crate → `tradr-transport` QUIC module; replace protobuf → `tradr-proto`; leave Tauri → `apps/tradr` + `tauri-plugin-tradr` only (the CLI proves this); new transport → one impl + registration + weight + reserved capability bit, **no `tradr-core` trait change**; rewrite Brokr → zero client changes (`BrokrApi` port).

## Invariants

| # | Invariant | Enforced by |
|---|---|---|
| I1 | Tier 0/1 works with no Brokr (the most fragile) | `ci/no-brokr.sh` (CI job), `ci/tier01-tests.txt` |
| I2 | A Brokr never verifies Attestations | review |
| I3 | A Brokr never learns `sub`, email, or folder contents | review |
| I4 | `tradr-core` does no real I/O | `ci/layer-deps.sh` |
| I5 | File paths are assembled only in `tradr-vfs` | review; `tradr-vfs/tests/{boundary_enforcement,path_sanitization}.rs` |
| I6 | Chunk boundaries are 1 MiB on every transport | `tradr-core/tests/chunk_resumption.rs`; offers with another `chunk_size` are refused |

## Critical Modules: tests first

Being wrong here produces a severe failure that nothing else catches. **Write the tests before the implementation** (the main session writes them, even when an implementer writes the code). Prove every negative test by breaking the implementation and watching the test fail.

| Module | Failure if wrong |
|---|---|
| Boundary enforcement in `tradr-vfs` | arbitrary file read |
| `RelPath`/`ItemId` (core) and filename transforms (vfs) | zip slip |
| Attestation verification in `tradr-identity` | impersonation |
| Device Key generation and `backing()` in `tradr-identity` | a derivable key; overstated hardware protection |
| JWKS fetch in `tradr-oidc` (HTTPS only, no redirects, status and size checks) | every account impersonable |
| Static Peer pin choice | MITM after DNS hijack |
| Chunk resumption in `tradr-core` | path switching collapses |
| Deferred Delivery envelope open in `tradr-identity` | forged deliveries |

## Code rules

Most of these are checked by `ci/run-all.sh`.

- Write everything in English: code, comments, docs, commit messages.
- Comments explain **why**: one line for a line comment, at most 5 lines for a block. No commented-out code. Doc comments (`///`) only on public API.
- **An excuse comment is a design smell** ("for now", "workaround", "hacky", "be careful", "TODO: refactor"). Fix the shape, or record it as a Deferred item in STATE.md.
- Never swallow an error: no `let _ =`, no `.ok();`, no empty catch. If an error is deliberately ignored, report it with context.
- No `unwrap`/`expect` unless failure is impossible. No secrets or tokens in logs.
- Tests: no `sleep` and no wall-clock waits (use tokio's paused clock). No ordering dependence. `tradr-core` tests use no real network or filesystem. A test triggers the event it asserts on.
- No dependencies beyond what the task needs; pin exact versions.
- **Done includes the real runtime**: a user-visible change is checked where it runs (the preview harness in [docs/12](docs/12-user-interface.md), then the device). Don't claim device behaviour you haven't seen; the user reports device problems.

## Docs map

| File | Contents |
|---|---|
| [01](docs/01-overview.md) | problem, use cases, non-goals |
| [02](docs/02-architecture.md) | tiers, crates, front ends, state locations |
| [03](docs/03-discovery-and-transport.md) | mDNS, Static Peers, transports, path selection |
| [04](docs/04-protocol.md) | framing, type codes, session, chunks, partial files |
| [05](docs/05-security.md) | Attestation, OAuth config, keys, channels, threat model |
| [06](docs/06-shares-and-browsing.md) | one-folder access, boundary enforcement |
| [07](docs/07-brokr.md) / [13](docs/13-deferred-delivery.md) | Brokr principles / Deferred Delivery as built |
| [08](docs/08-platform-integration.md) | desktop and Android specifics |
| [09](docs/09-roadmap-and-risks.md) | milestones, releases, risks |
| [11](docs/11-account-linking.md) | Links |
| [12](docs/12-user-interface.md) | UI flows and wording |
| [adr/](docs/adr/README.md) | decisions |

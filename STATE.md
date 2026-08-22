# STATE

> **Only the Supervisor edits this file.** Update it after each review, before anything else.
> An arriving Supervisor reads this first, then runs `git log --oneline -20` to see what happened after `last_updated`.
> **Commits newer than `last_updated` mean the first job is reconciling this file.**

```yaml
last_updated: 2026-08-22
phase: design-complete
current_milestone: M0
implementation_started: false
repo_initialized: true (local only, no remote yet)
```

---

## Where we are

**Design is complete; implementation has not started.** Design documents `docs/01`-`10`, nine ADRs, and five protobuf files are in place. Everything is in English and carries the final names.

Before starting M0, resolve the open decisions below.

## Next three actions

1. **Create the GitHub repository and push.** The local repository, `LICENSE`, `.gitignore`, and the initial design commit are in place; only the remote is missing
2. **Create the Google Cloud project and two OAuth client IDs** — one desktop, one Android. This blocks M0's completion criteria (decision 5 below)
3. **Write the Work Order for WI-M0-001**, the monorepo skeleton: pnpm and Cargo workspaces plus code generation from `proto`

## In flight

```yaml
work_items: []
blocked: []
```

---

## Decisions

### Settled

| # | Decision | Choice | Date |
|---|---|---|---|
| 1 | Product name | **Tradr** for the app, **Brokr** for the self-hosted server process | 2026-08-22 |
| 2 | Repository visibility and licence | **Public, Apache-2.0** | 2026-08-22 |
| 3 | Documentation language | **English throughout.** Code comments were already English-only | 2026-08-22 |
| 4 | Repository host and CI | **GitHub with GitHub Actions.** Needed for the Windows and macOS runners at M4 | 2026-08-22 |

Consequences already applied: every document is in English, `Coordinator` is now `Brokr` everywhere, `proto/tradr/v1/` replaces `proto/watari/v1/`, crates are named `tradr-*`, the mDNS service type is `_tradr._udp`, the URL scheme is `tradr://`, Brokr environment variables are `BROKR_*`, and domain-separation strings are `tradr-*-v1`.

### Open

| # | Decision | Needed by | Who decides |
|---|---|---|---|
| 5 | **Google Cloud project and OAuth client IDs**, desktop and Android | **M0 completion** | User |
| 6 | Implementer model tier. `.claude/agents/implementer.md` currently says `sonnet`; Haiku 4.5 is cheaper but likely costs more in `REVISE` cycles on Rust work | M0's first Work Item | User, or measured |
| 7 | Distribution channels: Play Store, F-Droid, direct APK. Affects how permissions must be justified | M2 | User |
| 8 | Code-signing certificates: Apple Developer Program and Authenticode. Procurement takes weeks | M2 start | User |
| 9 | Whether same-account transfers auto-accept by default | M1 | Decide from how it feels |
| 10 | Whether one device may hold several Google accounts | M6 | User |
| 11 | Transfer history retention, and the default write limit for a writable Share | M3 | Open |

Decision 5 is the only one blocking M0.

---

## Milestones

From [docs/09-roadmap-and-risks.md](docs/09-roadmap-and-risks.md).

| # | Content | Estimate | Status |
|---|---|---|---|
| **M0** | **Skeleton** — monorepo, Tauri launching on Linux and Android, Google sign-in, key generation, Attestation issue and verify | 2 weeks | **next** |
| M1 | **LAN transfer**, the most important — mDNS, QUIC, transfer, resumption, drag-and-drop send | 4 weeks | todo |
| M2 | Android integration — share sheet, Sharing Shortcuts, SAF, permissions | 3 weeks | todo |
| M3 | Share browsing — VFS, boundary enforcement, the Browse plane | 3 weeks | todo |
| M4 | Windows and macOS — builds, signing, auto-update, tray | 3 weeks | todo |
| M5 | Static Peers and overlay networks — direct over Tailscale | 1 week | todo |
| M6 | Account linking — QR, Link Secret, Fingerprint | 2 weeks | todo |
| M7 | BLE, the largest estimation risk — advertising and scanning on four platforms, EIDs, Noise over GATT | 4-5 weeks | todo |
| M8 | Brokr — presence, rendezvous, relay, FCM, revocation list | 3 weeks | todo |
| M9 | Finishing — security review, store submission, packaging, i18n | ongoing | todo |

### Current milestone: M0, the skeleton

**Design**: [docs/02-architecture.md](docs/02-architecture.md), [docs/05-security.md](docs/05-security.md)

**Done when**: two devices exchange Attestations by hand and each verifies the other.

**Decision point at the end of M0** — evaluate [ADR-0001](docs/adr/0001-tauri-2-as-app-shell.md)'s withdrawal conditions. Failing any of these means switching to Electron with Kotlin.

- [ ] The Tauri 2 Android build passes reliably in CI
- [ ] Bidirectional calls work: Kotlin plugin into Rust, Rust back into Kotlin
- [ ] Android `ACTION_SEND` arrives through the Tauri plugin

Also walk Change Drill D9 — moving from Tauri to Electron — on paper at the end of M0.

#### Work Items

| ID | Content | Status | Critical |
|---|---|---|---|
| WI-M0-000 | Repository init: `git init`, `LICENSE`, `.gitignore`, GitHub remote, initial commit | in-progress — local done, remote pending | |
| WI-M0-001 | Monorepo skeleton: pnpm and Cargo workspaces, code generation from `proto` | todo | |
| WI-M0-002 | Required CI jobs: lint, test, comment-lang, comment-length, excuse-grep, layer-deps | todo | |
| WI-M0-003 | The Tauri 2 app launches on Linux | todo | |
| WI-M0-004 | The Tauri 2 app launches on Android — evidence for ADR-0001 | todo | |
| WI-M0-005 | Bidirectional Kotlin and Rust calls — evidence for ADR-0001 | todo | |
| WI-M0-006 | Layer 0 and 1 types and traits: `Transport`, `Vfs`, `KeyStore`, `Clock`, `Rng` | todo | |
| WI-M0-007 | Key generation and OS key store storage — Linux Secret Service, Android Keystore | todo | Yes |
| WI-M0-008 | Google OAuth on desktop: loopback with PKCE | todo | |
| WI-M0-009 | Google OAuth on Android: Custom Tabs with AppAuth | todo | |
| WI-M0-010 | **Attestation verification tests, written first** — the Supervisor writes these | todo | Yes |
| WI-M0-011 | Attestation issue, with the public keys in the nonce, and verification | todo | Yes |

WI-M0-010 completes **before** WI-M0-011. That is the Critical Module discipline, [CLAUDE.md](CLAUDE.md) §6.

WI-M0-006 sits early because without the Layer 1 traits in place, later implementations bind to concrete types. Violations of B1 through B7 are expensive to unwind afterwards.

WI-M0-002 puts every required CI job in at M0. Introducing `layer-deps` and `excuse-grep` later means facing a pile of existing violations, which neutralizes them.

---

## Design changes

Design changes arising during implementation. Every DCR must have a matching `docs/` diff.

| DCR | Content | Reflected in | Date |
|---|---|---|---|
| — | None yet | | |

### Major changes during the design phase, for reference

| Change | Reflected in |
|---|---|
| The backend went from required to optional; authentication was rebuilt around Attestations and the three tiers introduced | [ADR-0003](docs/adr/0003-google-attestation-as-trust-root.md), [ADR-0005](docs/adr/0005-brokr-is-optional.md), every design document |
| BLE was removed from bulk transfer and limited to discovery, authentication, and payloads under 512 KiB | [ADR-0002](docs/adr/0002-ble-for-discovery-and-small-payloads.md), [docs/03](docs/03-discovery-and-transport.md) |
| Named Tradr and Brokr; all documentation translated to English | Every file |

---

## Deferred

Things consciously postponed. **These live here, not in TODO comments in the code.**

| # | Content | When | Source |
|---|---|---|---|
| DF-1 | Desktop drag-out, pulling a peer's file into a file manager. A download button substitutes | After M9 | [docs/08](docs/08-platform-integration.md) |
| DF-2 | Shell integration: Windows context menu, macOS share menu, Linux `.desktop` | Phase 3 | [docs/08](docs/08-platform-integration.md) |
| DF-3 | Post-quantum migration. Write an ADR once `rustls` X25519MLKEM768 and hybrid Noise are both stable | Undecided | [docs/05](docs/05-security.md) |
| DF-4 | Android 14+ `ChooserAction` custom actions. Sharing Shortcuts suffice for v1 | Undecided | [docs/08](docs/08-platform-integration.md) |

---

## Risk status

From [docs/09](docs/09-roadmap-and-risks.md). Update as implementation proceeds.

| # | Risk | Likelihood | Status |
|---|---|---|---|
| R1 | BLE peripheral role means four separate implementations | High | Not started. M7's first week goes to connectivity checks |
| R2 | Tauri 2's Android maturity | Medium | **Decided at M0**, via WI-M0-004 and WI-M0-005 |
| R8 | Brokr-free operation breaks as features are added | High | Make CI's `no-brokr` job required from M1 |
| R9 | macOS and Windows signing procurement takes weeks | Medium | Needs starting before M4. Re-check at the start of M2 |

R9 has a procurement lead time, so it cannot wait for M4. Revisit when M2 begins.

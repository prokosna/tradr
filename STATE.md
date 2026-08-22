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

**Design is complete; implementation has not started.** Design documents `docs/01`-`10`, eleven ADRs, and five protobuf files are in place. Everything is in English and carries the final names.

Before starting M0, resolve the open decisions below.

## Next three actions

1. **Write the Work Order for WI-M0-001b**, the pnpm workspace and the four TypeScript packages. Nothing blocks it
2. **Close decision 13, the identity curve, before WI-M0-007.** The blocking unknown is whether the chosen Noise crate can perform P-256 DH through an external `agree`, as [ADR-0011](docs/adr/0011-keystore-exposes-operations.md) requires. Establish that first; the decision follows from it
3. **Keep measuring decision 6.** One Work Item is not a sample; see the record under that decision below

Implementation has begun. Decision 13 has until WI-M0-007. Creating the GitHub repository and pushing waits until local-only work ends.

### Review record

| WI | Verdict | REVISE cycles | Cause |
|---|---|---|---|
| WI-M0-001 | PASS | 1 | The Work Order, not the Implementer. It said to copy a crate's doc line verbatim from the `docs/02` layout table; that table's row for `tauri-plugin-tradr` begins "Exposes the above", which points at nothing once lifted out of the table |

Checklist items D (tests) were **not applicable** rather than skipped: WI-M0-001 creates no executable code and is not a Critical Module. Its Definition of Done carried no test item.

**Lesson recorded for future Work Orders: never instruct verbatim copying out of a document into code.** Prose written for a table depends on the table.

## In flight

```yaml
work_items: []
blocked: []
```

**The original WI-M0-001 was re-cut into three**, since one skeleton covering both workspaces plus code generation exceeded the 8-file guide in [docs/10](docs/10-implementation-process.md#the-unit-of-work-the-work-item) by roughly threefold. `WI-M0-001c` depends on both of the other two.

`WI-M0-001` itself creates 14 files, above the guide, and that is accepted rather than split further: the six crates' dependency edges **are** the architecture, and declaring them in one reviewable unit is what makes `layer-deps` meaningful from its first run. Total content is under 150 lines.

---

## Decisions

### Settled

| # | Decision | Choice | Date |
|---|---|---|---|
| 1 | Product name | **Tradr** for the app, **Brokr** for the self-hosted server process | 2026-08-22 |
| 2 | Repository visibility and licence | **Public, Apache-2.0** | 2026-08-22 |
| 3 | Documentation language | **English throughout.** Code comments were already English-only | 2026-08-22 |
| 4 | Repository host and CI | **GitHub with GitHub Actions.** Needed for the Windows and macOS runners at M4 | 2026-08-22 |
| 5 | Google OAuth clients | **Created.** Values below. The consent screen stays in Testing until release | 2026-08-22 |
| 12 | The desktop client secret in a public repository | **Committed, with a runtime override.** See [docs/05](docs/05-security.md#oauth-client-configuration) | 2026-08-22 |

Consequences already applied: every document is in English, `Coordinator` is now `Brokr` everywhere, `proto/tradr/v1/` replaces `proto/watari/v1/`, crates are named `tradr-*`, the mDNS service type is `_tradr._udp`, the URL scheme is `tradr://`, Brokr environment variables are `BROKR_*`, and domain-separation strings are `tradr-*-v1`.

### Open

| # | Decision | Needed by | Who decides |
|---|---|---|---|
| 6 | Implementer model tier. `.claude/agents/implementer.md` currently says `sonnet`; Haiku 4.5 is cheaper but likely costs more in `REVISE` cycles on Rust work. **After WI-M0-001: one REVISE, attributable to the Work Order rather than the model. No evidence against `sonnet` yet, and none for dropping to Haiku either — a skeleton exercises nothing.** Revisit after WI-M0-006 | M0's end | User, or measured |
| 7 | Distribution channels: Play Store, F-Droid, direct APK. Affects how permissions must be justified | M2 | User |
| 8 | Code-signing certificates: Apple Developer Program and Authenticode. Procurement takes weeks | M2 start | User |
| 9 | Whether same-account transfers auto-accept by default | M1 | Decide from how it feels |
| 10 | Whether one device may hold several Google accounts | M6 | User |
| 11 | Transfer history retention, and the default write limit for a writable Share | M3 | Open |
| 13 | **The identity curve.** Ed25519 + X25519 as designed, or P-256 throughout. P-256 is the only curve the macOS Secure Enclave, a Windows TPM, and Android StrongBox all protect, so the present choice forfeits hardware backing on three platforms. Blocked on whether the Noise crate supports P-256 DH through an external `agree`. See [docs/05](docs/05-security.md#hardware-backing-and-the-curve) | **WI-M0-007** | Supervisor, after the Noise check |

**Decision 13 is the one with a deadline inside M0.** A Device ID is `BLAKE3(public key)[0..16]`, so deciding after keys exist invalidates every Device ID, pinned Fingerprint, and stored ABK at once. Its blast radius includes `DeviceInfo.ed25519_pub` in `proto/tradr/v1/common.proto`, which is why that field has not been renamed pre-emptively.

The other outstanding input is the desktop client secret's value, which WI-M0-008 needs.

#### Toolchain present on the development machine

Checked 2026-08-22: `cargo` and `rustc` 1.98.0, `pnpm` 10.20.0, `node` v24.11.0. **Neither `protoc` nor `buf` is installed as a system binary.**

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

A debug keystore is machine-local, so the SHA-1 a GitHub Actions runner produces differs from the one on a developer machine and OAuth will refuse it. **This will surface during WI-M0-004.**

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
| WI-M0-001 | Cargo workspace and the six crates, with the dependency edges of [docs/02](docs/02-architecture.md#direction-of-dependency) and no external crates | **done** — PASS after one REVISE | |
| WI-M0-001b | pnpm workspace and the four TypeScript packages | todo | |
| WI-M0-001c | Code generation from `proto`: prost for Rust, ts-proto for TypeScript | todo | |
| WI-M0-002 | Required CI jobs: lint, test, comment-lang, comment-length, excuse-grep, layer-deps | todo | |
| WI-M0-003 | The Tauri 2 app launches on Linux | todo | |
| WI-M0-004 | The Tauri 2 app launches on Android — evidence for ADR-0001 | todo | |
| WI-M0-004a | Register the CI runner's debug keystore SHA-1 on the Android OAuth client — see the note below | todo | |
| WI-M0-005 | Bidirectional Kotlin and Rust calls — evidence for ADR-0001 | todo | |
| WI-M0-006 | Layer 0 and 1 types and traits: `Transport`, `Vfs`, `KeyStore`, `Clock`, `Rng`. **`KeyStore` is operation-shaped per [ADR-0011](docs/adr/0011-keystore-exposes-operations.md); no method returns key material** | todo | |
| WI-M0-007 | Key generation and OS key store storage — Linux Secret Service, Android Keystore. **Blocked on decision 13** | todo | Yes |
| WI-M0-008 | Google OAuth on desktop: loopback with PKCE | todo | |
| WI-M0-009 | Google OAuth on Android: Custom Tabs with AppAuth | todo | |
| WI-M0-010 | **Attestation verification tests, written first** — the Supervisor writes these. Must cover profile selection by exact `iss`, rejection of an unknown `iss`, and `(iss, sub)` pair comparison | todo | Yes |
| WI-M0-011 | Attestation issue, with the public keys in the nonce, and verification | todo | Yes |

WI-M0-010 completes **before** WI-M0-011. That is the Critical Module discipline, [CLAUDE.md](CLAUDE.md) §6.

WI-M0-006 sits early because without the Layer 1 traits in place, later implementations bind to concrete types. Violations of B1 through B7 are expensive to unwind afterwards.

WI-M0-002 puts every required CI job in at M0. Introducing `layer-deps` and `excuse-grep` later means facing a pile of existing violations, which neutralizes them.

---

## Design changes

Design changes arising during implementation. Every DCR must have a matching `docs/` diff.

| DCR | Content | Reflected in | Date |
|---|---|---|---|
| DCR-001 | Account identity becomes the `(iss, sub)` pair, and provider-specific knowledge is confined to a Provider Profile. Every derived value — `account_tag`, the bootstrap EID secret, link records — takes `account_id = iss \|\| 0x00 \|\| sub` | [ADR-0010](docs/adr/0010-identity-is-the-issuer-subject-pair.md), [docs/05](docs/05-security.md), [CONTEXT.md](CONTEXT.md), docs/02, 03, 06, 07, `proto/` | 2026-08-22 |
| DCR-004 | Change Drill D9 demanded `crates/` be untouched when moving off Tauri, which no layout can satisfy — the composition root must name a shell. D9 now budgets one binding crate, checkable with `grep -ril tauri crates/` | [CLAUDE.md](CLAUDE.md) §4-C | 2026-08-22 |
| DCR-003 | The crate dependency diagram in docs/02 pointed outward from `tradr-core`, contradicting B3 and I4. Split into a call-flow diagram and a crate-dependency diagram; every crate edge now points at `tradr-core` | [docs/02](docs/02-architecture.md#direction-of-dependency) | 2026-08-22 |
| DCR-002 | `KeyStore` exposes operations and never key material, since a key in StrongBox, a TPM, or the Secure Enclave cannot be read out. The curve question this exposes becomes open decision 13 | [ADR-0011](docs/adr/0011-keystore-exposes-operations.md), [docs/05](docs/05-security.md), docs/08 | 2026-08-22 |

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

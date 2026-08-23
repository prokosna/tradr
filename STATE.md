# STATE

> **Only the Supervisor edits this file.** Update it after each review, before anything else.
> An arriving Supervisor reads this first, then runs `git log --oneline -20` to see what happened after `last_updated`.
> **Commits newer than `last_updated` mean the first job is reconciling this file.**

```yaml
last_updated: 2026-08-22
phase: implementing
current_milestone: M0
implementation_started: true
work_items_landed: 17
last_commit: 1c177e9
repo_initialized: true (local only, no remote yet)
```

---

## Where we are

**M0 is under way and nothing is blocked.** Seventeen Work Items have landed, and **every Layer 1 trait now exists**: `Clock`, `Rng`, `KeyStore`, `Vfs`, `SecureChannel`, `Transport` and the streams, every one reviewed against the §4 checklist before its commit: both workspaces, code generation, the CI checks, the Layer 0 domain types, the Layer 1 traits, and the Tauri shell building and now **running** on Linux and Android.

`crates/` holds `tradr-core` with no dependency at all, and six other crates whose edges all point at it. `ci/run-all.sh` enforces that mechanically, along with Change Drills D5 and D9.

**The build environment is complete.** WebKitGTK, the Android SDK, NDK r27, the four Android Rust targets, JDK 21 and a booting emulator are all in place — see Build environment below, which also lists three traps that produce misleading errors.

**The app runs on Android.** WI-M0-004b installed the APK on the emulator and the React frontend rendered inside the WebView. Two of [ADR-0001](docs/adr/0001-tauri-2-as-app-shell.md)'s three withdrawal conditions remain open, and neither is blocked.

Eighteen DCRs have been raised since design "finished". Six of them fixed defects that would have been expensive after implementation: an `aud` compared as a scalar, a dependency diagram that inverted the architecture, sender-chosen strings used as path components, identity-key signatures with no domain separation — that one let a Brokr impersonate a device — a layout table that put a Layer 1 trait in a Layer 3 crate, and a filename able to disguise its own extension.

## Next three actions

1. **WI-M0-005**, bidirectional Kotlin and Rust calls. The second of ADR-0001's three withdrawal conditions, and the only one testable without CI. `println!` under the `RustStdoutStderr` logcat tag is the observation channel
2. **WI-M0-007**, key generation and OS key store storage. Settled as a **Critical Module** by DCR-018, so **the Supervisor writes its tests first**, as for `ItemId` and `RelPath`. A software `KeyStore` driven by a pinned `Rng` is what those tests exercise
3. **WI-M0-010**, the Attestation verification tests, which the Supervisor writes before WI-M0-011 implements against them — the second withdrawal condition, and the only remaining one testable locally. `println!` under the `RustStdoutStderr` logcat tag is the observation channel

Decisions 13, 15 and the environment are closed. **Decision 16 must be settled before a second transport lands**, since it asks whether Change Drill D10's budget survives contact with the capability bitmask. Creating the GitHub repository and pushing waits until local-only work ends.

### Review record

| WI | Verdict | REVISE cycles | Cause |
|---|---|---|---|
| WI-M0-006g | PASS | 1 | `Transport`, `Candidate` and the listening side, closing out the Layer 1 traits. **The REVISE was for a test that could not fail in the direction that matters.** Mutating `Candidate::new` to also reject an address containing a space left all six tests green — and over-rejection is the failure mode that hides: an address the core wrongly refuses presents as a transport that never establishes, diagnosed as a network fault or an offline peer, never as a validation rule three layers away. My Definition of Done named four addresses to accept and none touched the boundary; the table now holds thirteen shapes the five transports actually produce. `Candidate::new` was not changed and did not need to be — it already accepted all thirteen. **My own check was inert for `Incoming`**, since it exercised `connect` and never `listen`, the same mistake as WI-M0-006f in a new place. Fixed, then five mutations caught: three over-rejections I invented, plus removing each of the two checks |
| WI-M0-006e | PASS | 0 | `SecureChannel` and the stream traits. **The compiled shape I handed over failed clippy**: `open_bi` and `accept_bi` returning `(Box<dyn SendStream>, Box<dyn RecvStream>)` trip `type_complexity` under `-D warnings`. The Implementer took clippy's own suggested fix, a private `type BiStreams` alias that changes no signature and is not re-exported, rather than the `#[allow]` the rules forbid. **That is a hole in how I verify a shape**: I compile a probe with `cargo build`, which lints nothing, so a shape can pass my check and fail the project's gate. Probes now run `cargo clippy -- -D warnings`. My independent check ran from outside the crate with every bound coming from the traits, and caught all six mutations: dropping `Send` or `Sync` from `SecureChannel`, `Send` from either stream trait, `const` from `TransportId::new`, and `Hash` from `TransportId` |
| WI-M0-002b | PASS | 0 | The wire half of DCR-015, and the first Work Item run in parallel with another. **My Definition of Done was impossible**: it required `cargo clippy --workspace` and `sh ci/run-all.sh` to be clean, which they cannot be while a second Work Item has uncommitted code in the same tree. The Implementer scoped to `-p tradr-proto`, said plainly that the workspace-wide gates fail, and named the other Work Item's file as the cause rather than reporting a clean bill it could not support. **I verified the zero-cost claim myself rather than reading it**: 60 bytes with the field defaulted, 60 with it explicitly zero, 64 with it set — matching the report exactly. And I checked the assertion could fail, by setting the test's non-zero case to zero and watching it report `default=60, non_zero=60`. Two proto mutations were caught: deleting field 7, and renumbering it onto `payload_len`'s 4 |
| WI-M0-006f | PASS | 1 | The `Vfs` trait, shaped by [ADR-0014](docs/adr/0014-vfs-exposes-operations-never-paths.md). **I compiled the trait shape before writing the Work Order**, which is why the round-trip found contracts rather than type errors. Two of the three findings were unstated contracts that only bite later: `open_write` never truncates — `File::create` is the obvious call and it would silently destroy everything a resumed transfer had already received — and `remove` never recurses, since a `RelPath` is peer-influenced. The third was mine: my Work Order named `std::task::Wake` when `Waker::noop()` has been stable since 1.85, so the Implementer had to add an `#[allow]` suppressing a lint that was correct. `grep -rn 'allow(' crates/` now returns nothing and that is the standard. **My own verification tool could not fail at first**: I checked `Arc<dyn Vfs + Send + Sync>`, which supplies the bounds at the use site, so it proved nothing about the trait. Rewritten as `Arc<dyn Vfs>`, it now catches all three of dropping `Send` from `Vfs`, `Sync` from `Vfs`, and `Send` from `BoxFuture` |
| WI-M0-006d | PASS | 1 | The second Critical Module, tests written first as for `ItemId`. **The REVISE was mine**: `char::is_control()` returns false for every bidirectional control, so the documented rule let `report\u{202E}fdp.exe` through, which renders to the user as `reportexe.pdf`. The implementation matched docs/04 exactly; docs/04 was wrong (DCR-013). The Implementer also found that **my own test file failed two of my own CI checks**, and declined to add the `ci/allowlist.txt` entry that would have turned the suite green, on the grounds that suppressing a check against the Supervisor's spec file is a process call. It is, and the fix was to rewrite my prose rather than touch either check. **I mutation-tested the result: nine mutations, eight caught.** The ninth, removing the absolute-path check, survived — and is an equivalent mutant rather than a gap, since a leading `/` always produces an empty first component which `EmptyComponent` rejects. Established by differential testing over 28,561 generated strings, not by argument. Four of the nine mutations tested **over-rejection**, which is the failure mode that matters here: rejecting `con`, trimming trailing dots, widening the bidi range over `U+200E`, and applying the drive check per component were all caught |
| WI-M0-004b | PASS | 0 | **The app runs on Android.** The Implementer reported the screen as "a mostly blank white screen" with one line of text and explicitly declined to judge whether that counted as success, saying the call needed someone who knew what the frontend should produce. That was the right call and the answer is that it is a complete render: `apps/tradr/index.html` contains only an empty `<div id="root">`, and the `<h1>Tradr</h1>` on screen exists nowhere but inside the React bundle. **Its presence proves the whole chain** — asset protocol, HTML, module script, React mount, DOM — which a WebView fallback page or a failed script load could not produce. `primaryCpuAbi=x86_64` confirms the ABI claim from WI-M0-004 was not merely present in the archive but selected and used. The negative control was run properly: after `am force-stop`, the same `pidof` and `dumpsys` commands report the process gone and the launcher resumed instead |
| WI-M0-001 | PASS | 1 | The Work Order, not the Implementer. It said to copy a crate's doc line verbatim from the `docs/02` layout table; that table's row for `tauri-plugin-tradr` begins "Exposes the above", which points at nothing once lifted out of the table |
| WI-M0-004 | PASS | 0 | Evidence for ADR-0001, and the richest so far. **The build failed first on the environment**, not on the code: Gradle 8.14.3 cannot read Java 25 class files and says only `Unsupported class file major version 69`, naming neither Java nor a version that works. Raising Gradle is not the fix, since the Android Gradle Plugin does not support Java 25 either. The Implementer stopped and reported rather than switching JDKs or bumping Gradle on its own, which kept an environment problem from being buried as an implementation one. **I verified the artifact rather than the report**: all four ABIs are present including `x86_64`, so the emulator can take it, and `apksigner` reports SHA-1 `9c95332f9bd8e7f47f2d5b763a4d688c33623a1b`, which matches the debug keystore fingerprint already registered on the Google OAuth client. The 40 files staged under `gen/` are Gradle sources with no build output among them. **The debug APK is 464 MB**, roughly 120 MB per ABI of unstripped native library |
| WI-M0-003 | PASS | 0 | Evidence for [ADR-0001](docs/adr/0001-tauri-2-as-app-shell.md). `cargo tauri build` succeeded and the binary was verified to launch: **exit 124 under `xvfb-run`, meaning still running, against exit 101 with no display, meaning it died** — I reproduced both rather than reading them, since a launch check that cannot tell a live window from a crash proves nothing. Two pieces of friction were reported unprompted and both were worth having: `cargo tauri build` **rewrites `src-tauri/Cargo.toml`** to add feature lists, so a build dirties a version-controlled file; and the AppImage bundler **downloads five unpinned executables** at build time, now recorded as risk R11 and folded into decision 7 |
| WI-M0-006c | PASS | 1 | ADR-0011 and ADR-0012 became code without friction. The REVISE came from the Implementer's own honest flag: doc coverage was the one Definition of Done item verified by hand rather than by a gate. `#![deny(missing_docs)]` compiled clean the moment it went in, which is the argument for adding it at zero violations rather than later at many. Verified by deleting a `///` and watching `cargo check` exit 101. **I recomputed the `DomainTag` prefix relation myself** rather than trusting the test that checks it, since DCR-009's whole defence rests on it |
| WI-M0-006b | PASS | 0 | The first Critical Module. Tests were written first, in `crates/tradr-core/tests/item_id.rs`, and handed over not compiling. **I then mutation-tested my own tests against the implementation**: removing the length check, the alphabet check or the reserved-name check each broke tests; allowing uppercase broke tests; and making the reserved-name check a prefix match, which over-rejects `com0` and `com10`, also broke tests. The suite catches both directions. **`cargo fmt --check` failed on my test file, not on the Implementer's code**, and the Implementer reported it rather than editing an off-limits file or hiding the failure behind a green summary |
| WI-M0-006a | PASS | 1 | **`u8::from_str_radix("+f", 16)` returns `Ok(15)`.** Both `DeviceId::from_str` and `TransferId::from_str` therefore accepted a leading sign, so `"+f0102..."` and `"0f0102..."` parsed to the same value and the string form stopped being injective. At the time `TransferId` still named a directory under `.tradr-partial/`, so laxity ran the wrong way; DCR-008 has since removed sender-chosen values from those paths, but the aliasing was real regardless. Fixed by requiring ASCII hex digits before parsing |
| WI-M0-002a | PASS | 0 | Field numbers held, `grep -rn "ed25519\|x25519" proto/ crates/ packages/` returns nothing, and the six `tradr-proto` tests run with 65-byte fixtures. The Implementer also deleted a stale `Curve is open decision 13` comment I had left on the field, flagged it as a judgment call rather than making it silently, and was right: ADR-0012 closed that decision and the comment would have contradicted the change implementing it |
| WI-M0-001d | PASS | 0 | The boundary was verified rather than assumed: `document.title` fails in `brokr-client`, in `client-state`, and in `ui`, and `globalThis.atob` fails everywhere except `packages/protocol`, which alone carries `DOM`. I added the `ui` probe; the other three were asked for. **The report claimed `cargo test --workspace` found no tests in any crate, which is false** — `tradr-proto` has six and they pass. Harmless here, and a reminder that a green exit code and an accurate account of what ran are different claims |
| WI-M0-002 | PASS | 1 | **My error, caught by the Implementer before it could do harm.** The Work Order's `layer-deps` rule 4 said an implementation crate may depend on `tradr-core` alone, which contradicts `docs/02` — that document says `tradr-transport`, `tradr-identity` and `tradr-discovery` also depend on `tradr-proto` for wire encoding. The check would have failed on sanctioned work within a few Work Items, and the first person to hit it would have weakened it. Corrected to: an implementation crate may depend on `tradr-core` and `tradr-proto` and nothing else internal. What stays forbidden is one implementation crate depending on another, which is the case that breaks D3 |
| WI-M0-001c | PASS | 2 | The second cycle was **my error, not the Implementer's**. I rejected `DOM` in `tsconfig.base.json` and directed `@types/node` instead; `@types/node` only re-exports `atob`/`btoa` from `globalThis` and cannot supply them. The Implementer stopped as instructed, quoted `buffer.d.ts:1793`, and did not improvise a third option — which is why one round settled it. `DOM` was restored deliberately and WI-M0-001d cut against it |
| WI-M0-001b | PASS | 1 | **A gate that could not fail.** `pnpm lint` exited 0 with a lint violation present, because Biome reports rule hits as warnings. WI-M0-002 was about to wire that script into CI as a required job. Fixed with `--error-on-warnings`, and confirmed by breaking it: dirty tree exits 1, clean tree exits 0. A second, minor finding converted the four package headers from `//` to JSDoc, matching the Rust crates' `//!` and moving them from checklist A3 to A5 |

**Two Work Orders in three have carried an error of mine, and in both cases the cost was one REVISE cycle, not a wrong implementation.** The pattern that keeps it cheap: the Work Order names the constraint it is protecting, and says to stop and report rather than work around a blocker. An Implementer told *why* a rule exists stops at the right place; one given only the rule improvises.

**Breaking a check proves the test notices the check is gone. It does not prove the check is complete.** WI-M0-006a is the example: the Implementer had a negative test for a non-hex character, verified it correctly by removing the check and watching it fail, and it still missed `+` — because the test used a character someone chose. The fix was to demand a **property** instead of a list: for any string `FromStr` accepts, `Display` of the result must equal the input lowercased. A property rules out the class; a list rules out what was thought of.

**Mutate the review's own instruments, not only the code under review.** WI-M0-006g's round caught two things in one pass: a test suite that could not detect over-rejection, and a Supervisor check that never exercised `Incoming` and so could not detect that trait losing `Send`. Running mutations against both at once is what surfaced the second, and it was the same mistake as WI-M0-006f's in a different place.

**A shape verified by compiling is not a shape verified.** WI-M0-006e's traits were probed with `cargo build`, which runs no lints, so the shape I handed over tripped `type_complexity` the moment it met the project's `-D warnings` gate. **Shape probes run `cargo clippy -- -D warnings`.** The Implementer resolved it with clippy's own suggestion rather than the suppression the rules forbid, which is the outcome worth having, but the round should not have needed the judgment.

**Two Work Items in one tree means neither can be gated on the workspace.** WI-M0-002b's Definition of Done demanded `cargo clippy --workspace` and `sh ci/run-all.sh`, and both failed on a file belonging to the Work Item running beside it. **A parallel Work Item's gates scope to its own crates** — `cargo clippy -p <crate>` — and the workspace-wide run happens at the Supervisor's commit, once the tree holds one Work Item's changes again.

**A check written to confirm something confirms nothing until it has been made to fail.** This applies to the Supervisor's own tools, not only to the Implementer's. WI-M0-006f's independent `Send + Sync` check was written as `Arc<dyn Vfs + Send + Sync>`, which supplies both bounds at the use site and therefore holds whatever the trait declares. It passed, and it would have passed against a trait with no supertraits at all.

**A surviving mutation is a question, not a verdict.** WI-M0-006d's absolute-path check can be deleted with every test still green, which looks exactly like a hole in the suite and is not one: any leading `/` produces an empty first component, so `EmptyComponent` rejects the same set. Confirmed by running both versions over 28,561 generated strings and comparing acceptance, which is the only way to tell an equivalent mutant from a gap. Deciding it by reading the code would have been a guess either way.

**Every tooling gate gets broken on purpose before it is trusted.** WI-M0-001b is the reason this is written down: both the Implementer and a reading of the command output said the lint gate worked, and it did not. E1's discipline applies to tooling, not only to tests.

The root `tsconfig.json` in WI-M0-001b is the one thing added that the Definition of Done did not name. It is accepted: `pnpm typecheck` was a Definition of Done item and needs a project file to run against.

Checklist items D (tests) were **not applicable** rather than skipped: WI-M0-001 creates no executable code and is not a Critical Module. Its Definition of Done carried no test item.

**Lesson recorded for future Work Orders: never instruct verbatim copying out of a document into code.** Prose written for a table depends on the table.

## In flight

```yaml
work_items: []
blocked: []
```

**Nothing is in flight and nothing is blocked.** The emulator AVD `tradr-test` may still be running from WI-M0-004's session; check with `adb -s emulator-5556 get-state` before assuming either way.

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
| 17 | Whether checklist A5, doc comments on public API only, governs `tests/` | **No, it governs crate source.** Every item in an integration test is private, so reading A5 literally would ban explanatory comments from test files, which inverts its purpose: A5 exists to stop private implementation from accumulating API-shaped documentation. Raised by the Implementer on WI-M0-006f rather than settled by inventing a third convention | 2026-08-23 |
| 15 | What `ChunkData.chunk_index` counts when a transport subdivides | **Reference chunks, always**, with a new `offset_in_chunk` field beside it. Stream order was rejected: `ble-gatt` cannot promise it, and the offset feeds verification. See DCR-015 | 2026-08-23 |
| 14 | TypeScript lint and format tooling | **Biome.** One tool covering both, no plugin matrix to keep aligned. Reason to withdraw: if a React rule ESLint has and Biome lacks catches a real bug in review, revisit at M2 | 2026-08-22 |
| 13 | The identity curve | **P-256 throughout**, ECDSA for signing and ECDH for agreement. Wire fields are named for their role, `identity_pub` and `agreement_pub`. See [ADR-0012](docs/adr/0012-p256-for-device-keys.md) | 2026-08-22 |
| 12 | The desktop client secret in a public repository | **Committed, with a runtime override.** See [docs/05](docs/05-security.md#oauth-client-configuration) | 2026-08-22 |

Consequences already applied: every document is in English, `Coordinator` is now `Brokr` everywhere, `proto/tradr/v1/` replaces `proto/watari/v1/`, crates are named `tradr-*`, the mDNS service type is `_tradr._udp`, the URL scheme is `tradr://`, Brokr environment variables are `BROKR_*`, and domain-separation strings are `tradr-*-v1`.

### Open

| # | Decision | Needed by | Who decides |
|---|---|---|---|
| 6 | Implementer model tier. `.claude/agents/implementer.md` currently says `sonnet`; Haiku 4.5 is cheaper but likely costs more in `REVISE` cycles on Rust work. **After eleven Work Items: seven REVISE cycles, three of them caused by my Work Order rather than by the model.** `sonnet` stopped at the right place every time it was blocked, flagged every addition beyond a Definition of Done, and never worked around a constraint. No evidence against it; no evidence for dropping to Haiku either, since nothing so far has been hard. Revisit at M0's end | M0's end | User, or measured |
| 7 | Distribution channels: Play Store, F-Droid, direct APK, and **whether Linux ships AppImage at all**. AppImage bundling downloads unpinned executables at build time; `deb` and `rpm` do not. See [docs/09](docs/09-roadmap-and-risks.md#risks) R11. Also affects how Android permissions must be justified | M2 | User |
| 8 | Code-signing certificates: Apple Developer Program and Authenticode. Procurement takes weeks | M2 start | User |
| 9 | Whether same-account transfers auto-accept by default | M1 | Decide from how it feels |
| 10 | Whether one device may hold several Google accounts | M6 | User |
| 11 | Transfer history retention, and the default write limit for a writable Share | M3 | Open |
| 16 | **Whether a new transport can be added within Change Drill D10's budget.** D10 allows one implementation, one registration and one weight-table entry. But [docs/03](docs/03-discovery-and-transport.md#capability-flags) assigns each transport a fixed capability bit on the wire, so a new transport also needs a `proto/` change — a fourth file, and one in the Adapter layer. Either D10's budget is wrong or capability flags should not enumerate transports | Before M7's BLE work, and before any second transport lands | Supervisor |

The one outstanding input is the desktop client secret's value, which WI-M0-008 needs.

#### Build environment, Ubuntu 24.04.4 LTS

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
| **M0** | **Skeleton** — monorepo, Tauri launching on Linux and Android, Google sign-in, key generation, Attestation issue and verify | 2 weeks | **in progress, 11 Work Items landed** |
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

- [ ] The Tauri 2 Android build passes reliably in CI — **builds and runs here** (WI-M0-004: all four ABIs, correctly signed; WI-M0-004b: installs, launches, and renders the frontend). Unchecked because no CI has run it yet, and CI is where "reliably" gets tested
- [ ] Bidirectional calls work: Kotlin plugin into Rust, Rust back into Kotlin — WI-M0-005
- [ ] Android `ACTION_SEND` arrives through the Tauri plugin — not yet cut

Also walk Change Drill D9 — moving from Tauri to Electron — on paper at the end of M0.

#### Work Items

| ID | Content | Status | Critical |
|---|---|---|---|
| WI-M0-000 | Repository init: `git init`, `LICENSE`, `.gitignore`, GitHub remote, initial commit | in-progress — local done, remote pending | |
| WI-M0-001 | Cargo workspace and the six crates (a seventh, `tradr-proto`, arrives with WI-M0-001c per DCR-005), with the dependency edges of [docs/02](docs/02-architecture.md#direction-of-dependency) and no external crates | **done** — PASS after one REVISE | |
| WI-M0-001b | pnpm workspace and the four TypeScript packages | **done** — PASS after one REVISE | |
| WI-M0-001c | Code generation from `proto`: `protox` and `prost` for Rust into the new `tradr-proto`, npm `buf` and `ts-proto` for TypeScript | **done** — PASS after two REVISE | |
| WI-M0-002a | **Rename the wire fields to `identity_pub` and `agreement_pub`** in `proto/tradr/v1/`, and update `crates/tradr-proto/tests/roundtrip.rs` to match. Follows DCR-007. **The only Work Item so far permitted to edit `proto/`** | **done** — PASS, no REVISE | |
| WI-M0-001d | **TypeScript project references.** Each package compiles as its own program with its own `lib`, so a Node-hosted package cannot typecheck against browser globals | **done** — PASS, no REVISE | |
| WI-M0-002 | Required CI jobs: `lint`, `test`, and the four checks under `ci/`. `layer-deps` also runs the mechanical Change Drills D5 and D9 | **done** — PASS after one REVISE | |
| WI-M0-003 | The Tauri 2 app launches on Linux | **done** — PASS, no REVISE | |
| WI-M0-004 | The Tauri 2 Android build produces an installable APK — evidence for ADR-0001 | **done** — PASS, no REVISE. Re-cut to build-only; launching moved to WI-M0-004b | |
| WI-M0-004b | Install the APK on the emulator and confirm the app starts — the launch half of WI-M0-004 | **done** — PASS, no REVISE | |
| WI-M0-004a | Register the CI runner's debug keystore SHA-1 on the Android OAuth client — see the note below | todo | |
| WI-M0-005 | Bidirectional Kotlin and Rust calls — evidence for ADR-0001 | todo | |
| WI-M0-006a | Layer 0 domain types: `DeviceId`, `TransferId`, `ChunkIndex`, `TrustTier` | **done** — PASS after one REVISE | |
| WI-M0-006b | **`ItemId`**, validated as an opaque token. Critical Module: the Supervisor wrote the tests first | **done** — PASS, no REVISE | Yes |
| WI-M0-006c | Layer 1 traits: `KeyStore`, `Clock`, `Rng`. **`KeyStore` is operation-shaped per [ADR-0011](docs/adr/0011-keystore-exposes-operations.md); no method returns key material** | **done** — PASS after one REVISE | |
| WI-M0-006d | **`RelPath`**, the Layer 0 half of docs/06's step 2. Critical Module: the Supervisor wrote the tests first, as for `ItemId`. NFC normalization is explicitly **not** here, per DCR-012 | **done** — PASS after one REVISE | Yes |
| WI-M0-006f | Layer 1 trait: `Vfs`, per [ADR-0014](docs/adr/0014-vfs-exposes-operations-never-paths.md). Also `BoxFuture`, in its own module because `Transport` reuses it | **done** — PASS after one REVISE | |
| WI-M0-006e | Layer 1 traits: `SecureChannel` and the stream traits it hands out, plus `TransportId` and `TransportError` | **done** — PASS, no REVISE | |
| WI-M0-002b | **Add `offset_in_chunk` to `ChunkData`**, following DCR-015 as WI-M0-002a followed DCR-007. The second Work Item permitted to edit `proto/` | **done** — PASS, no REVISE | |
| WI-M0-006g | Layer 1 trait: `Transport`, plus `Candidate` and the listening side. **Completes WI-M0-006** | **done** — PASS after one REVISE | |
| WI-M0-007 | Key generation and OS key store storage — Linux Secret Service, Android Keystore. P-256 per [ADR-0012](docs/adr/0012-p256-for-device-keys.md); decision 13 is closed and this is unblocked | todo | Yes |
| WI-M0-008 | Google OAuth on desktop: loopback with PKCE | todo | |
| WI-M0-009 | Google OAuth on Android: Custom Tabs with AppAuth | todo | |
| WI-M0-010 | **Attestation verification tests, written first** — the Supervisor writes these. Must cover profile selection by exact `iss`, rejection of an unknown `iss`, and `(iss, sub)` pair comparison | todo | Yes |
| WI-M0-011 | Attestation issue, with the public keys in the nonce, and verification | todo | Yes |

WI-M0-010 completes **before** WI-M0-011. That is the Critical Module discipline, [CLAUDE.md](CLAUDE.md) §6.

WI-M0-006 sits early because without the Layer 1 traits in place, later implementations bind to concrete types. Violations of B1 through B7 are expensive to unwind afterwards.

**WI-M0-001d landed 2026-08-22.** `tsconfig.base.json` is back to `lib: ["ES2022"]` and `packages/protocol` alone carries `DOM`. The record of why it existed follows, because the reasoning applies to any future package that wants a compiler setting of its own.

**Why WI-M0-001d existed, and why it was not deferred.** `packages/protocol`'s generated code calls `globalThis.atob` and `globalThis.btoa`, which only `lib.dom.d.ts` declares — `@types/node` merely re-exports them from `globalThis` and cannot supply them on its own, which was checked in `buffer.d.ts` rather than assumed. `tsconfig.base.json` therefore carries `DOM`, and every package inherits it, including the Node-hosted `apps/brokr` when it arrives at M8. A `document.querySelector` inside the Brokr would typecheck and then fail at run time.

No small change fixes this: `pnpm typecheck` runs one `tsc` across `packages/*/src/**/*.ts`, so the per-package `tsconfig.json` files are inert and no per-package `lib` can take effect. Project references are what make them live.

**It runs while the packages are still empty.** Migrating four packages holding real code costs many times more than migrating four packages holding one `export {}` each, which is the whole reason this is not parked until `apps/brokr` needs it.

WI-M0-002 puts every required CI job in at M0. Introducing `layer-deps` and `excuse-grep` later means facing a pile of existing violations, which neutralizes them.

---

## Design changes

Design changes arising during implementation. Every DCR must have a matching `docs/` diff.

| DCR | Content | Reflected in | Date |
|---|---|---|---|
| DCR-001 | Account identity becomes the `(iss, sub)` pair, and provider-specific knowledge is confined to a Provider Profile. Every derived value — `account_tag`, the bootstrap EID secret, link records — takes `account_id = iss \|\| 0x00 \|\| sub` | [ADR-0010](docs/adr/0010-identity-is-the-issuer-subject-pair.md), [docs/05](docs/05-security.md), [CONTEXT.md](CONTEXT.md), docs/02, 03, 06, 07, `proto/` | 2026-08-22 |
| DCR-018 | **Device Key generation is a Critical Module**, and [CLAUDE.md](CLAUDE.md) §6's table did not list it while this file's Work Item table marked WI-M0-007 critical. The two disagreed, and the answer decides who writes the tests. It qualifies on §6's own test: a predictable key is a derivable key, which is impersonation by a second route, and a `backing()` that overstates itself makes docs/05's hardware promise false while failing nowhere. **The module that would otherwise notice, Attestation verification, is checking a signature that is perfectly valid.** Also named the crates for the filename-sanitization row, which is now split between `tradr-core` and `tradr-vfs` and was not when the row was written | [CLAUDE.md](CLAUDE.md) §6 | 2026-08-23 |
| DCR-017 | **A candidate address is opaque to the core, but not unchecked.** docs/03 said the core never parses one and said nothing about what it does check. A candidate can come from a Brokr, which docs/05's T4 does not trust, and it reaches logs and the UI before any transport sees it. The core now rejects an empty address and one carrying control characters, the two rules `item_id` already carries and for the same reason, and nothing else, since the rest is syntax only a transport knows. Validating that syntax is a contract on each transport implementation | [docs/03](docs/03-discovery-and-transport.md#what-the-core-knows-about-a-transport) | 2026-08-23 |
| DCR-016 | **An established channel reports its own frame-size limit.** docs/04 negotiates `max_frame_size` in `Hello`, at 1 MiB by default and 512 bytes over BLE, and that negotiation runs in Layer 1. Nothing said where the 512 comes from, and the only two answers are a per-transport table in `tradr-core` — the table DCR-011 exists to keep out of it — or a method on `SecureChannel`. The latter, since unlike a class weight a frame limit is a property of one path rather than a comparison between several | [docs/03](docs/03-discovery-and-transport.md#what-the-core-knows-about-a-transport) | 2026-08-23 |
| DCR-015 | **A subdivided chunk piece carries its own offset.** `ChunkData` had `chunk_index`, `payload_len` and `last` but nothing separating the second 256 KiB relay piece from the third, so correct resumption rested on arrival order that no document stated. `chunk_index` keeps counting reference chunks (invariant I6) and `offset_in_chunk` is added beside it. Rejected the free option — deriving the offset from stream order — because `ble-gatt` write-without-response guarantees neither order nor delivery, because the offset feeds verification and not only placement, so a misordering surfaces as three failed chunks and a blamed path, and because it would be an unwritten invariant under a Critical Module. Protobuf omits a zero scalar, so the field costs nothing on the QUIC paths. **Settles open decision 15.** `proto/` and the codec tests follow in a Work Item, as DCR-007 did | [docs/04](docs/04-protocol.md#where-a-subdivided-piece-belongs), [docs/09](docs/09-roadmap-and-risks.md) | 2026-08-23 |
| DCR-014 | **A transport delivers an already-secure channel, and no document said so.** `SecureChannel` appeared once in docs/05, in passing, and docs/02's list of Layer 1 traits omitted it. The gap matters because the natural implementation is the wrong one: a `Transport` returning a raw stream forces the Noise handshake into Layer 1, where the core would have to branch on which transport it holds — either double-encrypting the QUIC paths or carrying a conditional that skips it. Each implementation owns its own encryption instead: QUIC from the protocol, `relay` and `ble-gatt` by wrapping before returning. Same for multiplexing, which is native on QUIC and in-band elsewhere | [docs/03](docs/03-discovery-and-transport.md#a-transport-delivers-an-already-secure-channel), [docs/02](docs/02-architecture.md#direction-of-dependency) | 2026-08-23 |
| DCR-013 | **A filename may not reorder itself.** The sanitization table stopped at control characters, and `U+202E RIGHT-TO-LEFT OVERRIDE` is not one — `char::is_control` is false for every bidi control. `report\u{202E}fdp.exe` renders as `reportexe.pdf` to the user deciding whether to accept it. Rejected: the overrides, embeddings and isolates, plus `U+2028` and `U+2029`. **`U+200E` and `U+200F` stay permitted**, since they cannot reverse a run and Arabic and Hebrew filenames use them; rejecting them would cost every RTL user something real to defend nothing. **My gap, not the Implementer's** — the implementation matched the documented rule exactly | [docs/04](docs/04-protocol.md#why-a-filename-may-not-reorder-itself), [docs/06](docs/06-shares-and-linking.md#resolution) | 2026-08-22 |
| DCR-012 | **NFC normalization cannot happen in Layer 0**, so step 2 of docs/06's resolution procedure splits across two layers. [ADR-0014](docs/adr/0014-vfs-exposes-operations-never-paths.md) had just claimed the whole of `RelPath` validation was a Layer 0 concern, normalization included; the standard library ships none and [I4](CLAUDE.md#8-invariants-that-must-not-break) forbids the dependency that would. `tradr-vfs` normalizes and rebuilds a `RelPath`, so the re-check runs through the same type rather than a second copy of the rules. **Caught while cutting WI-M0-006d against an ADR written 20 minutes earlier** — the shape of every check-then-implement cycle, at a smaller scale than usual | [ADR-0014](docs/adr/0014-vfs-exposes-operations-never-paths.md), [docs/06](docs/06-shares-and-linking.md#resolution) | 2026-08-22 |
| DCR-011 | **`docs/02` contradicted itself about who declares the `Transport` trait.** The layout table said `tradr-transport/ # The Transport trait, ...`, while the prose and the dependency diagram both said `tradr-core` declares it. An Implementer following the table would have declared a Layer 1 trait in a Layer 3 crate, and **everything would still have compiled** — B3 fails silently. Same class as DCR-003. Also settled two things the `Transport` trait needed and no document stated: `TransportId` and candidate addresses are opaque to the core, and the class-weight table belongs to path selection, both required for Change Drill D10 not to reach `tradr-core`. And recorded the async shape and the `Vfs` shape as decisions | [ADR-0013](docs/adr/0013-layer-1-async-traits-return-boxed-futures.md), [ADR-0014](docs/adr/0014-vfs-exposes-operations-never-paths.md), [docs/02](docs/02-architecture.md#direction-of-dependency), [docs/03](docs/03-discovery-and-transport.md#what-the-core-knows-about-a-transport) | 2026-08-22 |
| DCR-010 | `gen/android/` is generated at `apps/tradr/src-tauri/gen/android/`, not at `apps/tradr/gen/android/` as the layout claimed. Corrected in `docs/02`, and the two dead `.gitignore` entries repointed | [docs/02](docs/02-architecture.md#monorepo-layout), `.gitignore` | 2026-08-22 |
| DCR-009 | **Every identity-key signature carries a domain tag from a closed set.** Only `KeyBinding` had one. `HelloAck.nonce_signature` and `BrokrRegister.challenge_signature` were both raw signatures over bytes the other side chose, so a Brokr could hand a device a peer's `Hello.nonce` as a registration challenge and replay the answer to impersonate it — which contradicts [ADR-0005](docs/adr/0005-brokr-is-optional.md)'s claim that a compromised Brokr cannot impersonate anyone | [docs/05](docs/05-security.md#every-signature-carries-a-domain-tag), docs/07, `proto/` | 2026-08-22 |
| DCR-008 | Partial files are named by a **receiver-assigned ordinal**, not by the sender's `item_id`. An `item_id` is attacker-controlled, and using it as a path component made zip-slip-class defences load-bearing forever. `item_id` is still validated as an opaque token, since it is a map key and reaches logs | [docs/04](docs/04-protocol.md#partial-files) | 2026-08-22 |
| DCR-007 | Device Keys become P-256 and wire fields are renamed to `identity_pub` and `agreement_pub`. Settles open decision 13 | [ADR-0012](docs/adr/0012-p256-for-device-keys.md), [docs/05](docs/05-security.md#hardware-backing-and-the-curve), [CONTEXT.md](CONTEXT.md), docs/03, 06, 07, 08, 10, ADR-0003, ADR-0006. **`proto/` and `roundtrip.rs` follow in WI-M0-002a** | 2026-08-22 |
| DCR-006 | The three comment jobs warned instead of failing, on the theory that a warning obliges inspection. A job that cannot fail is not a gate — WI-M0-001b caught that exact shape in `pnpm lint`. All jobs now fail, and false positives are retired in `ci/allowlist.txt` with a mandatory reason | [docs/10](docs/10-implementation-process.md#every-job-fails-false-positives-go-in-the-allowlist) | 2026-08-22 |
| DCR-005 | `docs/02` named no crate as the protobuf codec's home, while Change Drill D5 requires it be confined to the Adapter layer. Added `crates/tradr-proto`, the only crate permitted to name `prost`, checkable with `grep -rl prost crates/`. The TypeScript side already had `@tradr/protocol`; the Rust side was the asymmetry | [docs/02](docs/02-architecture.md#where-the-protobuf-codec-lives) | 2026-08-22 |
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

### A trap this Supervisor fell into

**`git add -A` while an Implementer is working sweeps unreviewed code into your commit.** It happened on 2026-08-22: a `docs/`-only DCR commit picked up WI-M0-001d's entire working tree, breaking two rules in [CLAUDE.md](CLAUDE.md) §5 at once — committing before `PASS`, and a design change that was supposed to be a docs-only commit. It was caught by reading `git show --stat` afterwards, and undone with `git reset --soft HEAD~1` before anything was pushed.

A second lesson arrived the same day from the opposite direction. A scripted `STATE.md` edit failed partway, so a Work Item commit landed **without** its `STATE.md` update, which §5 also forbids — and it happened twice in a row, because the fix was scripted just as blindly as the mistake. **Read `git show --stat` after every commit and confirm both halves are there**, the code and the record. And when a scripted edit asserts, read the file before writing the next script.

**Stage paths explicitly when a Work Item is in flight.** `git add docs/ STATE.md`, never `git add -A`. And read `git show --stat` after every commit; the mistake is invisible in `git status` once it is made.

### Notes on the CI checks

**`ci/` is deliberately outside the scan scope.** The three comment checks cover `crates/**/*.rs` and `packages/**/*.ts` only. `ci/excuse-grep.sh` necessarily contains the entire A4 phrase list, so a self-scan would either fail permanently or need an allowlist entry that reads as a blanket exemption. The scripts were checked by hand instead: ASCII only, headers within the five-line block limit.

**`.github/workflows/ci.yml` pins pnpm to 10.20.0 with nothing local to compare against.** `rust-toolchain.toml` is the single source of truth for the Rust channel and the workflow defers to it, but pnpm's version exists only in the workflow. Add a `packageManager` field to the root `package.json` and have the workflow read it, **at the same time the GitHub repository is created** — that is the first moment CI can actually run, and the first moment the drift could bite.

---

## Deferred

Things consciously postponed. **These live here, not in TODO comments in the code.**

| # | Content | When | Source |
|---|---|---|---|
| DF-1 | Desktop drag-out, pulling a peer's file into a file manager. A download button substitutes | After M9 | [docs/08](docs/08-platform-integration.md) |
| DF-2 | Shell integration: Windows context menu, macOS share menu, Linux `.desktop` | Phase 3 | [docs/08](docs/08-platform-integration.md) |
| DF-3 | Post-quantum migration. Write an ADR once `rustls` X25519MLKEM768 and hybrid Noise are both stable | Undecided | [docs/05](docs/05-security.md) |
| DF-4 | Android 14+ `ChooserAction` custom actions. Sharing Shortcuts suffice for v1 | Undecided | [docs/08](docs/08-platform-integration.md) |
| DF-12 | **A candidate address may carry a bidirectional override; a `RelPath` may not.** DCR-013 rejects `U+202A`-`U+202E` and the isolates in a filename, because a name is shown at an accept-or-decline prompt and `report\u{202E}fdp.exe` renders as `reportexe.pdf`. DCR-017 gives a candidate address only the `item_id` rules, empty and control characters, so `\u{202E}evil.example:443` is accepted — confirmed by probe. The asymmetry is deliberate today: path selection is automatic and no user approves a candidate, so there is no prompt to spoof. **It stops being deliberate the moment the UI shows a peer's address**, which device details plausibly will | When the UI displays a peer address, M4 at the latest | WI-M0-006g |
| DF-11 | **Two `Vfs` contracts are stated but not tested.** `open_write` creates if absent and **never truncates** — a truncating implementation silently destroys everything a resumed transfer already received. `remove` takes a file or an already-empty directory and **never recurses** — a `RelPath` is peer-influenced, and recursion on the far end of one is more power than any caller needs. Both are contracts on implementations that do not exist yet, so M3's `tradr-vfs` Work Order carries the tests. **Both are Critical Module adjacent**, so the Supervisor writes those tests first | M3, with `tradr-vfs` | WI-M0-006f |
| DF-10 | **A colon in a component opens an NTFS alternate data stream.** `RelPath` rejects `C:` only in the drive position, because rejecting `:` outright would make ordinary Linux filenames such as `2026-08-22T10:00:00.log` unbrowsable — a cost on every platform to defend one. The Windows `Vfs` must handle it the way docs/04 handles reserved names, by transforming rather than rejecting | Before M4's Windows build | WI-M0-006d |
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
| R2 | Tauri 2's Android maturity | Medium | **One of three conditions met.** WI-M0-004 built a correctly signed APK carrying all four ABIs. The two conditions needing a running Android are testable now that an AVD boots |
| R8 | Brokr-free operation breaks as features are added | High | Make CI's `no-brokr` job required from M1 |
| R9 | macOS and Windows signing procurement takes weeks | Medium | Needs starting before M4. Re-check at the start of M2 |
| R11 | The AppImage bundler downloads unpinned executables at build time | Medium | **Observed at M0.** Five artifacts fetched with no hash pinning; `deb` and `rpm` need none. Folded into open decision 7 — either drop AppImage or vendor and pin, before M2 |

R9 has a procurement lead time, so it cannot wait for M4. Revisit when M2 begins.

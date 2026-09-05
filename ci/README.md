# CI Scripts

This directory contains the custom checks that enforce Tradr's rules.

## discarded-result.sh
Mechanizes rule F6 (CLAUDE.md section 4-E): refuses any production Rust source binding a value to nothing via `let _ =`, `let _: T =`, statement-position `_ =`, or statement-position `.ok();`. Scans every `*.rs` under `crates/*/src/` and `apps/*/src-tauri/src/`, excluding `target/`, `tests/`, and `build.rs`. Takes no allowlist and has no suppression mechanism: an error genuinely not worth propagating must be reported with `if let Err(e) = ... { eprintln!(...) }` naming its context, making the decision explicit and visible in diffs.

## frontend-gate.sh
Runs `pnpm lint`, `pnpm typecheck` and `pnpm format:check`, all three regardless of an earlier failure, so one failure never hides another. Lives in `ci/` rather than as its own CI job so that `.githooks/pre-commit` runs it, through `ci/run-all.sh`, on every commit rather than only on a pull request -- before this script existed, a `.tsx` file that failed to typecheck or that `biome format` refused could be committed with every stage the hook ran reporting green. Checks that `pnpm` is on `PATH` and that `node_modules` exists at the repository root before running any of the three, and fails rather than skips when either is missing. Takes no allowlist: `biome lint`, `tsc` and `biome format` each carry their own suppression mechanism.

## hooks-executable.sh
DCR-036: `.githooks/pre-commit` is version-controlled so it arrives with a clone, but git file modes are not always preserved by every checkout path (a zip download, some CI checkout actions), and a non-executable hook is silently never run by git -- no error, no warning, just skipped. This is the part a repository can mechanically verify. Whether a given clone has actually pointed `core.hooksPath` at `.githooks` is a per-clone git config setting; nothing under version control can observe that, and this check does not claim to.

## invoke-commands.sh
Mechanizes WI-M0-014c: a frontend `invoke()` call names the plugin command by string alone, so a typo compiles perfectly and only fails at runtime. Reads every `invoke("...")` and `invoke<...>("...")` string literal under `apps/tradr/src/` and requires each to be of the form `plugin:<plugin>|<command>`, where `<command>` appears in the `COMMANDS` list in `crates/tauri-plugin-tradr/build.rs`. Runs one way only: a command in `COMMANDS` that the frontend never calls is not a violation.

## layer-deps.sh
Mechanizes invariant I4, rule B1, and Change Drills D5 and D9: `tradr-core` depends on nothing, only `tradr-proto` names `prost`, only `tauri-plugin-tradr` names `tauri`, only `tradr-oidc` names `reqwest` (DCR-024), only `tradr-integrity` names `bao` (Critical Module, ADR-0006), and no implementation crate depends internally on anything but `tradr-core` and `tradr-proto` (`tauri-plugin-tradr`, the composition root, is exempt from that last rule).

Scans every `Cargo.toml` under both `crates/` and `apps/`. The app manifests under `apps/` (e.g. `apps/tradr/src-tauri`) get the same `prost`/`reqwest` confinement as `crates/`, are exempted from the `tauri` confinement (an app is allowed to name `tauri`), and are held to a stricter internal-dependency rule than `crates/`: `tauri-plugin-tradr` is their only permitted path dependency, with no composition-root exemption, since the app reaches every implementation crate through that plugin rather than directly.

## no-brokr.sh
Enforces Invariant I1 (ADR-0005, CLAUDE.md section 8) by running every test in `ci/tier01-tests.txt` inside a network namespace sealed to loopback: nothing in it can dial a Brokr, reachable or not, so a pass here is evidence Tier 0/1 needs none. See `ci/tier01-tests.txt` for what is covered and why.

## plugin-permissions.sh
Mechanizes WI-M5-006: a Tauri command is named in three places -- `tauri::generate_handler![...]` in `crates/tauri-plugin-tradr/src/lib.rs`, `COMMANDS` in `crates/tauri-plugin-tradr/build.rs`, and the `permissions` array in `apps/tradr/src-tauri/capabilities/*.json` -- and a command missing from the third is refused by the IPC ACL at runtime however correctly it is registered in the first two. Nothing checked that these agreed before this script.

Enforces three rules. Rule 1: the set of command names inside `generate_handler![...]` equals the set in `COMMANDS`, checked in both directions. Rule 2: every name in `COMMANDS` is granted by at least one capability file, either as `tradr:allow-<name>` or by `tradr:default`, unioned across every `apps/tradr/src-tauri/capabilities/*.json`. Rule 3: every value symbol a frontend file imports from an `@tauri-apps/plugin-<plugin>` module is granted as `<plugin>:allow-<kebab-case symbol>` or by `<plugin>:default`; a type-only import, and a `type` specifier inside a mixed import, are skipped; what it cannot parse -- two import statements sharing one region, one that never reaches a module specifier, or a dynamic `import("@tauri-apps/plugin-<plugin>")` whose destructured symbols it cannot read -- is refused rather than silently passed, and that refusal cannot be suppressed by the allowlist.

Composes with `invoke-commands.sh` rather than replacing it: that script checks a frontend `invoke()` literal against `COMMANDS`, the one link this script does not check, since a command in `COMMANDS` the frontend never calls is not a violation of anything here either. Together the two cover the whole chain from a call site to the ACL -- `invoke-commands.sh` for `tradr:`-namespaced commands called through `invoke()`, this script for `invoke_handler` agreeing with `COMMANDS`, `COMMANDS` agreeing with the capability grants, and any plugin (`dialog:` included) whose API the frontend imports directly rather than through `invoke()`.

## state-sync.sh
Mechanizes `STATE.md`'s own contract: every DCR-N already committed into `STATE.md` or `RECORD.md` appears in a commit message (one the working tree is only now adding is exempt -- it has no commit yet by construction), every DCR number is defined at most once, every repository path referenced resolves, and the current branch must never be "main" itself. Never writes `STATE.md` or `RECORD.md`.

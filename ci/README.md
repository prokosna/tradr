# CI Scripts

This directory contains the custom checks that enforce Tradr's rules.

## hooks-executable.sh
DCR-036: `.githooks/pre-commit` is version-controlled so it arrives with a clone, but git file modes are not always preserved by every checkout path (a zip download, some CI checkout actions), and a non-executable hook is silently never run by git -- no error, no warning, just skipped. This is the part a repository can mechanically verify. Whether a given clone has actually pointed `core.hooksPath` at `.githooks` is a per-clone git config setting; nothing under version control can observe that, and this check does not claim to.

## invoke-commands.sh
Mechanizes WI-M0-014c: a frontend `invoke()` call names the plugin command by string alone, so a typo compiles perfectly and only fails at runtime. Reads every `invoke("...")` and `invoke<...>("...")` string literal under `apps/tradr/src/` and requires each to be of the form `plugin:<plugin>|<command>`, where `<command>` appears in the `COMMANDS` list in `crates/tauri-plugin-tradr/build.rs`. Runs one way only: a command in `COMMANDS` that the frontend never calls is not a violation.

## layer-deps.sh
Mechanizes invariant I4, rule B1, and Change Drills D5 and D9: `tradr-core` depends on nothing, only `tradr-proto` names `prost`, only `tauri-plugin-tradr` names `tauri`, only `tradr-oidc` names `reqwest` (DCR-024), only `tradr-integrity` names `bao` (Critical Module, ADR-0006), and no implementation crate depends internally on anything but `tradr-core` and `tradr-proto` (`tauri-plugin-tradr`, the composition root, is exempt from that last rule).

Scans every `Cargo.toml` under both `crates/` and `apps/`. The app manifests under `apps/` (e.g. `apps/tradr/src-tauri`) get the same `prost`/`reqwest` confinement as `crates/`, are exempted from the `tauri` confinement (an app is allowed to name `tauri`), and are held to a stricter internal-dependency rule than `crates/`: `tauri-plugin-tradr` is their only permitted path dependency, with no composition-root exemption, since the app reaches every implementation crate through that plugin rather than directly.

## no-brokr.sh
Enforces Invariant I1 (ADR-0005, CLAUDE.md section 8) by running every test in `ci/tier01-tests.txt` inside a network namespace sealed to loopback: nothing in it can dial a Brokr, reachable or not, so a pass here is evidence Tier 0/1 needs none. See `ci/tier01-tests.txt` for what is covered and why.

## state-sync.sh
Mechanizes `STATE.md`'s own contract: every DCR-N already committed into `STATE.md` or `RECORD.md` appears in a commit message (one the working tree is only now adding is exempt -- it has no commit yet by construction), every DCR number is defined at most once, every repository path referenced resolves, and the current branch must never be "main" itself. Never writes `STATE.md` or `RECORD.md`.

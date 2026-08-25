# Tradr

Cross-device file exchange for Linux, Windows, macOS, and Android. Quick Share, without the vendor lock-in.

Send files between your own devices — or devices belonging to someone you have explicitly linked with — over LAN, proximity, or the open internet, end-to-end encrypted throughout.

**Tradr runs with no server.** A [Brokr](docs/07-brokr.md) is an optional component you host yourself when you want to reach across networks.

## Three principles

1. **Serverless by default.**
   Devices find each other over mDNS and BLE and transfer directly. No backend is required for the product to work.

2. **Google is the root of trust.**
   Embedding the device public key in the OIDC `nonce` turns Google's signed ID token into proof that this account holder controls this key. Devices authenticate each other using Google's public keys alone — Tradr operates no authentication service of its own.

3. **A Brokr is an optional add-on.**
   Deploy one yourself and register it from the client to gain cross-network discovery, NAT traversal, and relay. If you already run an overlay network such as Tailscale, you do not need a Brokr at all: pin the peer's address and connect directly.

## Documentation

| # | Document | Contents |
|---|---|---|
| 01 | [Overview](docs/01-overview.md) | Users, use cases, scope, non-goals |
| 02 | [Architecture](docs/02-architecture.md) | Tiers, components, monorepo layout, language boundaries |
| 03 | [Discovery and transport](docs/03-discovery-and-transport.md) | mDNS, BLE, static peers, Brokr, path selection |
| 04 | [Wire protocol](docs/04-protocol.md) | Framing, messages, chunked transfer |
| 05 | [Security and identity](docs/05-security.md) | Attestation, key handling, threat model |
| 06 | [Shares and linking](docs/06-shares-and-linking.md) | Share roots, permissions, cross-account links |
| 07 | [Brokr (optional)](docs/07-brokr.md) | API, data model, relay, self-hosting |
| 08 | [Platform integration](docs/08-platform-integration.md) | Drag and drop, Android share sheet, iOS constraints |
| 09 | [Roadmap and risks](docs/09-roadmap-and-risks.md) | Milestones, open questions |
| 10 | [Implementation process](docs/10-implementation-process.md) | Roles, work orders, review, design changes |

Decisions are recorded in [docs/adr/](docs/adr/).

## Before you start working

| File | Contents |
|---|---|
| **[CLAUDE.md](CLAUDE.md)** | **Working rules. Every agent reads this first** |
| **[STATE.md](STATE.md)** | **Current progress and the next three actions** |
| [CONTEXT.md](CONTEXT.md) | Domain vocabulary. The single source of truth for terms |

Implementation is done by a cheap model (the Implementer) and reviewed by an expensive one (the Supervisor). Progress lives in `STATE.md` so that an agent with no context can take over as Supervisor at any moment — see [ADR-0009](docs/adr/0009-supervised-implementation-loop.md).

**Enable the pre-commit hook once per clone.** `core.hooksPath` is a per-clone git config setting; it does not arrive with a `git clone` on its own:

```
git config core.hooksPath .githooks
```

This turns on the local gate that CLAUDE.md section 5 describes: `ci/run-all.sh`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, then `cargo test --workspace`, in that order, before any commit is created. **`git commit --no-verify` is forbidden** — it is the one way to make a commit that skips this gate, and `ci/hooks-executable.sh` can confirm the hook file is in place and executable, but nothing in the repository can confirm a given clone actually ran the command above.

**Branch protection on `main`** is a GitHub repository setting, not something this repository can turn on itself. Run once, by whoever administers the repository:

```
gh api -X PUT repos/prokosna/tradr/branches/main/protection --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["checks", "rust", "web", "desktop", "android-debug-smoke (aarch64, debug only -- not the release toolchain check)"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

That refuses direct pushes to `main` (including the administrator's own), requires a pull request, and requires the checks that actually run on a pull request to pass before merging. `android-release-toolchain` is deliberately absent from `contexts`: it runs only on `schedule` and on `push` to `main` (see `.github/workflows/ci.yml`), never on a pull request, so requiring it would leave every pull request blocked on a check that never runs against it.

## Setting it up

**Tradr ships with no OAuth credentials.** Every deployment registers its own Google Cloud project, which is what makes each deployment a self-contained trust domain. See [docs/05](docs/05-security.md#oauth-client-configuration) for why.

Create a project, then an OAuth client per platform you intend to build — one **Desktop app**, one **Android**. Google issues a secret for the Desktop client and none for the Android one; **that is expected, not a mistake in your setup.** A Desktop client's secret is required by Google's token endpoint even under PKCE, which was measured rather than assumed and is written up in docs/05.

Both values are baked in at build time, from the environment:

```
TRADR_OAUTH_CLIENT_IDS=desktop:<id>,android:<id>
TRADR_OAUTH_CLIENT_SECRET=<the Desktop client's secret>
```

Put them in a gitignored `.tradr-deployment.env` at the repository root and every build picks them up; in CI, set them per job from your repository secrets and no file is involved. **An Android build never receives the secret**, because nothing on Android uses it.

Adding a platform later means adding one entry to `TRADR_OAUTH_CLIENT_IDS`. Devices that predate it accept the new platform after a rebuild with the updated value.

## Building

```
cargo tauri build            # this host's desktop
cargo tauri android build    # Android
```

**The asymmetry is deliberate and it is worth understanding before it looks like an oversight.**

`cargo tauri build` takes no platform argument because there is nothing to choose: a desktop build needs the host it is built for. Linux bundles link against the system WebKitGTK, macOS bundles need macOS SDKs and signing, and Windows bundles want MSVC. Tauri can cross-compile a Windows bundle from Linux or macOS through NSIS, and its own documentation calls that a last resort. **So `cargo tauri build` means "the desktop this machine is", and that is the only desktop this machine builds.**

`cargo tauri android build` is a separate command because Android is the one target that is *not* bound to the host. Any of the three desktop OSes can build it, given the NDK.

Which is to say: **the two commands differ because the two situations differ.** A wrapper taking `linux|macos|windows|android` was considered and rejected — it would have presented four equal choices where three of them fail on any given machine, hiding the constraint instead of naming it.

Building all four therefore means four machines, or a CI matrix with one runner per desktop OS plus an Android job on any of them.

## Stack

- **App shell**: Tauri 2, targeting Linux, Windows, macOS, and Android from one project
- **UI**: TypeScript and React
- **Native layer**: Rust — BLE, mDNS, QUIC, cryptography, file I/O
- **Android glue**: Kotlin — share sheet, SAF, foreground service, BLE advertising
- **Brokr (optional)**: TypeScript on Node.js with Fastify, SQLite or PostgreSQL. One binary, one container
- **Protocol**: Protocol Buffers in `proto/`, generated into Rust and TypeScript

## License

Apache License 2.0. See [LICENSE](LICENSE).

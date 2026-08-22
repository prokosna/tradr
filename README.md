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

## Stack

- **App shell**: Tauri 2, targeting Linux, Windows, macOS, and Android from one project
- **UI**: TypeScript and React
- **Native layer**: Rust — BLE, mDNS, QUIC, cryptography, file I/O
- **Android glue**: Kotlin — share sheet, SAF, foreground service, BLE advertising
- **Brokr (optional)**: TypeScript on Node.js with Fastify, SQLite or PostgreSQL. One binary, one container
- **Protocol**: Protocol Buffers in `proto/`, generated into Rust and TypeScript

## License

Apache License 2.0. See [LICENSE](LICENSE).

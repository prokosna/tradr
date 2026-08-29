# ADR-0008: Network, disk, and keys live in Rust

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

The direction is TypeScript unless a specific reason favours something else. That reason needs a line drawn.

## Decision

Language follows this test:

> **Anything called tens of thousands of times per second, reaching a low-level OS API, or touching a secret key goes to Rust. Anything reachable only through an Android OS API goes to Kotlin. Everything else is TypeScript.**

Which gives:

| Area | Language |
|---|---|
| All UI | TypeScript, React |
| The entire Brokr | TypeScript, Fastify |
| BLE, mDNS, QUIC, file I/O, cryptography, chunking | Rust |
| Android share sheet, SAF, foreground service, BLE advertising, Wi-Fi Direct, Custom Tabs | Kotlin |

## Reasoning

### Why Rust

1. **Library maturity.** This product's core libraries — BLE, QUIC, Noise, BLAKE3 — all exist in Rust and are in production use. Node's equivalents are weakest at BLE and handle platform differences incompletely.

2. **Tauri's structure makes it inevitable.** Tauri's native side is Rust ([ADR-0001](0001-tauri-2-as-app-shell.md)). Making it TypeScript means launching a separate Node sidecar process, which dissolves the single-codebase premise behind choosing Tauri and raises the residency cost.

3. **The nature of transfer.** Pushing gigabytes at tens of megabytes per second while hashing every chunk makes GC pauses and buffer copies show up directly. Handling a hundred 1 MiB chunks per second, Node's Buffer copies and GC pressure are not negligible.

4. **Handling secret keys.** Every OS key store exposes a C ABI, callable directly from Rust. Reaching it from Node needs FFI or a native module.

### Why Kotlin stays minimal

Kotlin code is tested only on Android and shares nothing with other platforms. The discipline is **Android APIs Rust cannot reach, and nothing else** — no logic. The Kotlin side takes values from the OS and hands them to Rust, or calls an OS API at Rust's instruction.

### Why TypeScript is confined to the UI and the Brokr

- The UI touches neither the network nor the filesystem, working only through Tauri commands and events. Holding that boundary keeps UI tests free of the network
- The Brokr is I/O-light, where type sharing and iteration speed win. And **being an optional component, the choice there cannot affect how clients behave** ([ADR-0005](0005-brokr-is-optional.md))

## Costs

- **Slower development.** The native layer takes longer than TypeScript would, especially while async handling and lifetimes are unfamiliar.
- **Three language toolchains to maintain**, complicating CI.
- **The risk of duplicated type definitions.** Prevented by making generation from `proto/` the single source of truth and keeping hand-written types off the boundary.

## The boundary's design

`tradr-core` depends only on the `Transport` and `Vfs` traits, never calling real I/O. That means:

- Core logic — offer and accept, chunking, deciding where to resume, verification — is testable with neither a real network nor a real filesystem
- Disconnections and path switches can be injected in tests, which is what the fragile-parts table in [09](../09-roadmap-and-risks.md) requires
- Writing iOS in Swift later can link the Rust core as a static library

This separation is the investment that keeps the most breakable part of the design testable.

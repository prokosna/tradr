# ADR-0001: Tauri 2 as the app shell

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

Four platforms are required: Linux, Windows, macOS, and Android. The UI should be TypeScript. iOS may follow.

Options considered:

1. **Tauri 2** — a Rust native layer with a WebView, building all four platforms plus iOS from one project
2. **Electron for desktop with React Native for Android** — the highest TypeScript share, the most mature ecosystem
3. **Electron for desktop with Kotlin for Android** — the most reliable Android OS integration

## Decision

**Tauri 2.**

## Reasoning

1. **One codebase.** Options 2 and 3 split desktop and Android. That means carrying the UI and the protocol implementation twice, which one person or a small team cannot sustain.

2. **The library situation in the native layer.** This product's core is BLE, mDNS, QUIC, file I/O, and cryptography. Node's ecosystem is weakest exactly at BLE — the `noble` lineage has been unstably maintained for years — and its handling of platform differences is incomplete. Rust offers `btleplug`, `bluer`, `quinn`, `snow`, and `blake3`, all in production use. **Choosing option 2 means writing native modules anyway, which dissolves the reason to choose Electron.**

3. **Binary size and residency cost.** This kind of app stays resident. A minimal Electron build exceeds 100 MB and idles at hundreds of megabytes of memory. Tauri lands around 10-20 MB and uses the system WebView, so memory stays small. For something premised on always running, that difference is not negligible.

4. **An escape route to iOS.** Tauri 2 can target iOS. Even if that proves inadequate, linking the Rust core into Swift as a static library remains available.

## Costs

- **Rust's learning curve and development speed.** The native layer will be slower to write than TypeScript. Accepted.
- **Tauri's mobile maturity.** Tauri 2's Android support is newer than Electron's or React Native's, so unknown problems are likely. Hence the explicit decision point at the end of M0, tracked as R2 in [09](../09-roadmap-and-risks.md).
- **WebView differences.** WebKitGTK on Linux, WebView2 on Windows, WKWebView on macOS and iOS, System WebView on Android. CSS and JS behaviour will diverge. Mitigated by not over-designing the UI.
- **Electron's large body of desktop-integration recipes does not apply.** Tray, notifications, and auto-update exist in Tauri, but intricate things like dragging out get written by hand.

## Conditions for withdrawal

If any of these fails at the end of M0, switch to option 3, Electron with Kotlin.

- The Tauri 2 Android build passes reliably in CI
- Bidirectional calls work — Kotlin plugin into Rust, and Rust back into Kotlin
- Android `ACTION_SEND` arrives through the Tauri plugin

# Architecture Decision Records

Decisions and the reasoning behind them. To change a decision, write a new ADR and mark the old one `Superseded`. Never rewrite an existing one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-tauri-2-as-app-shell.md) | Tauri 2 as the app shell | Accepted |
| [0002](0002-ble-for-discovery-and-small-payloads.md) | BLE carries discovery, authentication, and small payloads only | Accepted |
| [0003](0003-google-attestation-as-trust-root.md) | An OIDC-nonce Attestation is the root of trust | Accepted |
| [0004](0004-quic-as-the-bulk-transport.md) | QUIC carries bulk transfer | Accepted |
| [0005](0005-brokr-is-optional.md) | The Brokr is an optional component | Accepted |
| [0006](0006-blake3-for-content-integrity.md) | BLAKE3 for content integrity | Accepted |
| [0007](0007-receiver-driven-chunk-pull.md) | The receiver pulls chunks | Accepted |
| [0008](0008-rust-for-the-native-layer.md) | Network, disk, and keys live in Rust | Accepted |
| [0009](0009-supervised-implementation-loop.md) | A cheap model implements, an expensive one reviews | Accepted |
| [0010](0010-identity-is-the-issuer-subject-pair.md) | Account identity is the (issuer, subject) pair | Accepted |
| [0011](0011-keystore-exposes-operations.md) | The KeyStore exposes operations, never key bytes | Accepted |
| [0012](0012-p256-for-device-keys.md) | P-256 for Device Keys | Accepted |
| [0013](0013-layer-1-async-traits-return-boxed-futures.md) | Layer 1 async traits return boxed futures | Accepted |
| [0014](0014-vfs-exposes-operations-never-paths.md) | The Vfs exposes operations, never paths | Accepted |
| [0015](0015-tauri-2-is-retained-after-m0.md) | Tauri 2 is retained after M0's decision point | Accepted |

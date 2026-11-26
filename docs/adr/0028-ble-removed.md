# ADR-0028: BLE is removed

- **Status**: Accepted
- **Date**: 2026-11-27
- **Supersedes**: [ADR-0002](0002-ble-for-discovery-and-small-payloads.md), [ADR-0018](0018-blake3-derive-key-for-eids.md), [ADR-0019](0019-a-128-bit-service-uuid-for-the-ble-advertisement.md), [ADR-0020](0020-noise-xx-for-ble-gatt.md), [ADR-0021](0021-macos-is-scan-only-on-ble.md)

## Context

M7 built BLE discovery (EIDs, advertising and scanning on three platforms) and a `ble-gatt` transport (Noise_XX over GATT with an in-band mux). It was never run on two radios, and the user's devices never use it. It made up about a fifth of the Rust code and tests, needed Bluetooth and location permissions on Android, and carried open security questions (an active prober learning static keys; 20% integrity overhead on 4 KiB pieces).

## Decision

Remove BLE completely:
- BLE discovery, EIDs and the Account Broadcast Key (store, exchange and `BroadcastKeyOffer`).
- The `ble-gatt` transport, the Noise channel, and the in-band stream mux.
- `bluer` and `snow` as dependencies; the Android BLE Kotlin code and the Bluetooth and location permissions.

Wire code `0x10` and the range `0x60-0x7f` are retired and never reassigned. Capability bit 2 is retired. `BroadcastKeyOffer` was never wired into the handshake, so older builds interoperate unchanged.

## Consequences

- Discovery is mDNS plus Static Peers; `direct-quic` is the only transport. UC-5 (no-network handover) is dropped.
- `relay`, if ever built, needs a new end-to-end channel design; the removed Noise code remains in git history.
- Leftover `account-broadcast-key.json` files and key-store slots on existing devices are inert.

# ADR-0004: QUIC carries bulk transfer

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

A transport is needed for device-to-device bulk transfer. Requirements:

- Control messages and several file bodies flowing at once
- Surviving a network change mid-transfer, Wi-Fi to cellular or an access-point roam
- Sharing one socket with NAT hole punching
- Mutual authentication and encryption

Options: TCP with TLS 1.3, QUIC, or a bespoke UDP protocol.

## Decision

**QUIC, via `quinn`.** A self-signed certificate carries the Device Key as its public key, matched against the pinned value. No CA and no chain validation.

## Reasoning

1. **Multiplexed streams.** The control and data planes ride independent streams. TCP offers one ordered stream, so a large file body blocks control messages behind it — head-of-line blocking — and cancelling or pausing stops taking effect promptly.

2. **Connection migration.** QUIC identifies a connection by connection ID rather than address. Moving from Wi-Fi to cellular, or having the NAT mapping change, does not end it. That maps directly onto carrying a laptop while a transfer runs.

3. **Fits hole punching.** Being UDP, the socket that punches the hole is the socket that transfers. TCP hole punching has a poor success rate and a more complicated implementation.

4. **0-RTT resumption.** A previously contacted peer connects one round trip sooner, which is felt across frequent short transfers.

5. **TLS 1.3 is already inside.** No separate encryption layer is needed, and public-key pinning removes the CA.

A bespoke UDP protocol is avoided because congestion control is hard to get right and easy to make unfair to other traffic. QUIC's is well tested.

## Costs

- **Unusable where UDP is blocked.** Corporate networks and some hotel Wi-Fi throttle UDP. Those fall back to `relay` over WebSocket and TLS.
- **Some middleboxes drop QUIC.** Same fallback.
- **Higher CPU cost than TCP**, running in user space rather than the kernel. Mitigated with GSO and GRO, but it will not match TCP. Measure at the 100 MB/s scale.
- **Unusable on BLE and relay.** Those use Noise_IK, so there are two encryption layers. Abstracted behind a `SecureChannel` trait so nothing above notices — see [05](../05-security.md#why-there-are-two-encryption-layers).

## To verify

During M1, confirm the measured LAN throughput reaches the 35 MB/s target. If it does not, first tune GSO, GRO, and receive buffer sizes, and only then re-measure against TCP.

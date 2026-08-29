# ADR-0002: BLE carries discovery, authentication, and small payloads only

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

The requirement was to support both device-to-device Bluetooth and LAN, choosing automatically between them. Read plainly, that means Bluetooth carries file payload too.

The measured reality:

| Method | Effective | Time for 1 GB |
|---|---|---|
| BLE GATT, 20-byte MTU | ~5 KB/s | about 55 hours |
| BLE GATT, 247-byte MTU on 2M PHY | ~100 KB/s | about 2.8 hours |
| Bluetooth Classic, RFCOMM | ~1.5 MB/s | about 11 minutes |
| Wi-Fi Direct | ~20 MB/s | about 50 seconds |
| LAN direct | 50-110 MB/s | 10-20 seconds |

Neither Quick Share nor AirDrop puts payload on BLE; both use it for discovery and key exchange and then switch to Wi-Fi Direct or AWDL.

## Decision

**Restrict BLE to three purposes: discovery, mutual authentication, and payloads of 512 KiB or less.**

Anything larger drops BLE from the candidate list. With no other path available the transfer queues as waiting for a network and starts by itself once Wi-Fi returns.

Bulk transfer over Bluetooth Classic, RFCOMM or L2CAP, **is not implemented**.

## Reasoning

1. **Bulk over BLE is not a working feature.** Calling a transfer that takes three hours for 1 GB "supported" is close to deceiving the user. The progress bar moves, but nobody waits for it to finish.

2. **Bluetooth Classic does not line up across four platforms.** Android, Linux, and Windows can use RFCOMM; macOS exposes little publicly, and iOS forbids arbitrary RFCOMM without MFi certification. A path that is fast only on some combinations adds selection complexity and a combinatorial test burden for little return.

3. **BLE remains valuable for discovery.** Where there is no Wi-Fi, where devices sit on different networks, or where an access point blocks client isolation, BLE still finds and authenticates a peer — after which the transfer moves to Wi-Fi Direct or the LAN. That is BLE's proper role.

4. **512 KiB has genuine uses.** Text, URLs, contacts, screenshots. At 100 KB/s that finishes in about five seconds.

## Costs

- **The expectation that large files move without Wi-Fi goes unmet.** The UI has to say so, surfacing the reason for waiting: "connected over Bluetooth only — large files will send once Wi-Fi is available."
- Android pairs can be rescued by `wifi-direct`. Anything involving a desktop cannot.

## Conditions for revisiting

- Bluetooth 5.x isochronous channels, or some future high-speed specification, becoming stable across all four platforms
- Substantial user demand for sending large files where there is no Wi-Fi, in which case an Android/Linux/Windows-only Bluetooth Classic path gets reconsidered

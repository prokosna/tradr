# ADR-0021: macOS is scan-only on BLE, because CoreBluetooth will not advertise Service Data

- **Status**: Accepted
- **Date**: 2026-09-12
- **Supersedes**: the macOS advertising cell of [docs/03](../03-discovery-and-transport.md#2-ble--proximity-no-network-required-tier-0)'s per-platform table, which named `objc2` and `CBPeripheralManager`. [ADR-0019](0019-a-128-bit-service-uuid-for-the-ble-advertisement.md) is untouched — the advertisement's layout is unchanged and the three platforms that can carry it still do. [ADR-0002](0002-ble-for-discovery-and-small-payloads.md) is untouched in scope, but its Change Drill D4 retreat stops being a retreat on one platform

## Context

[ADR-0019](0019-a-128-bit-service-uuid-for-the-ble-advertisement.md) puts the EID in Service Data under a 128-bit service UUID, and the budget is exact: three bytes of Flags, eighteen of AD-structure overhead, ten of payload, thirty-one in total. Apple documents `CBPeripheralManager.startAdvertising` as honouring `CBAdvertisementDataLocalNameKey` and `CBAdvertisementDataServiceUUIDsKey` and ignoring every other key. If that holds, macOS cannot put a Tradr advertisement on the air at all.

**DCR-085 is the precedent for not trusting a documented restriction**: the D-Bus description of BlueZ's UUID filter was read the same way and was wrong, and the correction came from reading `eir.c` rather than the documentation. So this was measured on a Mac and a phone on 2026-09-12, with a raw scanner on the phone reading AD structures rather than a Tradr scanner reporting observations.

**The measurement.** Both runs answered `error: nil` and `isAdvertising = true`.

| What was offered | What the air carried |
|---|---|
| LocalName, ServiceUUIDs, ServiceData | `02011A` `11071CB2A7EA9437D385D640ED6E01000000` — Flags, then the complete 128-bit service UUID list. Twenty-one bytes, and no `0x21` structure |
| ServiceData alone — Flags 3 + Service Data 28 = exactly 31, which is this design's own advertisement | nothing carrying the payload |

**Three things the measurement settled that reading could not.**

**An unsupported key is not always ignored.** Handed `[CBUUID: Data]`, the shape `didDiscover` reports service data in, CoreBluetooth's own XPC encoder sends `UTF8String` to a `CBUUID` and aborts the process inside `startAdvertising`. A macOS implementation therefore cannot find this out by passing the key and observing what happens; it crashes, and it crashes in a frame that names neither the key nor the restriction.

**`didStartAdvertising(error: nil)` carries no information.** An honoured key and a dropped one produce the identical callback, which is why this question always needed a second radio and could never be answered on one machine.

**A scanner built to this design cannot be the instrument.** [docs/03](../03-discovery-and-transport.md#what-a-scanner-reports-and-what-blesource-does-with-it) filters on `setServiceData`, so a Tradr scanner cannot report an advertisement that lacks the very structure under measurement. Pointed at a Mac it would have reported silence, and silence has three causes here. The raw read is what separated them.

**One ambiguity survives and it does not reach the verdict.** Either CoreBluetooth drops the key by policy, or it declines to advertise when no service UUID list is offered. A 128-bit UUID list is eighteen bytes, a 128-bit Service Data structure is twenty-eight, and Flags are three: forty-nine against the thirty-one a legacy advertisement carries, on every platform. **The two cannot coexist in one advertisement**, so both surviving hypotheses put this design's advertisement beyond macOS, and disambiguating them would change nothing that follows.

## Decision

**macOS implements `BleScanner` and does not implement `BleAdvertiser`.** There is no `MacBleAdvertiser`; the macOS build registers a central and no peripheral, and the Work Item that cuts macOS BLE is the central half only.

**Change Drill D4's scan-only retreat is macOS's permanent state rather than a contingency.** D4 asks what it costs to reduce BLE to scan-only; on macOS the answer is that nothing is reduced, because nothing was ever there.

## Consequences

**A Mac is never discovered over BLE, and two Macs never meet over it.** A Mac discovers other devices and dials them as a `ble-gatt` central, so a Mac and an Android phone transfer with the phone as peripheral — which is the same asymmetry R1 already forced on Linux, where this machine's controller refuses every advertisement at the MGMT layer. **The pair M7's completion criterion names is Linux and Android**, and neither changes.

**A Mac's `Capabilities` never go on the air**, since the flags byte rides in the Service Data this platform will not send. Nothing reads a capability bit for a device it cannot observe, so no wire change follows.

**Discovering a Mac needs a transport that is not BLE** — mDNS on a shared LAN, a Static Peer, or a Brokr. That is a real product limit and it is stated here rather than discovered by a user: on a Wi-Fi-less desk, a Mac can start a transfer and cannot receive an unsolicited one.

## Alternatives considered

**Carry the EID in the local name, which Apple does honour.** Rejected, and not narrowly. The EID is eight arbitrary bytes and a local name is a UTF-8 string, so it would need an encoding; every BLE scanner in the world displays a local name to its user; and Android's `ScanFilter` matches a device name exactly, with no pattern form, so a scanner looking for a value that rotates every fifteen minutes would have to scan unfiltered and parse every advertisement in range. **The `setServiceData` filter is what buys this design its battery budget**, and a second wire layout for one platform would cost it on all four.

**A BLE 5 extended advertisement, whose payload is not bounded at thirty-one bytes.** CoreBluetooth exposes no control over it either, and [ADR-0019](0019-a-128-bit-service-uuid-for-the-ble-advertisement.md) chose a legacy advertisement for reach rather than for size. Rejected without measurement, because the restriction under discussion is on the key and not on the length.

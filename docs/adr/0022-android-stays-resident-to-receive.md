# ADR-0022: Android stays resident to receive, once the app has been opened

- **Status**: Accepted
- **Date**: 2026-09-26
- **Supersedes**: [docs/02](../02-architecture.md#android)'s "continuous listening costs too much battery" for Tier 0 and 1, and [docs/08](../08-platform-integration.md#foreground-service)'s "started only during a transfer, never resident"

## Context

Run F, 2026-09-26, sent files with Japanese names between a phone, a MacBook and a Linux machine in all four directions, and a send to the phone arrived only while the app was in the foreground. **The person using it asked for the phone to receive at any time**, which is what M8's criterion, "sends and receives on all four devices", means to a person rather than to a test.

The design refused this on battery grounds and specified a `dataSync` foreground service started only for the length of a transfer. **That service was never built**: no manifest declares it and no Kotlin implements it, so today the listener lives exactly as long as Android lets the process live, which for a backgrounded app is minutes.

Three platform facts decide the shape:

- **Android 14 requires a foreground service to declare a type**, and caps `dataSync` at six hours a day from Android 15. A resident listener under `dataSync` would stop silently each afternoon
- **`connectedDevice` is the type for "interactions with external devices that require a Bluetooth, NFC, IR, USB, or network connection"**, and it requires holding one of a listed set of permissions; `CHANGE_WIFI_MULTICAST_STATE` is one, and it is the permission mDNS needs anyway
- **Wi-Fi drivers filter multicast while the screen is off** unless a `WifiManager.MulticastLock` is held, so a resident listener that does not hold one can be dialled by a peer that already knows its address and cannot be discovered by one that does not

## Decision

**Once the app has been opened, a `connectedDevice` foreground service keeps its process alive, and the listener already running in that process keeps receiving, until the person stops it.** Decided by the user on 2026-09-26, choosing this over starting at boot and over a setting.

- **It starts when the plugin loads**, which happens with the app's Activity in the foreground -- the one moment Android 12 and later permit starting a foreground service without an exemption. It is not started at boot: after a reboot the person opens the app once
- **Its notification is permanent and says the device is ready to receive**, with one action, Stop. Android requires the notification; it is also the only honest indicator that a radio-holding process is running
- **Stop ends the service and the process**, so "stopped" means a peer cannot reach it. Leaving the process to be reclaimed later would make Stop mean "stop, eventually"
- **It holds a `MulticastLock` for as long as it runs**, released when it stops, so discovery works with the screen off
- **The receive path is unchanged.** The service keeps a process alive; it does not run a listener of its own, change what is accepted, or add a second route into Rust

## Consequences

- **Battery is the cost, and it is unmeasured.** A held multicast lock keeps the Wi-Fi radio waking for every multicast packet on the LAN. The first run with this build measures it: the phone's battery use over a night with the service running, against a night without
- **Doze and vendor battery managers are the other unmeasured half.** Whether a send arrives after the screen has been off for an hour is the run's second question; a vendor that kills foreground services regardless is answered by the person marking the app unrestricted, which this ADR records rather than automates
- The manifest gains `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE` and `CHANGE_WIFI_MULTICAST_STATE`, and loses `FOREGROUND_SERVICE_DATA_SYNC`, which nothing used
- **A transfer-length progress notification**, which docs/08 also specified, is not part of this decision and stays unbuilt

## Alternatives rejected

- **`dataSync`, as specified**: the six-hour cap ends it without saying so
- **Start at boot**: offered to the user, declined in favour of opening the app once after a reboot
- **A Brokr and FCM**: Tier 2 only, and [ADR-0005](0005-brokr-is-optional.md) makes Tier 0 receiving the thing that must work without one

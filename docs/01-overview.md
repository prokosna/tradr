# 01. Overview

## The problem

Moving a file between two devices you own is harder than it has any right to be. Every existing option carries a defect.

| Approach | Defect |
|---|---|
| Cloud storage | Wait for the upload, then wait for the download. Round-trips to a datacenter even when both devices sit on the same LAN. Capacity and privacy limits. |
| Quick Share / AirDrop | Requires matching OS and vendor. Linux is left out almost entirely. |
| USB drive | Requires physically touching both devices, which on Android is especially tedious. |
| Messaging yourself | Recompressed images, mangled filenames, polluted history. |
| Syncthing and similar | Every new device needs a key exchange. It synchronizes rather than hands over, which is heavy for sending one file one way once. |

Tradr makes files move freely inside two circles — the devices one person owns, and the devices of people they have explicitly trusted — without the user thinking about which path the bytes take.

## Who it is for

- **Primary**: developers and creators who use several operating systems daily — a Linux desktop, an Android phone, a work-issued Mac. Including those already running an overlay network such as Tailscale.
- **Secondary**: families and small teams who exchange files repeatedly with a small, fixed set of people.

## Core use cases

### UC-1: Send to your own device (the common case)
A file being worked on at the desktop needs to reach an Android phone. Drag it onto the device tile and it arrives. Same account, so no approval is needed on the far side — configurable.

### UC-2: Send from Android through the share sheet
Pick a file in the Android file manager or gallery, tap Share, choose Tradr, pick a destination. On Android 14 and later, recent destination devices appear directly in the share sheet itself.

### UC-3: Browse a peer's directory
Register `~/Documents/scan` on the desktop as a Share Root, and everything beneath it becomes listable, viewable, and downloadable from Android. Set it to `rw` and files can be written back.

### UC-4: Send to another person
Link their Google account once, which requires approval from both sides. Their devices then appear in your destination list and UC-1 applies unchanged. Share Roots can be exposed per person.

### UC-5: Hand something over with no network
With no Wi-Fi anywhere, devices still find each other over Bluetooth and can pass text, URLs, and small files. Larger files queue up as waiting for a network.

### UC-6: Reach a machine on another network (optional setup)
Sending from a laptop away from home to the desktop at home has two answers.

- **Running an overlay network already**: register the peer as a Static Peer and nothing else is needed. Tradr adds no infrastructure and rides the tailnet's existing reachability.
- **Not running one**: deploy a Brokr and register it from both devices. NAT hole punching is attempted first, and only when that fails does ciphertext get relayed.

## Serverless by construction

**Tradr is complete without a backend.** This is a central constraint rather than something to add later, so it is settled up front.

- Discovery runs on mDNS for the LAN and BLE for proximity. Neither needs a central index.
- Devices authenticate each other with a Google-signed Attestation (see [05](05-security.md)). Verification needs only Google's public keys; Tradr operates no authentication service.
- Transfers go device to device.
- Accounts are linked by handing over a QR code or an invite blob.

A **Brokr** is an optional layer on top, adding exactly three things.

1. Discovery across networks, by aggregating presence
2. Rendezvous for NAT traversal, by exchanging address candidates
3. Relay when nothing connects directly, forwarding ciphertext only

**A Brokr going down changes nothing about LAN and proximity behaviour.** CI verifies this continuously — see [09](09-roadmap-and-risks.md).

## Scope

### Platforms

| OS | Standing | Notes |
|---|---|---|
| Linux (x86_64, aarch64) | First class | The primary development environment. Assumes BlueZ and D-Bus. |
| Windows 11 | First class | Windows 10 is best-effort; its BLE stack is unreliable. |
| macOS 13+ | First class | Apple Silicon and Intel. |
| Android 10+ | First class | API 29 and up. Absorbs the differences in BLE and SAF behaviour. |
| iOS | **Future** | Not built now, but the protocol and permission model are shaped to satisfy iOS constraints — see [08](08-platform-integration.md). |

A Brokr must run as a single Linux container, published for x86_64 and aarch64.

### In scope

- Google sign-in and the device-to-device authentication built on it
- Discovery among same-account and linked-account devices over mDNS, BLE, static pins, and a Brokr
- File and directory transfer, resumable and integrity-checked
- Exposing and remotely browsing Share Roots
- Automatic path selection
- End-to-end encryption, so that even relayed bytes stay opaque to the Brokr
- Self-hosting a Brokr from one container and one configuration file

### Non-goals

Decisions to **not** do something. A request to revisit any of these gets an ADR.

- **Two-way sync.** No continuous synchronization in the manner of Dropbox or Syncthing. That drags in conflict resolution, deletion propagation, and partial sync — a problem set fundamentally at odds with handing a file over. Browsing a Share Root is read-through, not sync.
- **A hosted service operated by us.** A Brokr is designed for self-hosting only. Multi-tenant billing, abuse handling, and SLAs constitute a different product.
- **Durable storage on a Brokr.** Relay is a transient buffer, deleted on TTL expiry or on receipt.
- **Content inspection or transformation on a Brokr.** No thumbnailing, no virus scanning, no full-text search. None of it survives contact with end-to-end encryption.
- **Google Drive integration.** Google sign-in establishes identity and nothing else. The Drive API is never called.
- **Public sharing.** No public URLs. Destinations are always authenticated devices.
- **One-to-many broadcast.** One transfer goes to one device. Multiple destinations are multiple transfers.
- **Identity providers other than Google.** Google only in v1. The Attestation mechanism rests on the standard OIDC `nonce`, so extending to other OIDC providers stays possible.

## Success criteria

| Measure | Target |
|---|---|
| 1 GB over the same LAN | Under 30 seconds, meaning 35 MB/s or better |
| 1 GB over Tailscale | At least 80% of the path's available bandwidth |
| Actions to complete a send | One drag and drop, same account |
| Time to discover a device | Under 2 seconds on the same LAN, under 10 seconds over BLE |
| Resuming an interrupted transfer | Automatic, retransmitting only the lost chunks |
| **Feature coverage with no Brokr** | UC-1, UC-2, UC-3, and UC-5 all fully working |
| **Behaviour when a Brokr goes down** | Every Tier 0 and Tier 1 feature continues undegraded |

The last two act as design constraints. A Brokr assists discovery and reachability; it must never become a required leg of a transfer.

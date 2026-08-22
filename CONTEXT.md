# CONTEXT — the Tradr domain language

This file is the single source of truth for the vocabulary used in code and documentation. When implementation introduces a new concept, update this file.

## Actors

| Term | Definition |
|---|---|
| **Account** | One account at an identity provider. Identity is the pair `(iss, sub)`, never the email — emails change, and a `sub` is unique only within its issuer. Google is the only provider shipped. |
| **Device** | One installation of Tradr. One device means one key pair and one Attestation. |
| **Peer** | The device on the other side of a transfer. Covers both your own devices and those of a linked account. |
| **Brokr** | The **optional** self-hosted backend. Adds cross-network discovery, NAT traversal assistance, and relay. Tradr works without it. |

Calling it a Brokr rather than "the server" is deliberate. "Server" implies required infrastructure and misrepresents what this product is.

## Trust

| Term | Definition |
|---|---|
| **Device Key** | A device's long-lived key material: Ed25519 for signing and identity, X25519 for key agreement. It never leaves the device. |
| **Device ID** | The first 16 bytes of `BLAKE3(ed25519_public_key)`. A device's permanent identifier. |
| **Attestation** | A provider-signed ID token whose `nonce` claim is `BLAKE3(device_public_keys)`. On its own it proves that the holder of a given `(iss, sub)` controls a given Device Key, verifiable against the provider's public keys alone. Tradr's root of trust. |
| **Provider Profile** | Everything verification needs to know about one identity provider: issuer, JWKS URI, client ID set, nonce binding, renewal terms. The only place a provider is named. |
| **Account ID** | `iss || 0x00 || sub`. The input to every value derived from account identity — never the bare `sub`. |
| **Fingerprint** | A Device Key encoded as human-readable words, equivalent to a Signal safety number. Used for out-of-band verification. |
| **Trust Tier** | How much a peer is trusted: `same-account`, `linked`, or `nearby-ephemeral`. |
| **Link** | A mutually consented relationship between two Accounts. A one-sided invitation never establishes one. |
| **Link Secret** | 32 bytes shared by both sides of a Link. Identifies linked peers over BLE and proves the link. |
| **Account Broadcast Key** (ABK) | 32 bytes shared by all devices of one Account. Identifies same-account peers over BLE. Handed over when devices first meet. |
| **EID** (Ephemeral Identifier) | The rotating identifier broadcast over BLE. Derived from an ABK or Link Secret plus the current time, rotating every 15 minutes, so no permanent ID ever goes on the air. |

## Sharing

| Term | Definition |
|---|---|
| **Share** | A definition exposing a directory on a Device to a given Audience. Carries a root, a mode, and an audience. |
| **Share Root** | The directory a Share exposes. Nothing outside it is ever reachable. |
| **Audience** | Who may see a Share: `account` (all devices of your account) or a set of `link:<link_id>`. |
| **Mode** | A Share's permission: `ro` (read only) or `rw` (write and delete allowed). |
| **VFS** | The abstraction over a Share Root that presents POSIX paths and Android SAF URIs through one interface. |

## Transfer

| Term | Definition |
|---|---|
| **Transfer** | One send operation, containing one or more Items. Its ID is unique across devices. |
| **Item** | One file within a Transfer, with a relative path, a size, and a Content Hash. |
| **Chunk** | A fixed-size block of an Item. The unit of transfer, resumption, and verification. |
| **Content Hash** | The BLAKE3 hash of a file's contents. Because BLAKE3 is a tree, per-chunk verification derives from this hash alone. |
| **Offer** | The sender's proposal, awaiting the receiver's Accept or Reject. |
| **Resume Offset** | The chunk position the receiver already holds. Carried in the Accept so the transfer picks up mid-stream. |

## Paths

| Term | Definition |
|---|---|
| **Transport** | What actually moves bytes: `direct-quic`, `wifi-direct`, `holepunch-quic`, `ble-gatt`, or `relay`. |
| **Candidate** | One way a Peer might be reachable: an address paired with a Transport kind. |
| **Path Selection** | Racing every Candidate in parallel and taking the first and fastest to establish. Not a one-time decision — it is revisited mid-transfer. |
| **Static Peer** | A reachable hostname or address the user pinned by hand. How overlay networks such as Tailscale are used without a Brokr. |
| **Rendezvous** | The Brokr's role in exchanging address candidates between peers. No file bytes pass through. |
| **Relay** | A path where the Brokr forwards ciphertext. The Brokr never sees plaintext. |

## Tiers

| Tier | Requires | Provides |
|---|---|---|
| **Tier 0 — Standalone** | Nothing | Discovery and transfer on the same LAN and in proximity. Share browsing. |
| **Tier 1 — Pinned** | A reachable address for the peer | Direct connections across overlay networks (Tailscale, WireGuard, ZeroTier) or fixed IPs. |
| **Tier 2 — Brokered** | A deployed and registered Brokr | Discovery from anywhere, NAT traversal, relay, delivery to offline devices. |

## Development process

| Term | Definition |
|---|---|
| **Supervisor** | The expensive model that instructs, reviews, tracks progress, and decides on design. The only role that may edit `docs/` and `STATE.md`. Does not write ordinary implementation code. |
| **Implementer** | The cheap model that implements a Work Item. Never edits `docs/` or `STATE.md`, never changes the design on its own. |
| **Work Item** | The unit of instruction, review, and record. Small enough to judge in one review — roughly 400 lines and 8 files. |
| **Work Order** | The Supervisor's instruction to the Implementer: target, referenced design, definition of done, constraints, prohibitions. |
| **DCR** (Design Change Request) | The Implementer's stop request when implementation reveals a design problem. The Supervisor rules on it, and if accepted, `docs/` changes first. |
| **Verdict** | A review outcome: `PASS`, `REVISE`, or `REDESIGN`. |
| **Critical Module** | A module whose tests the Supervisor writes first and whose implementation the Implementer then makes pass. Covers boundary enforcement, Attestation verification, chunk resumption, and filename sanitization. |
| **Change Drill** | Measuring flexibility against external change by counting the files a hypothetical change would touch. |

## Usage notes

- Never write "server". The optional backend is always a **Brokr**; the listening side of a transfer is the **receiver**.
- "Connect" refers to establishing a Transport. Account linking is always **link**, never mixed with connect.
- Never write "sync". Tradr does not synchronize — see the non-goals in [docs/01-overview.md](docs/01-overview.md). It transfers and it browses.
- "Log in" refers only to authenticating with Google. Tradr has no login of its own; attaching to a Brokr is **register**.

# 13. Deferred Delivery, and the Brokr that carries it

> Decided 2026-10-03 by DCR-173, from three answers the person using Tradr gave that day: **what is wanted first is sending to a device that is offline**; **the Brokr runs inside the tailnet**, on a machine at home, not on the public internet; and **a parked delivery is held for 30 days**, with its size limits set by whoever deploys the Brokr. This document is M9's design. [docs/07](07-brokr.md) remains the design of the whole Brokr; what is built now is the part below, and the rest of docs/07 -- rendezvous, relay, FCM wake-up, linking through a Brokr, the revocation list -- is deferred to a later milestone.

## What it is

**Deferred Delivery** ([CONTEXT.md](../CONTEXT.md)): a Transfer the sender hands to a Brokr for a device that is not online, collected when that device next is. One direction, one Transfer, no reconciliation and no shared state. **It is not sync**, and nothing here converges.

What a person sees:

1. A device that is not reachable now still appears in the device list if this device has met it before, marked "offline". With a Brokr configured, tapping it with files waiting says **"It's offline -- Tradr will deliver this when it's back"** and hands the files to the Brokr.
2. The sending device shows the delivery as **waiting** until the recipient collects it, then **delivered**; after 30 days uncollected, **expired**.
3. The recipient collects pending deliveries whenever it is running and reaches the Brokr, and each arrives in **Received** like any other file, from the sending device's name.

Without a Brokr configured, an offline device stays in the list, greyed, with "offline", and cannot be tapped to send. **Tier 0 and Tier 1 are untouched** ([ADR-0005](adr/0005-brokr-is-optional.md), invariant I1): everything here is additive, and the `no-brokr` job keeps proving it.

## Where the trust lives

The Brokr is outside the circle of trust, as docs/07 requires, and this feature has to work with a Brokr that is compromised. **A compromised Brokr can delay, drop or duplicate a delivery, and nothing else**: it cannot read one, alter one undetected, substitute a recipient's key, or make a delivery appear to come from a device it did not come from.

Three consequences, each a rule:

- **A device sends only to devices it has met.** The recipient's public keys come from a **Known Devices** record this device wrote after a direct, verified handshake with it (docs/05's seven steps, and the key join), never from the Brokr. The Brokr could otherwise hand a sender any key it liked. This is also what puts an offline device in the list at all. It answers the remembering half of DF-108 and nothing more: a changed key on a known Device ID is recorded, not yet refused.
- **The Brokr learns no identity.** It never sees an Attestation, because an Attestation carries the Google `sub` and email, which invariant I3 keeps from every Brokr. The sender's Attestation travels **inside** the encrypted delivery. The recipient verifies it, through the seven steps, when it collects.
- **Filenames and sizes per file are inside the encryption.** What the Brokr sees is a recipient Device ID, a sender Device ID, a total size, an upload time and an opaque body.

## The envelope

**The format is [ADR-0025](adr/0025-hpke-for-deferred-delivery.md): HPKE in base mode (RFC 9180) to the recipient's agreement key, `DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`**, with the sender authenticated by a signature from its identity key rather than by HPKE's own auth mode.

```
outer header, readable by the Brokr (routing only)
  version              1
  recipient_device_id  16 bytes
  sender_device_id     16 bytes
  enc                  65 bytes, the HPKE encapsulated key
  total_ciphertext_len u64

records, each sealed with the HPKE context, sequence numbers from 0
  record 0       the manifest
  record 1..n    the items' bytes, 1 MiB of plaintext per record (invariant I6),
                 items back to back in manifest order
```

- **The HPKE `info`** is `"tradr-deferred-v1" || recipient_device_id || sender_device_id`, so an envelope cannot be re-addressed.
- **Each record's associated data** is its sequence number and a final-record flag, so records cannot be reordered, dropped from the end or truncated without the last one failing to open. HPKE's own sequence-numbered nonces do the rest.
- **The manifest** carries: the `transfer_id`, the sender's `identity_pub`, `KeyBinding` and Attestation token, `created_at` from the sender's `Clock`, the items (relative path, size, Content Hash), and a **signature by the sender's identity key under a new domain tag, `DeferredDelivery`**, over `enc || recipient_device_id || sender_device_id || created_at || transfer_id || the items`. A domain tag of its own is what stops this signature being replayed as any other (docs/05, "Every signature carries a domain tag").
- **The recipient accepts an envelope only when** it opens, the signature verifies under the manifest's `identity_pub`, that key's Device ID equals `sender_device_id`, the `KeyBinding` joins the identity key to an agreement key, the Attestation passes docs/05's seven steps for that `identity_pub`, and the Trust Tier is `same-account` or `linked`. **Staleness is judged at `created_at`, and `created_at` must be within the last 30 days and not more than 300 seconds ahead of the recipient's clock**: an Attestation that was fresh when its holder sent is honoured for as long as the Brokr may hold the delivery, which bounds how stale an accepted Attestation can be at 60 days. That is a weaker revocation story than a live connection's 30, and it is stated rather than hidden.
- **Each item is verified against its Content Hash as it is written**, placed through the ordinary receive path (sanitised names, `.tradr-partial`, `rename_no_replace`), and reported in `files-received`.

**The code lives in `tradr-identity`** (ADR-0025). **This is a Critical Module.** Opening an envelope is where a forged delivery would be accepted, so the Supervisor writes its tests first: RFC 9180's published test vectors for the suite, a negative test per acceptance check, truncation, reordering and re-addressing.

## The Brokr, as built in M9

**A small HTTP service, TypeScript on Fastify with SQLite**, as docs/09 planned, in `apps/brokr`, run as one container. **Inside the tailnet it listens on plain HTTP by default**: WireGuard already encrypts the hop, and every body it carries is end-to-end encrypted. TLS can be put in front by a reverse proxy or `tailscale serve`. Nothing in the client assumes either.

| Method | Path | What it does |
|---|---|---|
| `GET` | `/v1/info` | Version, the limits below, and this deployment's `account_salt` |
| `POST` | `/v1/challenge` | A fresh nonce for one registration |
| `POST` | `/v1/register` | `device_id`, `identity_pub`, `join_token`, `account_tag`, `link_tags[]`, and a signature over `"tradr-brokr-v1" \|\| nonce` (docs/07's `BrokrChallenge` tag). Answers a session token |
| `PUT` | `/v1/deliveries` | Upload one envelope. The outer header is read and checked against the caller's own Device ID and the size limits; the body is stored as it arrives, never buffered whole |
| `GET` | `/v1/deliveries/inbox` | Deliveries addressed to the caller: id, sender Device ID, size, upload time |
| `GET` | `/v1/deliveries/:id` | Download one, streamed. Only its recipient may |
| `DELETE` | `/v1/deliveries/:id` | The recipient's acknowledgement, after every item has been placed. The body is deleted at once |
| `GET` | `/v1/deliveries/outbox` | The caller's own uploads: waiting, delivered (with when), or expired |

- **Who may address whom is the Brokr's one policy, and it is a grouping, not an identity**: a delivery is accepted only when sender and recipient share the `account_tag` or a `link_tag`, as docs/07 defines them. `account_tag` is `BLAKE3(account_id || account_salt)` with this deployment's salt, so two Brokrs cannot correlate a person.
- **Limits, set at deployment**: `BROKR_DELIVERY_TTL_DAYS` (30), `BROKR_DELIVERY_MAX_BYTES` (no default: the operator chooses), `BROKR_STORAGE_MAX_BYTES` (likewise), and a per-sender cap on deliveries waiting. Exceeding one is answered with its reason, which the sender shows.
- **Expiry is swept** at start and hourly: the body is deleted and the outbox says expired. The database records that a delivery existed for as long as its row is kept (30 days after it ends), and docs/07's logging rules hold: no Device IDs in logs by default.
- **Losing the database loses only what was waiting**, as docs/07 says of relay sessions; devices register again with the join token.

## Running the Brokr

**One container, one volume, four settings.** The image is built from `apps/brokr/Dockerfile` at the repository root as its build context; it runs as a user that is not root, listens on 8780, and keeps everything it owns -- the database and the deliveries waiting -- under `/data`.

```sh
docker build -f apps/brokr/Dockerfile -t tradr-brokr .
docker run -d --name tradr-brokr --restart unless-stopped \
  -p 8780:8780 -v tradr-brokr-data:/data \
  -e BROKR_JOIN_TOKEN="$(openssl rand -hex 24)" \
  -e BROKR_DELIVERY_MAX_BYTES=10737418240 \
  -e BROKR_STORAGE_MAX_BYTES=107374182400 \
  tradr-brokr
```

- **`BROKR_JOIN_TOKEN`** is what a device presents once, to register; choose it and keep it (`BROKR_JOIN_TOKEN_FILE` reads it from a file instead). **`BROKR_DELIVERY_MAX_BYTES`** and **`BROKR_STORAGE_MAX_BYTES`** have no default on purpose: how much one delivery and all of them together may occupy is the operator's disk to budget. The example allows 10 GiB per delivery and 100 GiB in all. `BROKR_DELIVERY_TTL_DAYS` defaults to 30.
- **Reach it over the tailnet, not the internet**: publish the port only on the machine's tailnet address (`-p 100.x.y.z:8780:8780`) or leave it on the LAN, and give devices `http://<that machine's tailnet name>:8780`. Nothing it carries is readable to it, but nothing about it is hardened for the open internet either.
- **On each device**: Settings, "Deliver when a device is offline", the address and the join token, Connect. A device has to have met another directly once before it can send to it while it is offline.
- **Health**: `GET /v1/health` answers `{"ok":true}`; the image's health check calls it.
- **Losing the volume loses what was waiting and nothing else**: devices register again by themselves with the same join token.

## The device side

- **Configuration**: Settings gains **"Brokr"**: its address and the join token, or a `tradr://brokr?url=...&token=...` link, and the connection's state. Sharing it to the account's other devices over their Noise channels (docs/07 step 4) is not in M9.
- **Registration** happens when configured and whenever the session token is refused. `account_tag` is `BLAKE3(account_id || salt)` over the **bytes** of `account_salt` (16 bytes, sent as hex), and each `link_tag` is `BLAKE3(link_secret)`.
- **The client speaks to the Brokr through a port, `BrokrApi`**, so a Brokr rewritten in another language changes nothing on the device (Change Drill D6). **Its HTTP implementation is the one place outside `tradr-oidc` allowed to name `reqwest`, decided 2026-10-05 by DCR-174**: `tradr-app`'s `src/brokr/http.rs` and no other file. DCR-024 confined `reqwest` because retrieving a JWKS is a Critical Module whose whole security is TLS to the provider's own host, so a second, less careful HTTP client in the workspace was the risk. The Brokr's traffic is different in kind -- an end-to-end encrypted envelope and a signature over a nonce -- and a compromised path to it can delay or drop a delivery and nothing more ("Where the trust lives"). So the confinement is kept and widened by exactly one file: `ci/layer-deps.sh` refuses `reqwest` in any other manifest, and refuses it in any `tradr-app` source but that one. The adapter never follows a redirect, accepts `http://` and `https://` only, and is never used to fetch a JWKS.
- **Collecting** runs at start, when the app comes to the foreground, and every 5 minutes while it runs; on Android also while resident (ADR-0022). Each pending delivery is downloaded, opened, verified, placed and acknowledged; a delivery that fails verification is acknowledged and dropped, and reported once, because keeping it would only repeat the failure.
- **Sending** to an offline known device, with a Brokr configured, reads each file twice -- once to compute its Content Hash, which the manifest at the head of the envelope carries, and once to stream it into the envelope as it is uploaded, never holding a file whole -- and records the delivery id with the names it sent, since the Brokr knows neither; a file that changed between the two passes fails the recipient's hash check, by design; the outbox is polled with the inbox and drives "waiting / delivered / expired".
- **Known Devices** is a local registry beside the Link registry: `DeviceId` to `PublicIdentity`, the last display name, the Trust Tier, and when it was last seen directly. It is written after every successful direct handshake, in either direction, and read by the device list and the envelope builder.

## What is deliberately not here

- Rendezvous, NAT traversal, relay of live transfers, FCM wake-up, linking through a Brokr, and the revocation list: later, as docs/07 designs them
- A WebSocket: polling every 5 minutes is enough for a delivery that waits for days, and it is one less long-lived connection to keep on a phone
- Refusing a changed key on a known Device ID: DF-108's decision, still open
- Distributing the Brokr's configuration between devices automatically

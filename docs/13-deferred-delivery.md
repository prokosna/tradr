# 13. Deferred Delivery and the Brokr

A Transfer handed to a Brokr for an **offline** device, and collected when that device is next online. One way, one Transfer. **It is not sync.** It is Tier 2 only; Tier 0 and Tier 1 are untouched (I1, `no-brokr`).

The Brokr runs **inside the tailnet**, at home. Deliveries are held for 30 days.

## User-visible behaviour

- A device that has been met before but is not reachable now stays in the list as "offline".
- With a Brokr configured, tapping it with files waiting shows "It's offline -- Tradr will deliver this when it's back". The sender sees waiting, then delivered, or expired.
- The recipient collects at start, on foreground, every 5 min, and while resident. Files arrive in Received.
- Without a Brokr, offline tiles are greyed and cannot be tapped.

## Trust: a compromised Brokr can delay, drop or duplicate, and nothing else

- **A device sends only to devices it has met.** Recipient keys come from **Known Devices** (written after every verified direct handshake), never from the Brokr. A changed key is recorded, not refused.
- **The Brokr learns no identity.** The sender's Attestation travels inside the encryption. The Brokr sees recipient and sender Device IDs, total size, time, and an opaque body.

## Envelope ([ADR-0025](adr/0025-hpke-for-deferred-delivery.md); Critical Module, `tradr-identity`)

HPKE base mode: `DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`, to the recipient's agreement key.

```
outer header (Brokr-readable): version=1 | recipient_device_id 16 | sender_device_id 16 | enc 65 | total_ciphertext_len u64
records (HPKE seq from 0): [0] manifest, [1..n] item bytes, 1 MiB plaintext each, items back to back
info = "tradr-deferred-v1" || recipient_id || sender_id
AAD  = seq || final_flag
```

The manifest holds `transfer_id`, the sender's `identity_pub`, KeyBinding, Attestation token, `created_at`, and the items (path, size, hash). It is signed with domain tag `tradr-deferred-v1` over `enc || recipient_id || sender_id || created_at || transfer_id || items`.

**Accept only if** all of the following hold:
- the envelope opens;
- the signature verifies;
- the key's DeviceId equals `sender_device_id`;
- the KeyBinding is valid;
- the Attestation passes the seven steps, **with staleness judged at `created_at`**;
- `created_at` is within the last 30 days and at most 300 s in the future;
- the tier is `same-account` or `linked`.

An accepted Attestation can therefore be up to 60 days old; this is documented. Items are verified against their hash as they are written and placed through the normal receive path.

Tests: RFC 9180 vectors, a negative test per acceptance check, truncation, reordering, re-addressing.

## Brokr (`apps/brokr`: TypeScript, Fastify, SQLite)

Plain HTTP inside the tailnet. Put TLS in front with a reverse proxy or `tailscale serve` if wanted.

| Method | Path | |
|---|---|---|
| GET | `/v1/health` | `{"ok":true}` |
| GET | `/v1/info` | version, limits, `account_salt` |
| POST | `/v1/challenge` | nonce |
| POST | `/v1/register` | `device_id`, `identity_pub`, `join_token`, `account_tag`, `link_tags[]`, signature over `tradr-brokr-v1 || nonce`. Returns a session token |
| PUT | `/v1/deliveries` | upload, streamed; the header is checked against the caller and the limits |
| GET | `/v1/deliveries/inbox` | deliveries addressed to the caller |
| GET | `/v1/deliveries/:id` | download (recipient only) |
| DELETE | `/v1/deliveries/:id` | ack after placement; the body is deleted |
| GET | `/v1/deliveries/outbox` | waiting / delivered / expired |

- Addressing policy: sender and recipient must share an `account_tag` (`BLAKE3(account_id || salt bytes)`) or a `link_tag` (`BLAKE3(link_secret)`).
- Limits: `BROKR_DELIVERY_TTL_DAYS` (default 30). `BROKR_DELIVERY_MAX_BYTES` and `BROKR_STORAGE_MAX_BYTES` have **no default**. There is also a per-sender cap on waiting deliveries.
- Expiry sweep at start and hourly. No Device IDs in logs. Losing the DB loses only what was waiting.

### Running it

```sh
echo 'BROKR_JOIN_TOKEN=<phrase>' > .env    # git-ignored; compose refuses to start without it
docker compose up -d --build              # docker-compose.yaml: port 8780, /data volume, 10 GiB / 100 GiB limits
```

Publish it only on the tailnet or the LAN (`-p 100.x.y.z:8780:8780`). Registration is not rate-limited.

## Device side

- **`BrokrApi` port**. Its HTTP implementation is `crates/tradr-app/src/brokr/http.rs`, the **only file outside `tradr-oidc` allowed to name `reqwest`** (enforced by `ci/layer-deps.sh`). It follows no redirects, accepts http/https only, and never fetches a JWKS.
- Registration happens when configured and whenever the session token is refused.
- **Collect**: download, open, verify, place, ack. A delivery that fails verification is acked, dropped and reported once.
  - The ids of placed deliveries are written to `collected.json` **before** the ack is sent, so a failed ack does not cause a second placement. A remembered id is acked without being downloaded.
  - A crash between placing the files and writing the id can still place them twice.
- **Send**: two passes per file (hash for the manifest, then stream it into the upload). The delivery id is recorded with the file names for the outbox view.
- **Known Devices**: `DeviceId → PublicIdentity`, last name, tier, last seen.

### Brokr link

```
tradr://brokr?url=<http(s) url, no path>&token=<join token>
```

- One parser and one writer, both in `tradr-app::brokr`.
- Unknown parameters are ignored. A missing, duplicated or empty `url` or `token` is refused.
- `connect_brokr_link` takes the pasted link (whitespace trimmed). `brokr_link` returns the link, only on **Show link**.
- **The link is the token**: never log it, and never echo it in errors.
- The OS does not register `tradr://`, and there is no QR. The link is pasted.

## Not here

Rendezvous, relay, FCM, linking through a Brokr, the revocation list, a WebSocket, automatic config sharing between devices.

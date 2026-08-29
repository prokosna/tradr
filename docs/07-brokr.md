# 07. Brokr (optional component)

## Where it stands

A Brokr is designed on the premise that **Tradr works without one**. CI holds that premise up by continuously verifying that every Tier 0 and Tier 1 integration test passes with no Brokr running.

### What it adds

| Capability | Without a Brokr | With a Brokr |
|---|---|---|
| Discovery on the same LAN | Yes, mDNS | Yes, mDNS, unchanged |
| Discovery in proximity | Yes, BLE | Yes, BLE, unchanged |
| Discovery across networks | Only by registering a Static Peer | Automatic |
| Direct connection through NAT | No | Yes, via rendezvous |
| When nothing connects directly | Cannot send | Relayed |
| Android background arrival | Only on screen-on | Yes, woken by FCM |
| Sending to an offline device | No | Yes, parked in relay for later |
| Immediate device revocation | Manual, per device | Yes, a pushed revocation list |

### What it does not add

- Authentication. Attestation verification always happens on a device against Google's JWKS. **A Brokr never talks to Google**
- Any view of file contents. Only Noise ciphertext traverses a relay
- Management of Share definitions, which exist only on devices
- A concept of user accounts. A Brokr knows a Device ID and an `account_tag`, being `BLAKE3(account_id || salt)`. It learns neither the issuer, nor the `sub`, nor an email address

**Keeping a Brokr outside the circle of trust is the central point of this design.** Self-hosted or not, it is the only component exposed to the internet and therefore the most likely to be compromised. What that compromise yields is minimized in advance.

## Deployment

One container is the requirement.

```yaml
# docker-compose.yml
services:
  brokr:
    image: ghcr.io/<org>/brokr:1
    ports: ["8443:8443"]
    volumes:
      - ./data:/data
    environment:
      BROKR_PUBLIC_URL: "https://brokr.example.com"
      BROKR_DB_URL: "sqlite:///data/brokr.db"
      BROKR_JOIN_TOKEN_FILE: "/data/join-token"
      BROKR_RELAY_MAX_BYTES: "5368709120"     # 5 GB per session
      BROKR_RELAY_TTL_HOURS: "24"
      BROKR_RELAY_STORAGE: "file:///data/relay"  # or s3://...
      BROKR_FCM_CREDENTIALS_FILE: "/data/fcm.json"  # optional
```

- **SQLite by default.** PostgreSQL exists as an option for hundreds of devices, but household and small-team use is well served by SQLite
- **Relay storage defaults to local files.** S3-compatible storage is optional
- TLS may terminate at a reverse proxy or in the Brokr itself

### Registering from a device

```
1. Deployment generates a join token, written to data/join-token
2. The user enters the URL and token in settings,
   or scans a QR or URL carrying both:
      tradr://brokr?url=https%3A%2F%2Fbrokr.example.com&token=...
3. The device opens a WebSocket, signs the challenge, and completes registration
4. Other devices on the account receive the Brokr configuration over their
   existing Noise channels, so nobody types it twice
```

A join token governs **whether registration is permitted** and nothing else. It carries no authentication duty, which belongs to the Attestation. It can be rotated without disturbing already-registered devices.

## API

### WebSocket `/v1/rt`

The primary channel. Messages follow `proto/tradr/v1/brokr.proto`.

```
Client                                     Brokr
  |---- WS connect ---------------------------->|
  |<--- BrokrChallenge { nonce } ---------------|
  |---- BrokrRegister {                         |
  |        device_id, identity_pub, join_token, |
  |        challenge_signature, account_tag,    |
  |        link_tags[], fcm_token }  ---------->|
  |<--- PeerList { peers[] } -------------------|
  |                                             |
  |  Presence changes arrive as pushes          |
  |<--- PresenceUpdate -------------------------|
  |                                             |
  |---- RendezvousOffer { to, candidates[] } -->|
  |                                             |--> forwarded to the peer
  |<--- RendezvousAnswer { from, candidates[] }-|
  |                                             |
  |---- RelayOpen { to, expected_bytes } ------>|
  |<--- RelayReady { session_id, urls, ttl } ---|
```

`challenge_signature` is a P-256 signature over `"tradr-brokr-v1" || nonce`, verified with `identity_pub`. **The domain tag is what stops a Brokr handing a device a peer's `Hello.nonce` as a challenge and replaying the answer** — see [docs/05](05-security.md#every-signature-carries-a-domain-tag). All it establishes is that the holder of the same key returned. Who that is stays unknown to the Brokr, which is correct.

### HTTP

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/info` | Version, feature flags, relay limits |
| `PUT` | `/v1/relay/:session_id` | Relay upload, chunked ciphertext |
| `GET` | `/v1/relay/:session_id` | Relay download |
| `DELETE` | `/v1/relay/:session_id` | Deletion after receipt |
| `POST` | `/v1/links/invite` | Issue a link code |
| `POST` | `/v1/links/redeem` | Redeem a link code |
| `POST` | `/v1/links/approve` | Inviter's approval, the second consent |
| `POST` | `/v1/revocations` | Register a device revocation |
| `GET` | `/v1/revocations` | Fetch the revocation list |

Relay URLs carry a short-lived signed token, so guessing a `session_id` gains nothing.

## Data model

```sql
CREATE TABLE devices (
  device_id       BLOB PRIMARY KEY,      -- 16 bytes
  identity_pub    BLOB NOT NULL,         -- SEC1 uncompressed P-256 point
  account_tag     BLOB NOT NULL,         -- BLAKE3(account_id || salt); the pair is never stored
  display_name    TEXT,
  platform        TEXT,
  fcm_token       TEXT,
  registered_at   INTEGER NOT NULL,
  last_seen       INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE INDEX idx_devices_account ON devices(account_tag);

CREATE TABLE device_link_tags (
  device_id  BLOB NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  link_tag   BLOB NOT NULL,              -- BLAKE3(link_secret)
  PRIMARY KEY (device_id, link_tag)
);
CREATE INDEX idx_link_tags ON device_link_tags(link_tag);

CREATE TABLE presence (
  device_id       BLOB PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
  reflexive_addr  TEXT,
  local_addrs     TEXT,                  -- JSON array
  connected_at    INTEGER,
  expires_at      INTEGER NOT NULL       -- expires when the heartbeat stops
);

CREATE TABLE relay_sessions (
  session_id      TEXT PRIMARY KEY,
  from_device_id  BLOB NOT NULL,
  to_device_id    BLOB NOT NULL,
  bytes_stored    INTEGER NOT NULL DEFAULT 0,
  max_bytes       INTEGER NOT NULL,
  storage_ref     TEXT,                  -- file path or S3 key
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER
);
CREATE INDEX idx_relay_expiry ON relay_sessions(expires_at);

CREATE TABLE link_invites (
  code            TEXT PRIMARY KEY,      -- six characters
  inviter_device  BLOB NOT NULL,
  invitee_device  BLOB,                  -- filled on redemption
  state           TEXT NOT NULL,         -- pending | redeemed | approved | expired
  payload_a       BLOB,                  -- each side's DeviceInfo, Attestation, half_secret
  payload_b       BLOB,                  -- the Brokr never interprets these
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
);

CREATE TABLE revocations (
  device_id     BLOB PRIMARY KEY,
  revoked_by    BLOB NOT NULL,           -- only a device sharing the account_tag may register one
  signature     BLOB NOT NULL,           -- signed by the declaring device
  revoked_at    INTEGER NOT NULL
);
```

Note what is absent: the issuer, the `sub`, email addresses, Share definitions, filenames, Link Secrets themselves, and file plaintext.

`link_invites.payload_a` and `payload_b` are opaque bytes the devices produced, forwarded verbatim. Attestations travel inside them, and the Brokr neither verifies them nor needs the ability to.

## NAT traversal

1. Both sides learn their reflexive address — what the Brokr observed as the source — from the WebSocket
2. `RendezvousOffer` and `RendezvousAnswer` exchange address candidates, including local addresses for hairpinning behind one NAT
3. Both sides send QUIC initial packets to every candidate of the other simultaneously
4. Whichever succeeds joins Phase 3 of path selection

Symmetric NAT on both ends defeats hole punching. That is a protocol-level limit, and such cases fall back to relay. No full TURN implementation is built; the relay substitutes for it.

A Brokr does not act as a STUN server. Reading the WebSocket's source address suffices, so no separate UDP STUN service is needed.

## Relay

The part of a Brokr that needs the most care. **Bandwidth and storage are finite, and the design says so.**

```
Sender                  Brokr                    Receiver
  |                        |                        |
  |- RelayOpen ----------->|                        |
  |                        |- WakePeer (FCM) ------>|
  |<- RelayReady ----------|                        |
  |                        |<- connect -------------|
  |- PUT /relay/:id ------>|                        |
  |   (Noise ciphertext)   |- GET /relay/:id ------>|
  |                        |   (the same ciphertext)|
  |                        |                        |
  |                        |<- DELETE /relay/:id ---|  receipt confirmed
  |                        |   deleted from storage |
```

- **Streaming is the normal case.** With the receiver connected, the Brokr passes bytes through without touching disk, propagating backpressure directly
- **An offline receiver means temporary storage**, deleted on TTL expiry — 24 hours by default — or on confirmed receipt
- Limits: bytes per session, concurrent sessions per device, total bytes per day. All configurable
- Exceeding a limit returns `ERROR_CODE_RATE_LIMITED`, and the device explains that relay capacity is exhausted and waits for a direct path
- **Only ciphertext passes.** The Noise keys exist only at the endpoints, leaving a Brokr no means of decryption

## Operations

### Monitoring

Prometheus metrics at `/metrics`. Nothing personally identifying is exported.

```
tradr_devices_registered
tradr_devices_online
tradr_relay_sessions_active
tradr_relay_bytes_total
tradr_relay_storage_bytes
tradr_rendezvous_attempts_total{result="direct|relay|failed"}
```

The `result` breakdown of `rendezvous_attempts_total` matters most: it is the measurement of whether hole punching is working.

### Logging

Device IDs are excluded by default. Debug logging can include them, but never the `account_tag`. The privacy meaning of retaining who-talked-to-whom is stated explicitly, including to a self-hosting operator.

### Backups

A Brokr's database is designed so that **losing it is not fatal**. If it is lost:

- Devices re-register with the join token, automatically
- Links survive, living on the devices
- Only in-flight relay sessions are lost, and those transfers resume

Backups are therefore recommended but not required — another consequence of the principle that a Brokr assists and does not hold the truth.

## Alternatives to running one

For anyone who wants Tier 2 capabilities without operating a Brokr:

| Want | Alternative |
|---|---|
| Reachability from another network | Tailscale, WireGuard, or ZeroTier with a Static Peer |
| Android background arrival | None. Tier 2 is required |
| Sending to an offline device | None. The sender waits for the peer to come online |

The documentation recommends an overlay network first. For anyone who already has one, a Brokr is pure additional operational burden, and recommending it would be wrong.

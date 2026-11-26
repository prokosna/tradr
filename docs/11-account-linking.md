# 11. Account linking

A **Link** connects two Google accounts. **Both sides must consent**; a one-sided invite establishes nothing. Linking is per account, not per device: a new device on Bob's account is `LINKED` to Alice automatically.

## Flow (Tier 0, in person or by paste)

```
Alice (inviter)                                Bob (replier)
show Invite (QR or base64url blob), 5 min
                                               paste/scan → show Alice's Fingerprint + expiry → consent
                                               find Alice: BLAKE3(identity_pub)[0..16] in own peer list
                                               dial with PeerExpectation::Device  (the invite is the pin)
            ←── LinkReply (0x0c) on a fresh Control stream ──
verify Bob (steps 1-5 + key join, no step 6)
show Bob's Fingerprint → person approves
store Link (secret first, then record)
            ── LinkApprove(invite_id, link_id) (0x0d) ──→   verify link_id matches, store, close
            or LinkDecline(invite_id, reason)  (0x0e)
```

```
Link Secret = BLAKE3::derive_key("tradr-link-v1", half_A(inviter) || half_B(replier))   32 B
link_id     = BLAKE3(Link Secret)[0..16], lowercase hex
```

### Invite

Format: `0x01` version byte, then a protobuf body, base64url without padding. The QR encodes the same string. A blob is about 1.7 KB, mostly the `id_token`. Parsing rejects anything longer than 4096 chars. A QR at low error correction fits about 2953 bytes; if the invite will not fit, the UI says to use paste.

| Field | Rule |
|---|---|
| `invite_id` (16 B), `identity_pub`, `agreement_pub` (65 B each), `attestation.id_token`, `half_secret` (16 B), `expires_at` (non-zero unix secs) | refuse the invite if invalid |
| `display_name` | the device's advertised name; dropped if invalid |
| `sub`, issuer/iat copies, `device_id`, platform, caps | not carried or ignored; the token is authoritative, and the Device ID is recomputed |

`LinkReply` carries the same fields minus `expires_at`. It has no nonce and no KeyBinding, because the channel is already authenticated and the key join ties the message to it.

### Rules

- **Window**: an open invite authorises exactly one inbound link stream. Only codes 0c-0e are allowed on it; nothing else is reachable. Step 6 cannot be expressed there ([05](05-security.md)).
  - A reply naming any other `invite_id` is refused without verification and **does not close the window**, so strangers cannot cancel it.
  - The window closes on the first approve or decline, or at expiry.
  - Showing a new invite is refused while a decision is pending; otherwise it replaces the old one.
- **One deadline**: `expires_at` also bounds the wait on a person. The inviter declines with `InviteExpired` when it passes. The replier waits until `expires_at` plus the clock-skew allowance, so the inviter's deadline always comes first.
- On Bob's side, expiry is advisory and is shown, not enforced (Alice enforces it). Bob replies with exactly the blob he previewed.
- Decline reasons: user declined, invite expired, verification failed. A failed store declines with no reason.
- **The inviter stores before approving**, then `finish()`es and waits for Bob to close (see [04](04-protocol.md#link-stream)). A lost approve leaves a half link; the fix is to remove it and link again.

## Link record (`links.json`, whole-file atomic write)

```jsonc
{ "links": [ { "link_id": "3f1c…", "peer_iss": "https://accounts.google.com", "peer_sub": "9273…",
               "peer_label": "Bob", "created_at": 1756684800, "full_access": false } ] }
```

- The secret lives in the key store slot `link-<link_id>`, on the Device Key's rung.
- `full_access` grants the peer's devices read/write on this device's folder. It defaults to false, a missing value reads as false, and it covers one direction only.
- A legacy `fingerprint_verified` field is ignored on read.
- **A malformed file is an error, never an empty registry.** A duplicate account or `link_id` is refused.
- `linked_accounts` is read from the registry **at every classification**, so a removal takes effect at once. An unreadable registry is reported on every use, and no peer is classified.
- `add(secret, record)`: the secret is written first, then the record. If the record write fails, the secret is rolled back. The secret must derive the record's `link_id`.
- `remove`: the secret is removed first (an idempotent `SecretStore::remove`), then the record. A rollback failure is reported alongside the original error.
- Reading a secret: an empty slot means empty (a half-finished removal). The wrong length is a malformed error.

Removing a link is unilateral and takes effect locally at once: the peer's EIDs stop matching and its connections are refused. Files already sent stay with the peer.

## Account Broadcast Key (ABK)

32 random bytes (`Rng`, never derived) shared by all devices of one account, used for BLE EIDs.

Record `account-broadcast-key.json`: `account_iss`, `account_sub`, `generation` (≥ 1, required), `created_at` (unix secs). The bytes live in the key store slot `account-broadcast-key`.

- A record bound to a different account is **refused**. Use `clear` explicitly to reset.
- Reads: no record means no ABK. A record whose slot is empty, wrong-length bytes, or `generation` 0 or missing are all **errors**.
- Rotation: fresh bytes, `generation + 1`. Write the secret first, then the record. A failed rotation **restores the previous bytes**.

### Exchange (`BroadcastKeyOffer`, 0x10)

- Sent and read **only on channels this device classified `SAME_ACCOUNT`** (its own verdict, never the peer's `assigned_tier`).
- Both sides offer. A device with no ABK draws one but does not persist it before comparing.
- **Order** (one named function, a total order, so it converges): higher `generation` > earlier `created_at` > lexicographically smaller bytes.
- At most one write per exchange. Outcomes: Kept, Generated, Adopted.
- Refused: a length other than 32, `generation` 0, `created_at` ≤ epoch. Future timestamps are accepted.
- A lying same-account device can win the order. That is accepted; revocation is handled through staleness.

`AccountBroadcastKey` and `LinkSecret` are Layer 0 types in `tradr-core`. `tradr-identity` and `tradr-discovery` never depend on each other; the composition root converts between them.

## Not built

Linking through a Brokr (a 6-character code). A QR scanner inside Tradr (`WI-M6-009`); any camera app plus paste works.

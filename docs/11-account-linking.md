# 11. Account linking



Enabling communication with another Google account. **Both sides must approve explicitly**; a one-sided invitation establishes nothing.

### Tier 0 — linking in person, no Brokr

```
   Alice's device                        Bob's device
        |                                     |
   [start linking]                            |
        |                                     |
   show a QR code ----------------------> [scan the QR]
     {                                        |
       v: 1,                                  |
       sub: "1048...",     <- Alice's sub     |
       identity_pub: ...,  <- Alice's key     |
       agreement_pub: ...,                    |
       attestation: ...,   <- Google-signed   |
       half_secret: ...,   <- 16 random bytes |
       expires: ...        <- 5 minutes       |
     }                                        |
        |                                     |
        |                         verify the Attestation
        |                         display the Fingerprint
        |                                     |
        |<---- reply over BLE or LAN ---------|
        |        {                            |
        |          sub: "9273...",            |
        |          identity_pub: ...,         |
        |          attestation: ...,          |
        |          half_secret: ...           |
        |        }                            |
        |                                     |
  verify the Attestation                      |
  display the Fingerprint                     |
        |                                     |
  [both compare Fingerprints and approve]     |
        |                                     |
  Link Secret = HKDF(half_A || half_B, "tradr-link-v1")
  link_id     = BLAKE3(Link Secret)[0..16]
        |                                     |
  both store the Link locally                 |
```

Where a QR will not work — a screen out of view, or distance — the same JSON travels as a base64 **invite blob** pasted into a chat. That channel cannot be trusted, so **Fingerprint verification becomes mandatory**, with the UI prompting both parties to read it aloud.

Contributing half the randomness each stops either side deciding the secret alone. Photographing the QR does not yield the Link Secret.

### Tier 2 — linking through a Brokr

For linking at a distance.

```
1. Alice creates an invitation. The Brokr issues a six-character code, valid 10 minutes
2. Alice passes the code to Bob by any means
3. Bob enters it. The Brokr records a pending link
4. Alice's device receives an approval request   <- the second consent
5. Alice approves. The Brokr delivers each side the other's DeviceInfo and Attestation
6. Both sides verify the Attestation themselves  <- the Brokr never verifies
7. half_secrets are exchanged through the Brokr and the Link Secret derived
8. Both sides display Fingerprints and press for verification, strongly but not mandatorily
```

The Brokr only mediates and takes no part in verification. A compromised Brokr introducing a fake peer fails on both sides, since its Attestation lacks Google's signature.

A Brokr can obstruct a link and can learn who linked with whom. Nothing more.

### State after linking

```jsonc
{
  "link_id": "01J8YM...",
  "peer_iss": "https://accounts.google.com",  // the peer's issuer
  "peer_sub": "9273...",            // subject, unique only within that issuer
  "peer_email": "bob@example.com",  // display only, never for identity
  "peer_label": "Bob",
  "link_secret": "<in the OS key store>",
  "created_at": "2026-08-22T...",
  "fingerprint_verified": true,
  "policy": {
    "auto_accept_transfers": false,
    "max_transfer_bytes": null,
    "notify_on_transfer": true
  },
  "known_devices": [                // peer devices met and verified
    { "device_id": "...", "label": "Bob's Pixel", "verified_at": "..." }
  ]
}
```

### Removing a link

- Either side removing it ends it. The other's consent is irrelevant
- Removal discards the Link Secret, so the peer's EIDs no longer resolve and they fall off BLE discovery
- The peer is notified when online, but **removal takes effect locally at once regardless**. Their connections are then rejected because the Attestation's `(iss, sub)` matches no known link
- Files already handed over cannot be recalled. The UI says so

### When the peer adds a device

Bob buying a new phone leaves Alice's device unaware of it. Even so:

1. Bob's new device holds an Attestation for Bob's `(iss, sub)`
2. Alice's device matches it against `link.peer_sub` and grants `TRUST_TIER_LINKED`
3. The Link Secret is shared across Bob's devices — handed over when Bob's devices meet — so BLE discovery works too

**Linking is therefore per account, not per device.** Nobody has to re-link every time the other person buys something. The cost is that a compromised account automatically extends trust to the attacker's new devices. That trade reflects how unusable per-device linking becomes when every new device demands an in-person meeting. Fingerprint verification remains per device for anyone who wants it stricter.

## Distributing the Account Broadcast Key

The shared secret letting same-account devices recognize each other over BLE.

```
1. The first device generates 32 random bytes
2. A second device advertises with the bootstrap secret, HKDF(account_id),
   and is discovered by the first, or they meet over mDNS on a shared LAN
3. Attestations are verified, confirming the same (iss, sub)
4. The first device passes the ABK over the Noise channel
5. Both now advertise EIDs derived from the ABK and stop bootstrap advertising
```

**Rotation**: revoking a device regenerates the ABK, handed to remaining devices as they meet. The revoked device never receives the new one, so it disappears from BLE discovery.

**Collision**: two devices may each independently generate an ABK, having each been "the first" somewhere. On meeting, the earlier creation time wins; on a tie, the smaller value. Every device applies the same rule, so it converges.

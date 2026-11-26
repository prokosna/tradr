# 07. Brokr (optional)

**Built today: Deferred Delivery only**: see [13](13-deferred-delivery.md). The Brokr runs inside the tailnet and speaks HTTP with polling.

Everything else in this file is **future design** and is not built: presence, rendezvous / hole punching, relay, FCM wake-up, linking through a Brokr, and the revocation list.

## Principles (these hold for any future work)

- **Tradr works with no Brokr (I1).** CI job `no-brokr` checks this.
- **A Brokr never talks to Google and never verifies Attestations (I2).** Compromising it grants no impersonation.
- **A Brokr never learns `(iss, sub)`, an email, or which folders a device exposes (I3).** It sees Device IDs, `account_tag = BLAKE3(account_id || salt)`, and opaque blobs.
- Only end-to-end ciphertext passes through it. Losing its database is not fatal: devices re-register, and links live on the devices.
- It is optional by registration, not by conditionals: `tradr-discovery` and `tradr-transport` would gain one more implementation each.
- Recommend an overlay network (Tailscale + Static Peer) before a Brokr.

## Future design sketch

| Capability | Mechanism |
|---|---|
| Presence | device ↔ Brokr channel, challenge signed with `tradr-brokr-v1` |
| NAT traversal | exchange reflexive and local candidates, then simultaneous QUIC; symmetric NAT falls back to relay |
| Relay | Noise_IK ciphertext streamed through, spooled only if the receiver is offline (TTL 24 h), with byte, session and day limits |
| Android wake | FCM high-priority data message |
| Revocation | a signed `tradr-revoke-v1` record, accepted only from a device with the same `account_tag` |

Store schema rule: no issuer, no `sub`, no email, no filenames, no Link Secrets, no plaintext.

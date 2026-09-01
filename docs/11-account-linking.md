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
       invite_id: ...,      <- 16 bytes       |
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
        |          invite_id: ...,            |
        |          identity_pub: ...,         |
        |          agreement_pub: ...,        |
        |          attestation: ...,          |
        |          half_secret: ...           |
        |        }                            |
        |                                     |
  verify the Attestation                      |
  display the Fingerprint                     |
        |                                     |
  [both compare Fingerprints and approve]     |
        |                                     |
  Link Secret = BLAKE3::derive_key("tradr-link-v1", half_A || half_B)
  link_id     = BLAKE3(Link Secret)[0..16]
        |                                     |
  both store the Link locally                 |
```

Where a QR will not work — a screen out of view, or distance — the same JSON travels as a base64 **invite blob** pasted into a chat. That channel cannot be trusted, so **Fingerprint verification becomes mandatory**, with the UI prompting both parties to read it aloud.

Contributing half the randomness each stops either side deciding the secret alone. Photographing the QR does not yield the Link Secret.

### Deriving the Link Secret

**This line read `HKDF(half_A || half_B, "tradr-link-v1")` and named no hash, no salt and no output length**, which is three decisions left to whoever implemented it first. DCR-066 settles them as BLAKE3's own key derivation:

```
Link Secret = BLAKE3::derive_key(context = "tradr-link-v1",
                                 key_material = half_A || half_B)   32 bytes
link_id     = BLAKE3(Link Secret)[0..16]
```

**`derive_key` is a KDF with a context string, which is the role HKDF's `info` was playing here**, so nothing about the construction changes — only the primitive that performs it. Every other derived value in this design is BLAKE3: the Device ID, the Content Hash, the Attestation nonce, the Agreement Key Tag, the EIDs. Adding HMAC-SHA256 for one value would put a second hash family in the trust path to save nothing.

**The salt the original line omitted has no source, which is why it could not be named.** HKDF's salt wants a value both sides share and neither controls alone, and at this point in the exchange the only such value is the key material itself. `derive_key`'s context string carries the domain separation a salt would have carried here, and it is a compile-time constant rather than a negotiated one, which is what the specification of that function asks for.

**`half_A` is the invite's creator's 16 bytes and `half_B` the replier's**, and the order is by role rather than by value. Both sides know which they are — Alice showed the QR, Bob scanned it — so no comparison is needed to agree, and sorting the two halves instead would let one side try both orders against a target.

**`link_id` is a plain hash and not a second `derive_key`.** It is an identifier that both sides must compute alike and neither must be able to invert into the secret; a truncated hash of the secret is exactly that. It is 16 bytes rendered as lowercase hex, the same shape as a `DeviceId`.

### How Bob's reply reaches Alice, and what authorises the connection

**The diagram says "reply over BLE or LAN" and that sentence was written before there was a handshake to say it about.** BLE is M7, so M6's reply is a LAN connection — and since `WI-M6-001` every live connection classifies the peer's Attestation, whose step 6 refuses an account that is neither this device's own nor already linked. Bob's account is exactly that account, by definition, at the moment he replies. **The check that makes linking worth having is the one that refuses the connection establishing it**, and DCR-067 settles how.

**Finding Alice needs no address in the QR, because the QR carries her identity key.** Bob computes `BLAKE3(identity_pub)[0..16]`, which is Alice's Device ID, and looks for it in his own Peer List — mDNS publishes it as TXT `id`, and a Static Peer entry carries it once pinned. **Tier 0 linking therefore requires that Bob has already discovered Alice**: a shared LAN, or an entry he added by hand. When that Device ID is in no observation, the interface says the peer cannot be found, which is a different sentence from a dial that failed.

**The QR is the pin.** Bob dials under `PeerExpectation::Device`, so the channel authenticates Alice's Device Key against the key he read off her screen. A device on the same LAN claiming her Device ID cannot complete the handshake, because it does not hold the key that ID is a hash of.

**The invite authorises one connection, for one purpose, and it does so outside the Trust Tier entirely.** While an invite is open — from the moment its QR is shown until it expires five minutes later — this device accepts an inbound Control stream **whose first frame is a `LinkReply` rather than a `Hello`**. Such a stream carries no session: no Trust Tier is computed for it, no `HelloAck` is exchanged, and the only frames that may travel on it are the three linking messages [docs/04](04-protocol.md#the-type-byte) assigns. No transfer and no browse is reachable from it.

**Bob's Attestation is verified in full on that stream, minus the single step that cannot apply.** Steps 1 to 5 all run — the provider's signature, the audience, the nonce binding Bob's two keys, the freshness — and so does the key join, `BLAKE3(LinkReply.identity_pub)[0..16]` against the Device ID the channel authenticated. **Step 6 is the only one left out, and it is the one the link exists to change.** What Alice ends up holding is therefore the same assertion an ordinary connection would have given her: this `(iss, sub)` controls these keys.

**Nothing in the tier machinery moves.** `classify` is untouched, `TrustTier` gains no fourth variant, and no widening flag is added to the policy: `ephemeral_receive` is the precedent for widening step 6 and it is the wrong instrument here, because it grants receiving files and an invite must grant nothing of the sort. Once both sides store the Link, the ordinary handshake returns `TrustTier::Linked` on its own, with no further special case anywhere.

**The window is single-use.** It closes at the first completed exchange — an approval and a decline close it alike — or at expiry, whichever comes first. A second reply arriving after that is refused the way any unexpected first frame is.

**So what a photographed QR buys is one thing: the chance to be shown to Alice as a stranger asking to link.** The approval and the Fingerprint comparison are still in the way, `half_B` was never on the screen, and no Link Secret of the real link is derivable from what the camera saw.

### What the three linking messages carry

**The diagram above is a sketch of a payload and not a definition of one**, and two of its lines could not be implemented as drawn. DCR-068 settles the three messages; `proto/tradr/v1/link.proto` is where they live, and the same rule the Offer and the Hello follow applies here: **a field that decides something refuses the message; a field that only decorates it never does.**

**`LinkReply` (`0x0c`), the replier to the inviter.**

| Field | Wire | Native | On disagreement |
|---|---|---|---|
| `invite_id` | `bytes`, 16 | `InviteId` | **Refuse.** It names which invite this answers, which is the reason that type exists at all, and a reply naming an invite that is not the open one is a reply to something else |
| `identity_pub`, `agreement_pub` | `bytes`, 65 each | `PublicKeyPoint` | **Refuse.** The key join reads the first and step 3's nonce binding reads both. **The diagram carried only `identity_pub` and the verification it describes cannot run on that**: the Attestation's nonce is `BLAKE3(identity_pub \|\| agreement_pub)`, so a reply omitting the agreement key omits half of what step 3 recomputes |
| `attestation.id_token` | `string` | `String`, unverified | **Refuse when absent.** It is the whole of what the exchange is for |
| `attestation.issuer`, `attestation.issued_at` | `string`, `int64` | **absent** | **Dropped**, exactly as in a `Hello`: the authoritative values are the token's own `iss` and `iat` claims, and a second copy is a second answer |
| `half_secret` | `bytes`, 16 | `HalfSecret` | **Refuse.** It is half of the Link Secret |
| `display_name` | `string` | `DisplayName`, dropped when invalid | **Drop it and carry on**, exactly as in a `Hello`. It is shown to a person and decides nothing |
| `sub` | — | — | **Not carried at all.** The diagram showed it and it is a wire copy of a claim already inside the token. Two answers to "which account is this" is the defect the key join exists to prevent, and it is why `Attestation.issuer` is a hint rather than a value |
| `device_id`, `platform`, `capabilities` | `DeviceInfo` fields | **absent** | **Dropped.** The Device ID is recomputed from `identity_pub` and never read off the wire, and nothing in this exchange negotiates a capability or reads a platform |
| a `KeyBinding` | — | — | **Not carried.** It is the redundant proof, and what makes it redundant is exactly the Attestation nonce this stream verifies in full. A `Hello` carries it so the agreement key can rotate on its own later; nothing here rotates a key |

**A `LinkReply` carries no nonce and no signature over one**, which a `Hello` does. It does not need one: the channel is already mutually authenticated before the first frame, so the inviter knows the replier's Device Key from the channel rather than from the message, and the key join is what ties the message to it.

**`LinkApprove` (`0x0d`), the inviter to the replier**: the `invite_id` and the `link_id` the inviter derived. **Both sides derive that identifier independently and a mismatch refuses the exchange** — it is the one cheap check that the two halves joined into the same secret in the same order. `link_id` is safe to send: a Share's Audience already names it, and it is a truncated hash nobody can invert into the Link Secret.

**`LinkDecline` (`0x0e`), the inviter to the replier**: the `invite_id`, and a reason that decorates. Three reasons are reachable and no more — the user declined, the invite expired while the user was reading the Fingerprint, or verification of the reply failed. **An unknown invite is not among them**, because a stream naming one is refused before any message is read. The reason follows `TransferReject.reason`: an unspecified or unrecognised value is dropped and the decline still stands, since what it decides is nothing.

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

**This block was a sketch of a record and not a definition of one**, the same way the reply payload four sections above was, and DCR-069 settles it against what the code can actually write. The registry is `links.json` in the application data directory, beside `static-peers.json`, written whole through a temporary file renamed over the target.

```jsonc
{
  "links": [
    {
      "link_id": "3f1c9a04e7b25d68...",  // 16 bytes of hex, never a ULID
      "peer_iss": "https://accounts.google.com",  // the peer's issuer
      "peer_sub": "9273...",          // subject, unique only within that issuer
      "peer_label": "Bob",            // display only, dropped when absent
      "created_at": 1756684800,       // seconds since the Unix epoch
      "fingerprint_verified": true
    }
  ]
}
```

**`created_at` is an integer of seconds and not an ISO-8601 string.** `UnixTime` is the only time this workspace has, nothing anywhere formats a date, and a second time representation is a second thing that can disagree with the one the Attestation staleness rule already compares against. The same argument settled the certificate validity window in decision 20: a field written in a shape nothing reads is a field that goes wrong unobserved.

**The Link Secret is in the OS key store and is named nowhere in this file.** A `SecretStore` slot is what holds it, and this record is what a reader of `links.json` may see.

#### What this record deliberately does not carry yet

**`peer_email` has no source.** `VerifiedClaims` carries no `email` claim and no linking message carries one, so it is a field nothing could write. It is left out rather than landed empty, following `ProviderProfile::renewal` — DF-16 — for the same reason.

**`policy` and `known_devices` are left out on the same grounds**: nothing reads either one, and a per-Link transfer policy is a decision open decision 9 has not settled. Both return when something consults them.

**What is here is what the milestone's own criterion needs**: the account, so `AttestationPolicy::linked_accounts` stops being `&[]`; the `link_id`, so removal names one Link; and `fingerprint_verified`, which the exchange writes and docs/05's changed-fingerprint refusal will read.

#### What the registry refuses

**A malformed `links.json` is an error and never an empty registry**, the same rule DCR-063 gives `static-peers.json` and for a sharper reason. An emptied Link registry silently withdraws `TrustTier::Linked` from every peer at once, and what the user sees is every one of their links appearing to have been removed from the other side.

**A second Link to an account already linked is refused.** Linking is per account, as "When the peer adds a device" below says, so two records naming one `(iss, sub)` are two answers to a question that has one. **A duplicate `link_id` is refused too**: it is the key removal and Fingerprint verification address a Link by, and a registry holding two would act on whichever it found first.

### Removing a link

- Either side removing it ends it. The other's consent is irrelevant
- Removal discards the Link Secret, so the peer's EIDs no longer resolve and they fall off BLE discovery
- The peer is notified when online, but **removal takes effect locally at once regardless**. Their connections are then rejected because the Attestation's `(iss, sub)` matches no known link
- Files already handed over cannot be recalled. The UI says so

**Discarding the Link Secret needs an operation `SecretStore` does not have.** The trait declares `store` and `load` and nothing that empties a slot, so removal as built today drops the Link record and leaves the secret behind it — orphaned, since nothing knows the slot name once the record naming it is gone, but still on disk or in the keyring. **The account half of removal is complete and is what the milestone is judged on**: the `(iss, sub)` leaves `linked_accounts` at once and the peer's next connection is refused. The secret half is `WI-M6-003b`, and it is the same shape as the two rules this project found had no instrument — the sentence was true as design and nothing made it true in code.

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

# 06. Shares and account linking

## Share — exposing a directory

```jsonc
{
  "share_id": "01J8XK...",          // UUIDv7, unique on this device
  "label": "Scans",
  "root": "/home/user/Documents/scan",   // a content:// tree URI on Android
  "mode": "ro",                     // "ro" | "rw"
  "audience": ["account", "link:01J8YM..."],
  "enabled": true,
  "limits": {
    "max_write_bytes_per_day": 5368709120,
    "max_entries": 200000
  }
}
```

Share definitions **exist only in the device's local SQLite** and never reach a Brokr. Which directories someone exposes is sensitive by itself, and no central component needs to know. Connected peers learn about the ones visible to them through `HelloAck.visible_shares`.

## Enforcing the Share Root boundary

**This is the most security-critical code in Tradr.** It lives entirely in `tradr-vfs`, under a discipline that no other code assembles a file path.

### Resolution

```
input:  share_id, relative path
output: an absolute path safe to touch, or a rejection

1. Look up the Share. Reject if disabled
2. Inspect the relative path
     absolute, leading "/" or "C:\"        -> reject
     contains ".."                         -> reject
     contains NUL or control characters    -> reject
     contains a bidi override or separator -> reject
     apply Unicode NFC normalization       -> re-run the checks above
3. Take the realpath of the root, resolving symlinks   -> real_root
4. Join root and the relative path, take the realpath  -> real_target
5. Confirm real_target is prefixed by real_root at a path component boundary
     A string startsWith is not enough:
     real_root "/home/u/scan" would admit "/home/u/scan-secret"
6. Check the type of real_target
     regular file or directory  -> allow
     symlink                    -> reject, even when it resolves inside,
                                   to avoid TOCTOU
     device, FIFO, socket       -> reject
7. Check against the deny list
```

**Step 2 is split across two layers; steps 1 and 3 through 7 are not.** The checks in step 2 are statements about the shape of a name, so they live in `tradr-core` as the `RelPath` type, beside `ItemId` — nothing there touches a filesystem. The normalization inside step 2 cannot live there: the standard library has no Unicode normalization and `tradr-core` may take no dependency ([invariant I4](../CLAUDE.md#8-invariants-that-must-not-break)). So `tradr-vfs` normalizes and then **rebuilds a `RelPath` from the normalized string**, which is how "re-run the checks above" happens without a second copy of the rules existing to drift out of step with the first.

### TOCTOU

Between validating a path in steps 4 and 5 and opening it in step 6, an attacker who can insert a symlink defeats the check. So **validation and opening are never separated**.

- Linux and macOS: `openat2` with `RESOLVE_BENEATH` on Linux 5.6+, where the kernel guarantees no escape. Otherwise descend component by component with `openat` and `O_NOFOLLOW`
- Windows: open each component with `FILE_FLAG_OPEN_REPARSE_POINT` and reject on encountering a reparse point
- Android SAF: the OS itself guarantees the boundary, since nothing outside the tree URI is reachable. Only the relative-path checks apply

### The default deny list

Even beneath a Share Root, these are neither listed nor accessible.

```
.ssh/            .gnupg/           .aws/            .kube/
.config/gcloud/  .docker/config.json
.netrc           .git-credentials  .npmrc           .pypirc
*.pem  *.key  *.p12  *.pfx  *.keystore  *.jks
.env  .env.*
id_rsa*  id_ed25519*  id_ecdsa*
```

#### How a pattern matches

**A pattern matches a path component, never a path.** `.ssh` denies any component named `.ssh` at any depth beneath the Share Root, which denies both the directory and everything under it in one rule rather than in two.

- **A pattern containing `/` matches a consecutive run of components.** `.config/gcloud` denies `.config/gcloud/` wherever it appears and leaves the rest of `.config/` alone, which is the whole reason it is written with a separator.
- **`*` matches inside one component and never crosses a separator.** `*.pem` denies `server.pem` and not `pem`; `id_rsa*` denies `id_rsa`, `id_rsa.pub` and `id_rsa_old`; `.env.*` denies `.env.production` and not `my.env.txt`.
- **Matching is ASCII-case-insensitive.** A deny list that `ID_RSA` walks past is not one, and on a case-insensitive filesystem the two name the same file anyway. The cost of the other direction is that someone with a file called `KEY.PEM` relaxes the list, which is the outcome this section already tells them they may choose.
- **Denied means neither listed nor reachable.** A listing omits the entry rather than showing one that cannot be opened, and every other operation refuses it. An entry that appears and then fails is a worse answer than one that never appeared: it confirms the file exists.

**`.git`, `node_modules`, `target` and `__pycache__` are not on this list and must not be added to it.** They are collapsed in listings, which is a default about presentation and belongs wherever a listing is rendered. Denying them instead makes a repository unshareable, and the paragraph below already says they remain accessible.

Users may relax this, but the default is conservative. **It is insurance against accidentally sharing an entire home directory, not a reason to consider the result safe.** The Share Root picker states plainly that sharing a home directory directly is a bad idea.

`.gitignore` is not honoured, since it would hide things people meant to share. But `node_modules`, `.git`, `target`, and `__pycache__` are collapsed in listings by default, while remaining accessible.

### Android SAF

Android has no free-form file paths. A Share Root is a tree URI the user picked through `ACTION_OPEN_DOCUMENT_TREE`.

```
Share.root = "content://com.android.externalstorage.documents/tree/primary%3ADocuments%2Fscan"
```

- `takePersistableUriPermission` persists the grant across restarts
- Walking a relative path means traversing `DocumentFile` objects, incurring an IPC per level, which makes it **markedly slower** than POSIX. Directory metadata is cached in SQLite and invalidated by a `ContentObserver`
- The `Vfs` trait has two implementations, `PosixVfs` and `SafVfs`, identical from above

## Audience — who sees a Share

| Value | Meaning |
|---|---|
| `"account"` | Every device of the same Google account, meaning `TRUST_TIER_SAME_ACCOUNT` |
| `"link:<link_id>"` | Every device of that linked account, meaning `TRUST_TIER_LINKED` |

`NEARBY_EPHEMERAL` peers see no Shares at all. Opening a directory to someone who merely happens to be nearby is a poor trade.

The receiving side decides:

```
allow(peer, share, operation) =
     share.enabled
  && audience_matches(peer.trust_tier, peer.link_id, share.audience)
  && (operation.is_read || share.mode == "rw")
  && within_limits(peer, share, operation)
```

## Account linking

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

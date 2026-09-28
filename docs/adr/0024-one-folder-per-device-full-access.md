# ADR-0024: A device exposes one folder, read-write, to its own account and to Links granted full access

- **Status**: Accepted
- **Date**: 2026-09-28
- **Supersedes**: [docs/06](../06-shares-and-browsing.md)'s model of many Share definitions, each with its own root, mode and Audience; the DF-109 proposal of the same day

## Context

docs/06 designed Shares as definitions a person creates -- a directory, a label, `ro` or `rw`, an Audience of the account and of chosen Links -- and none of it was ever built (DF-109). Reading the code for a proposal found the Browse plane serving the receive directory to every peer that completes a handshake, own devices and linked accounts alike, with `share_id` and the Trust Tier both ignored (DF-120).

The person using Tradr decided on 2026-09-28 that the product should be finished quickly and that the many-definitions model is more than it needs. Their rule: **devices of the same Google account may read and write each other without conditions; a linked account gets the same access only when this side grants it, per Link, and the grant is one-directional until the other side grants it too.**

## Decision

**Each device exposes exactly one folder: its receive directory**, the root the listener already serves -- the downloads directory on the desktop and on Android, and the directory `tradr receive` is given. It is the one Share of the device, `rw`, under the constant `share_id` the front end already uses.

**Access is decided per connection and is all or nothing:**

| Peer | Browse plane |
|---|---|
| `SameAccount` | read and write |
| `Linked`, and this device's Link record for that account has `full_access` | read and write |
| `Linked` without it | refused |
| anything else | cannot complete a handshake today |

- **`full_access` is a field of the Link record**, `false` when a Link is made, changed only by the person on this device through the Linking screen. It governs what the *peer* may do *here*; it says nothing about what this device may do there, which is the peer's own record. Removing the Link removes the grant with it
- **The decision is made where the Attestation is classified**, and remembered by the listener for the authenticated `DeviceId` of that connection, so the Browse stream is refused or served without the handshake's signature changing and without touching Attestation verification
- **Transfers are unchanged**: sending to a linked peer never needed a grant and still does not
- **Android serves the same way as the desktop**, since its receive directory is an ordinary path under `NativeVfs`; SAF Share Roots (DF-110) are no longer needed for this and are deferred with the rest of docs/06's model

## Consequences

- DF-120 closes: a Link no longer implies a read of anyone's downloads
- Browsing gains writes -- upload, new folder, delete, rename -- through the messages docs/04 already assigns (`WriteFile`, `Mkdir`, `Delete`, `Rename`, `Ack`), with every path still resolved by `tradr-vfs`
- Nothing can be exposed except the receive directory; exposing another directory is a later decision
- `HelloAck.visible_shares`, `Watch`, `limits` and a verified `content_hash` on downloads and uploads stay unbuilt

## Alternatives rejected

- **docs/06's per-directory Share definitions with Audiences**: more than the person using it needs, and the reason M8 has not reached daily use
- **Promoting a granted Link to `TrustTier::SameAccount`**: the tier is a wire value decided by the Attestation, and other behaviour reads it; a grant is a local permission, not an identity

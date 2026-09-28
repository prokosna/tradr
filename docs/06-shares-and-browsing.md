# 06. Shares and browsing

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

Share definitions **are kept only on the device** and never reach a Brokr. **No store for them exists yet and no Share can be defined** (DF-109, recorded by DCR-158): `get_visible_shares` answers one constant entry for every peer, and `HelloAck.visible_shares` is written empty. Which directories someone exposes is sensitive by itself, and no central component needs to know. Connected peers learn about the ones visible to them through `HelloAck.visible_shares`.

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
- Walking a relative path means traversing `DocumentFile` objects, incurring an IPC per level, which makes it **markedly slower** than POSIX. Caching directory metadata, invalidated by a `ContentObserver`, is the design; **nothing caches it and no production `SafBridge` exists yet** (DF-110, recorded by DCR-158)
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


## The Browse plane

The Browse plane operates over a dedicated QUIC stream (`Browse`). It enables a device to list directories, fetch file metadata, read files, and receive live filesystem events from a peer's Share.

See `docs/04-protocol.md` for the exact wire messages.

### Listing and Pagination
`ListDir` returns a `DirListing` with a `next_cursor` when results exceed the page size (default 500). The requester follows up with the same `share_id` and `path`, providing the `cursor` to fetch the next page.

### Live Updates
A `Watch` request establishes a continuous stream of `FsEvent` messages. The provider uses the OS's native file monitoring (inotify, FSEvents, ReadDirectoryChangesW, or Android's ContentObserver) to detect changes within the Share Root. Events are debounced (250 ms) before transmission to avoid flooding the stream during bulk operations.

### Downloading Files
A file read begins by opening a new, dedicated bidirectional QUIC stream. The requester sends a `ReadFile` message on this stream. The provider validates the request, responds with `ReadFileBegin` on the same stream, and then immediately transmits the raw file bytes on that same stream until EOF. This avoids both head-of-line blocking on the main Browse stream and the need for separate correlation IDs.

## Defining a Share -- a proposal awaiting decisions (DF-109)

> **Not yet ruled. No Work Item may be cut from this section** until the user has answered decision 16 in [STATE.md](../STATE.md) and the answers have been written back here as a DCR. It was drafted on 2026-09-28 from a reading of the code, and it records what that reading found.

### What the code does today, read on 2026-09-28

- **The Browse plane ignores the Share and the peer.** `handle_browse_stream` in `crates/tradr-core/src/browse.rs` takes the listener's one `RootId` and answers `ListDir`, `Stat` and `ReadFile` against it whatever `share_id` says, without being told the peer's Trust Tier. That root is the receive directory -- the downloads directory on the desktop and on Android, and the directory `tradr receive` was given. **So every device that completes a handshake can list and download everything in it**, and since only `SameAccount` and `Linked` peers complete one (`ephemeral_receive` is `false` everywhere), that means the devices of every linked account as well as one's own. This is DF-120
- `get_visible_shares` answers one constant entry without contacting the peer, and `HelloAck.visible_shares` is written empty, as DF-109 records
- `WriteFile`, `Mkdir`, `Delete`, `Rename` and `Watch` are decoded and refused; nothing implements `rw`, live updates or `limits`
- `ReadFileBegin.content_hash` is 32 zero bytes, so a download over the Browse plane is not verified against anything
- **M3's record says a device "browsed a peer's configured Share"; no Share could be configured**, so what was browsed was the receive directory under the constant `share_id`. M3's own completion criterion -- the adversarial path suite -- was met and still is

### The proposal

1. **A store of Share definitions on the device**, `shares.json` in the application data directory beside `static-peers.json` and the Link registry, written atomically the way those two are. A record is docs/06's JSON above: `share_id` (UUIDv7), `label`, `root`, `mode`, `audience`, `enabled`. `limits` is left out until something enforces it, as DF-28 argues for fields nothing reads. It lives in `tradr-app` so both front ends share it
2. **The listener resolves `share_id` before any `Vfs` call.** Each enabled Share is registered as its own `RootId`, `read_only` when its mode is `ro`, and `handle_browse_stream` is handed a resolver instead of one root. A request is served only when `allow(peer, share, operation)` above holds; otherwise it is refused with the same answer as a Share that does not exist, so a peer cannot probe for Shares it may not see. **The receive directory stops being browsable** unless someone defines a Share over it
3. **`allow` needs to know which Link a linked peer came through**, and today the handshake yields a bare `TrustTier`. The session has to carry the peer's `AccountId` so that `link:<link_id>` can be matched against the Link registry. This is the one change that reaches the handshake's signature
4. **`HelloAck.visible_shares` is filled per peer** from the same `allow`, read-only operation, and `get_visible_shares` performs the handshake and answers what the peer sent, instead of a constant
5. **Defining a Share**: in the GUI, a Shares panel -- choose a directory (the desktop's folder dialog, or the SAF tree picker `pick_share_root` already has on Android), a label, `ro`/`rw`, an Audience of "my devices" and any of the current Links, an on/off switch, and remove. In the CLI, `tradr share add <dir> --label <l> [--link <id>]...`, `tradr share list` and `tradr share remove <id>`, served while `tradr receive` runs
6. **Android as the serving side needs DF-110's `SafBridge`**, a Kotlin `DocumentFile` walk behind `SafVfs`; until then an Android device browses other devices and serves nothing
7. **Out of this proposal unless the user says otherwise**: `rw` (the write messages, and decision 11's default write limit), `Watch`, `limits`, and a verified `content_hash` on `ReadFileBegin`, each its own later Work Item

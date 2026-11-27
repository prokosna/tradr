# 06. Folder access and browsing

## Model ([ADR-0024](adr/0024-one-folder-per-device-full-access.md))

**A device exposes exactly one folder, its receive directory, read and write.** The configurable Shares design (audiences, ro/rw, SAF tree URIs, per-Share limits) was superseded and is not built.

- **Access is decided at Attestation classification** and remembered per authenticated `DeviceId`:
  - a `SameAccount` peer is always allowed;
  - a `Linked` peer is allowed only if this device's Link record has `full_access`, a per-link toggle in Linking that grants one direction only;
  - anyone else is refused.
- The listener refuses a Browse stream without that grant with `Refused{NO_ACCESS}`.
- Operations and wire messages are listed in [04](04-protocol.md#browse-plane). Uploads land under `.tradr-partial` and are renamed into place, and each is reported as an arrival (Received list). Downloads from a peer are staged the same way on this side. `content_hash` is not checked on upload or download yet.
- The UI words each `Refused` reason for a person (for example "that name is already taken").

## Boundary enforcement (Critical Module, `tradr-vfs`; invariant I5)

No code outside `tradr-vfs` assembles a file path. `Vfs` exposes operations on `(root, RelPath)` and never returns paths ([ADR-0014](adr/0014-vfs-exposes-operations-never-paths.md)).

Resolution:
1. `RelPath` (in `tradr-core`, pure) rejects absolute paths, `..`, NUL or control characters, and bidi or separator characters.
2. `tradr-vfs` applies NFC normalization, then **rebuilds the `RelPath`**, so the same rules run again with no second copy.
3. `realpath(root)`, then join and resolve. The result must sit under the root **at a component boundary** (`/home/u/scan` must not admit `/home/u/scan-secret`).
4. The type must be a regular file or a directory. Symlinks (even pointing inside), devices, FIFOs and sockets are rejected.
5. Deny list.

**Validation and open are never separated (TOCTOU).** Linux uses `openat2(RESOLVE_BENEATH)`, falling back to a per-component `openat(O_NOFOLLOW)`. Windows opens each component with `FILE_FLAG_OPEN_REPARSE_POINT` and rejects reparse points. Android adopts a descriptor in one `unsafe` call ([ADR-0023](adr/0023-one-unsafe-call-adopts-an-android-descriptor.md)).

### Deny list

```
.ssh/ .gnupg/ .aws/ .kube/ .config/gcloud/ .docker/config.json
.netrc .git-credentials .npmrc .pypirc
*.pem *.key *.p12 *.pfx *.keystore *.jks  .env .env.*  id_rsa* id_ed25519* id_ecdsa*
.tradr-partial (from peers)
```

- A pattern matches **path components**, not whole paths. A pattern containing `/` matches a consecutive run of components, and `*` never crosses a separator. Matching is ASCII case-insensitive.
- A denied entry is omitted from listings and refused by every operation.
- `.git`, `node_modules` and similar are **not** denied (they may be collapsed in the UI).
- Below the partial root, listing uses the same write-deny rule the other operations use. The partial root itself stays hidden from peers.

### Writes

- Placement uses `rename_no_replace` under a process-wide lock (see [04](04-protocol.md#session)).
- `Mkdir{parents}` creates the directory. `Delete` removes a file or an empty directory, or the whole tree with `recursive`. `Rename` never replaces an existing name.

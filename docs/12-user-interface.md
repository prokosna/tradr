# 12. User interface

Modelled on Quick Share. Goal: **a person sends and receives on all four devices without knowing what a Static Peer or a Trust Tier is.**

Main path: **Send** (files → device), **Receive** (see what arrived), **Open another device's folder**. Everything else is under Settings.

## Flows

**First run**: a single card, "Sign in with Google to reach your devices". The device list sits greyed underneath. After sign-in the header says "Signed in" (the app keeps no email).

**Send, files first**:
1. Select files, or drop them anywhere. They appear as chips with name, size and a total, plus Clear.
2. The device list is headed "Send to"; tap a device.
3. The tile shows a progress ring. Hashing shows as "Preparing… N%" (progress `status: preparing`, one event per MiB).
4. Sends queue one at a time.
5. Success: "Sent", then the tray clears. Failure: "Couldn't send", the files stay, and an mDNS recheck runs, so a vanished device goes offline within about 10 s and the next tap offers Send later.

The **Refresh** button in the device-list header rechecks every device (shows "Checking…" for 10 s).

**Send, device first**: drop files on a tile (desktop). On Android, sharing to Tradr opens the app with the files already in the tray.

**Receive**:
- No action needed. Same-account and linked devices are auto-accepted.
- **Received** card: one row per file, showing name, source device ("from X" or "downloaded from X") and time (date if older than today).
- The list is kept until cleared (inline confirm "Clear this list? The files stay where they are.").
- It shows the newest 50, then Show all.
- Row actions, depending on platform:
  - desktop: Open and Show in folder;
  - Android: Open and Share.
- A missing file shows "This file is no longer where it was saved."
- The card names the receive folder.
- Not yet listed: files that another device writes into this device's folder.

**Open folder**: Open folder on the tile, or tap the tile when no files are waiting.
- Breadcrumb starting at the device name.
- Upload and New folder at the top; Download, Rename and Delete per row (delete has an inline confirm).
- `Refused` reasons are shown in plain words.

**Settings** (in order):
1. Account.
2. Linked accounts (invite, paste a code, list with the "Let this account's devices open and change my folder" toggle).
3. Add a device by address.
4. Deliver when a device is offline. Connect by pasting a Brokr link; typing the address and token is a fallback. Once connected: status, Check now, Disconnect, Show link with Copy.
5. Advanced (collapsed): Device ID, key backing, Attestation tools.

## Words

| Internal | Shown |
|---|---|
| Peer | Device |
| Static Peer | "added by address" |
| mDNS / BLE source | "on this network" / "nearby" |
| Share | "folder" |
| Trust Tier | "your device" / "`<name>`'s device" |
| Attestation, Device ID, backing | Settings → Advanced only |

Errors are one plain sentence, with the raw error in a smaller details line underneath.

## Layout

- **Wide (≥ 720 px)**: Devices column (about 320 px) | send card above Received. The folder view and Settings replace the right column.
- **Narrow**: a single column. Sub-views go full screen with Back.
- Plain CSS with design tokens in one stylesheet, **no UI library**, no inline styles. System font. Follows the system light/dark setting. Touch targets ≥ 44 px.
- On Android: `viewport-fit=cover` plus `env(safe-area-inset-*)`.

## Plugin commands the UI relies on

- Event `files-received`. `received_history` and `clear_received_history` back `received.json` in `tradr-app`, written atomically. Each row: id, relative path, sender DeviceId, name at the time, time, sent or downloaded. Failing to record a row never fails the transfer.
- `received_actions`, plus `open_received`, `reveal_received` and `share_received`, each taking a row id (never a path; [ADR-0026](adr/0026-one-operation-hands-the-os-a-received-files-location.md)). The desktop uses `tauri-plugin-opener`'s Rust API, with no webview permission.
- `receive_folder`, `refresh_peers`, `connect_brokr_link`, `brokr_link`.

## Checking UI work

- **Preview harness**: run `pnpm --filter @tradr/tradr dev` and open `http://localhost:1420/preview.html?scenario=signed-in|signed-out|empty|share` (add `#/settings` or `#/folder/<key>` for those views). It uses the `@tauri-apps/api/mocks` IPC mock and is dev only. Screenshot it with headless Firefox (`--no-remote --profile <dir>`, served over http; the Firefox snap can only write under `~/snap/firefox/common/`) at wide and narrow widths in both themes.
- **Behaviour tests**: Vitest + jsdom + Testing Library in `apps/tradr`, driving real components through the same IPC mock. `pnpm test` runs them (also from `ci/frontend-gate.sh`).
- A device run is still the final judgement.

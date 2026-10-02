# 12. User interface

> Decided 2026-09-30 by DCR-169, at the request of the person using Tradr: "make it a design that works as an ordinary app; Quick Share is a good example." It supersedes the two-pane sketch in [docs/08](08-platform-integration.md#residency-and-ui) and is what M8's completion criterion is judged against: **a person sends and receives on all four devices without needing to know what a Static Peer or a Trust Tier is.**

## What was wrong with the screen before this

The window was one long page of every capability in the order it was built: this device's Device ID and key storage level, sign-in with the Trust Tier in brackets, the peer list, "Static Peers", account linking, a drop zone, the browse panel with a Share selector showing a UUID, and two panels for pasting Attestation bundles. **Every one of them is correct and most of them are vocabulary from `docs/`, not from the person using it.** There was no place that said what arrived, and sending took four separate controls in three sections.

## The two things a person comes to do

Quick Share is the model because it is built around the two acts people actually perform, and puts everything else one step away.

1. **Send**: *these files* to *that device*. Either order: pick files then a device, or drop files on a device.
2. **Receive**: be reachable, and see what came in.

A third act is particular to Tradr and is kept on the main path because the person asked for it: **open another device's folder** (browse, download, upload, rename, delete -- [ADR-0024](adr/0024-one-folder-per-device-full-access.md)).

Everything else -- signing in, linking another account, adding a device by address, diagnostics -- is set up once and lives in **Settings**.

## The flows

### First run

1. The home screen shows one card: **"Sign in with Google to reach your devices"** and a single button. Nothing else competes with it; the device list shows underneath, greyed, with a line saying devices appear once signed in.
2. After sign-in the card disappears. The account's email or name is not known to the app (docs/05 keeps only `iss` and `sub`), so the header shows **"Signed in"** and Settings shows the account as "Google account".

### Sending, files first

1. **Select files** (a button in the send card) or **drop files anywhere on the window**. The send card turns into a tray: the files as chips with name and size, a total, and **Clear**.
2. The device list is headed **"Send to"** while files are waiting. Tapping a device sends to it.
3. The device's tile shows a progress ring and "Sending… 42%"; the send card shows the same with the file being sent. Other devices stay tappable; a second send queues behind the first rather than being refused.
4. On success the tile shows **"Sent"** with a check for a few seconds and the tray clears. On failure the tile shows **"Couldn't send"** and the error in one plain sentence, and the files stay in the tray so a retry is one tap.

### Sending, device first

- **Drop files on a device tile** to send to it directly (desktop).
- On Android, **sharing to Tradr** from any app opens it with the files already in the tray, headed "Send to", which is the files-first flow from step 2. A Sharing Shortcut that names a device keeps doing what it does today.

### Receiving

- Receiving needs no action: while the app is open (and on Android while it is resident, ADR-0022) own-account devices are accepted automatically (DCR-129). The Received card says so when it is empty: "Files sent to this device appear here."
- Each arrival adds a row to **Received** on the home screen: the file name, which device it came from, and when. The list covers what arrived since the app started; keeping history across restarts is open decision 11.
- On Android the existing notification stays the signal while the app is in the background.

### Opening another device's folder

- Every device tile has **Open folder**. With no files waiting, tapping the tile itself does the same.
- The folder view replaces the home view (with **Back**), headed by the device's name and a breadcrumb starting at the device's name rather than at `/`. Rows show an icon for file or folder, the name, size and date. Tapping a folder goes into it.
- **Upload** and **New folder** sit at the top. Each row has **Download**, **Rename** and **Delete** (delete asks once more inline). The refusal reasons DCR-168 added are shown as a message above the list.
- The Share selector is gone: a device exposes exactly one folder (ADR-0024), so there is nothing to choose.

### Settings

One page, in this order:

1. **Account**: signed in or not, and sign in / sign in again.
2. **Linked accounts**: what the Linking screen is today -- invite by QR or code, join by pasting a code, the list of links with "let this account's devices read and write my folder".
3. **Add a device by address**: what "Static Peers" was, for a device not on the same network (a Tailscale address, for example). The words "Static Peer" do not appear.
4. **Advanced**: the Device ID, where the key is held, and the two Attestation tools. Collapsed by default.

## Words

| Internal term | What the screen says |
|---|---|
| Peer | Device |
| Static Peer | "added by address" |
| mDNS source | "on this network" |
| BLE source | "nearby" |
| Share / Share Root | "folder" |
| Trust Tier `same-account` / `linked` | "your device" / "`<name>`'s device" where a name is known, otherwise nothing |
| Attestation, Device ID, key backing | only under Settings → Advanced |
| Transfer | "sending" / "sent" / "received" |

**An error shown to a person is one sentence saying what did not happen and, when known, why** -- "Couldn't send to Pixel 8: it isn't reachable right now." The raw error string is kept in a details line underneath, smaller, because it is what a bug report needs.

## Layout and look

### Two widths, one component tree

- **Wide (desktop, at least 720 px)**: a header bar, then two columns -- **Devices** on the left (about 320 px), and on the right the **send card** above **Received**. The folder view and Settings take the right column's place with a Back button; the device list stays visible.
- **Narrow (phone)**: one column -- header, send card, Devices, Received. The folder view and Settings take the whole screen with Back.
- The header carries the app name, whether this device is signed in, and a Settings button.

### Visual style

- **Plain CSS in one stylesheet with design tokens** as custom properties: colours, a 4 px spacing scale, radii, one font stack (the system UI font). **No UI library**: nothing on this screen needs one, and every dependency is a supply-chain line in a product whose job is moving files between a person's own devices.
- **Light and dark follow the system** (`prefers-color-scheme`).
- Cards with rounded corners and a soft border; one accent colour for primary actions and progress; tiles with a round initial avatar derived from the device name.
- Touch targets at least 44 px high on narrow screens.
- **The Android WebView respects the system bars**: `viewport-fit=cover` and `env(safe-area-inset-*)` padding, closing DF-8.
- No inline `style` attributes in components; styles are classes in the stylesheet.

## What the front end needs from the plugin that it does not have

- **An arrival event.** The listener's `on_arrival` hook exists (DCR-129) and the plugin passes `None`, so a desktop never learns a file arrived. The plugin emits **`files-received`** with the sender's Device ID and the placed paths; the front end names the sender from the device list and falls back to "another device".
- **Nothing else.** Every other flow above uses a command that exists today.

## How it is checked

- **A preview harness**: a page served only by the Vite dev server that installs `@tauri-apps/api/mocks`' IPC mock with fixture data (signed in, three devices, a folder listing, a transfer in progress) and renders the same `App`. It is never part of the built application.
- **The Supervisor screenshots it** with headless Firefox at a wide and a narrow width in both colour schemes, and reviews those images as part of every UI Work Item. It is not a test, and it does not claim to be one: it is the instrument that makes the layout reviewable at all before a device run.
- The device run is still the judgement that counts.

### Behaviour is tested, decided 2026-10-02 by DCR-170 closing DF-40

**The screenshots check how the screen looks and nothing checks what it does.** DF-40 recorded that the two lines DCR-078 rests on -- the link reply carries the code that was previewed, and editing the code discards the preview -- survive deletion with every gate green, and the rebuild above added more logic of the same kind: the send queue, a tap meaning "send" or "open" depending on waiting files, the Received list, and the subscription helper whose absence listed every arrival twice.

- **Vitest, in `apps/tradr`, with jsdom and React Testing Library**, as development dependencies only, pinned exactly like every other dependency here. Vitest is chosen because the app already builds with Vite, so the test run shares its configuration rather than adding a second toolchain.
- **Tests drive the real components through the same IPC mock the preview uses** (`@tauri-apps/api/mocks`), asserting on what a person sees and on which commands were invoked with which arguments. A test never reaches into component state.
- **`pnpm test` at the repository root runs them, and `ci/frontend-gate.sh` runs `pnpm test` as its fourth step**, so they gate every commit through the pre-commit hook and every pull request through the `checks` job, as lint, typecheck and format already do.
- **What must be covered first**: DCR-078's two rules; sends running one at a time and a second tap waiting; a tap sending when files wait and opening the folder when none do; `files-received` adding one row per file, named after the sender, at most 50; the subscription helper removing a subscription whose cleanup ran before `listen` resolved; and a refused folder operation showing its reason.

## Out of scope here

- Accepting or declining a transfer from a linked account before it lands (open decision 9).
- A received-files history across restarts (open decision 11).
- "Open" / "Show in folder" for a received file: it needs an opener plugin and a decision about Android's Downloads provider, so it is DF-122.
- Nearby-ephemeral ("everyone") mode, which docs/05 keeps off and unbuilt.

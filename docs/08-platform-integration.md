# 08. Platform integration

UI layout and flows are in [12](12-user-interface.md).

## Desktop

- Resident in the tray. Closing the window leaves it listening.
- Drag and drop (Tauri `onDragDropEvent`): drop on a device tile to send to it. A dropped directory is walked recursively.
- Not built: dragging *out* of a peer folder into the file manager (needs native `NSFilePromiseProvider`, `IDataObject` or XDND; a Download button covers it), and shell integration (Explorer, Finder or Nautilus menus).

## Android

### Sending (share sheet and in-app picker)

- `ShareTargetActivity` (dialog theme) handles `SEND` and `SEND_MULTIPLE` for `*/*`.
- **A `content://` URI is never handed to Rust.** While the Activity is alive, Kotlin opens a `ParcelFileDescriptor`, detaches it and passes the fd. Rust adopts it once as a single-file root in `tradr-vfs` ([ADR-0023](adr/0023-one-unsafe-call-adopts-an-android-descriptor.md)), identified by an opaque registry id.
- A descriptor that cannot be read at an offset (`statSize < 0`, i.e. a pipe) is copied to `cache/shared_incoming/<unique>/<display name>`. Copies are swept on the next plugin start.
- The filename comes from `COLUMN_DISPLAY_NAME`, not from the URI.
- In-app **Select Files** uses the plugin command `pick_files_to_send` (`ACTION_OPEN_DOCUMENT`, multiple) and the same processing path, never `plugin-dialog` (which returns URIs).
- Sharing Shortcuts (direct share targets) are designed but not built.

### Receiving

- Files land in the **shared `Download` folder** (`<storage root>/Download`), written by path with no storage permission. This is also the folder the device serves.
- A start-up probe (create a `.tradr-partial` file, write, rename, delete) checks that the folder works. If the probe fails (Android ≤ 10, odd vendors), the app-specific `Android/data/.../Download` is used instead. The Received card always names the folder.
- Limitations: other apps' files in Download are invisible to Tradr, so a name already used by another app makes the placement fail instead of getting a ` (1)` suffix (unmeasured). `MANAGE_EXTERNAL_STORAGE` is never requested.
- **Open / Share** on a Received row: Rust resolves the location ([ADR-0026](adr/0026-one-operation-hands-the-os-a-received-files-location.md)). Kotlin builds a `content://` URI through `com.tradr.plugin.TradrFileProvider` (a subclass, so it does not clash with Tauri's FileProvider; authority `<appId>.tradr.files`; paths limited to shared Download and the app's external files dir), then fires `ACTION_VIEW` or `ACTION_SEND` with a read grant.

### Foreground service ([ADR-0022](adr/0022-android-stays-resident-to-receive.md))

- `ReceiveService`, `foregroundServiceType="connectedDevice"`. It is started when the plugin loads with the Activity in the foreground, never at boot.
- It shows a permanent "Ready to receive" notification with a Stop action, which ends the process.
- It holds a `MulticastLock`. It runs no listener of its own: it only keeps the process, and the Rust listener inside it, alive.
- Battery cost: **unmeasured**.

### Permissions

Requested individually, the first time a feature needs them. Refusing one disables only that feature.

| Permission | API | For |
|---|---|---|
| `BLUETOOTH_SCAN` (`neverForLocation`), `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` | 31+ | BLE |
| `BLUETOOTH`, `BLUETOOTH_ADMIN`, `ACCESS_FINE_LOCATION` | ≤ 30 | BLE on old APIs |
| `POST_NOTIFICATIONS` | 33+ | notifications |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE`, `CHANGE_WIFI_MULTICAST_STATE` | — | resident receive |
| `INTERNET`, `ACCESS_NETWORK_STATE` | — | network |

### Sign-in

Credential Manager with the Google ID option ([05](05-security.md#oauth-client-configuration)). Requires Play Services. There are no WebViews and no custom-scheme redirects.

## iOS (future)

The design leaves room for iOS:
- `_tradr._udp` is fixed, so it can be listed in `NSBonjourServices`.
- BLE is never the only discovery channel.
- `wifi-direct` is Android-only.
- `Vfs` can host a security-scoped bookmark implementation.
- P-256 works in the Secure Enclave.

If Tauri's iOS support is not good enough, a native Swift shell can link the I/O-free core.

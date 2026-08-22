# 08. Platform integration

## Desktop, common

### Residency and UI

- Resident in the tray or menu bar. Closing the window leaves it listening
- Two panes:

```
+----------------------------------------------------------------+
|  Tradr                                        [settings] [-][x]|
+----------------------+-----------------------------------------+
| My devices           |                                         |
|  * Pixel 8      LAN  |     +---------------------------+       |
|  * ThinkPad     tail |     |                           |       |
|  o Mac mini   (away) |     |     Drop here to send     |       |
|                      |     |                           |       |
| Linked               |     |      -> Pixel 8           |       |
|  * Bob's Pixel   BLE |     |                           |       |
|                      |     +---------------------------+       |
| Nearby               |                                         |
|  (ephemeral off)     |  -- or open a peer's share --           |
|                      |  [dir] Scans (Pixel 8)      read-only   |
| [+ add a device]     |  [dir] Downloads (ThinkPad) read-write  |
+----------------------+-----------------------------------------+
```

- Each device carries a badge for its current path — `LAN`, `tail`, `BLE`, `relay`. Making "why is this slow" answerable matters
- During a transfer: progress, speed, time remaining, and the active transport, updated in place when the path switches

### Drag and drop, receiving

Tauri 2's `onDragDropEvent` provides file paths. Behaviour depends on the drop target.

| Drop target | Behaviour |
|---|---|
| A device tile | Send to that device |
| The large drop zone | Send to the selected device |
| A folder in the share browser | Write into that folder, `rw` only. A read-only target shows a reject cursor |
| The tray icon, outside the window | Open the window and ask for a destination |

Dropping a directory walks it recursively and enumerates every file into the `TransferOffer`. During the walk the UI shows "preparing N files, M GB" and offers cancellation.

### Dragging out — pulling a peer's file into a file manager

**A hard case, not built in v1** — see [09](09-roadmap-and-risks.md).

The difficulty is that when the drag begins, no local file exists, and OS drag and drop wants a real path. Each platform has a deferred-delivery mechanism.

| OS | Mechanism | Difficulty |
|---|---|---|
| macOS | `NSFilePromiseProvider` | Moderate. Works as intended |
| Windows | `IDataObject` with `CFSTR_FILEDESCRIPTOR` and `CFSTR_FILECONTENTS` | High. Requires a COM implementation |
| Linux, X11 and Wayland | XDND `text/uri-list` plus a temporary file | Moderate. Deferral is not really possible, so the file must be downloaded first |

Tauri offers no drag-source API, so all three go straight to native code. **A download button covers it for now** and is functionally sufficient.

### Shell integration, phase 3

| OS | Integration |
|---|---|
| Windows | Explorer context menu via `IExplorerCommand`. Appearing in the Windows 11 menu needs a sparse package |
| macOS | A Share Extension plus a Finder Quick Action |
| Linux | `MimeType=` in the `.desktop` file for "Open with", plus Nautilus and Dolphin scripts |

All three do the same job as Android's share sheet: start a send from the OS's own file-picking surface.

## Android

### Receiving from the share sheet (UC-2)

```xml
<activity android:name=".ShareTargetActivity"
          android:exported="true"
          android:excludeFromRecents="true"
          android:theme="@style/Theme.Tradr.Dialog">
  <intent-filter>
    <action android:name="android.intent.action.SEND" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:mimeType="*/*" />
  </intent-filter>
  <intent-filter>
    <action android:name="android.intent.action.SEND_MULTIPLE" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:mimeType="*/*" />
  </intent-filter>
</activity>
```

On the Kotlin side:

1. Take the `content://` URIs from `Intent.EXTRA_STREAM`, singular or plural
2. **Never hand the URI straight to Rust.** A `content://` URI's permission is bound to the Intent and expires when the Activity does. `takePersistableUriPermission` applies only to `ACTION_OPEN_DOCUMENT` and friends, never to an `ACTION_SEND` URI
3. So, while the Activity lives, either read through `ContentResolver.openInputStream` into the app cache, or obtain a `ParcelFileDescriptor` and pass the fd to Rust
   - **Under 50 MB: copy to cache.** Simple and certain
   - **Larger: pass the fd.** Avoids the copy cost and the storage consumption. The fd stays valid as long as the process holds it
4. Take the filename from `DocumentsContract.Document.COLUMN_DISPLAY_NAME`; the tail of a URI is not necessarily a name
5. Show the destination picker, or send immediately if one is already chosen

**A dialog-themed Activity** keeps the share sheet from opening the whole app, showing only a small destination picker.

### Putting destinations directly in the share sheet

Android 11+ Sharing Shortcuts place "Send to Pixel 8" and "Send to ThinkPad" at the top of the share sheet, removing one tap.

```kotlin
// Publish discovered devices as sharing shortcuts
ShortcutManagerCompat.pushDynamicShortcut(context,
  ShortcutInfoCompat.Builder(context, "peer:$deviceId")
    .setShortLabel(peer.displayName)
    .setIcon(IconCompat.createWithResource(context, iconFor(peer.platform)))
    .setCategories(setOf("com.tradr.category.SEND"))
    .setLongLived(true)
    .setIntent(Intent(context, ShareTargetActivity::class.java)
      .setAction(Intent.ACTION_SEND)
      .putExtra(EXTRA_TARGET_DEVICE, deviceId))
    .build())
```

- `shortcuts.xml` declares a `<share-target>` bound to that category
- Updated as devices appear and vanish, throttled to roughly once a minute since `pushDynamicShortcut` is rate limited
- Four or five entries at most, most recently used first

Android 14+ also allows custom actions through `ChooserAction`, but Sharing Shortcuts suffice for v1.

### Where received files land

- `Downloads/Tradr/` by default, written through `MediaStore` so file managers see them
- The user may choose elsewhere with `ACTION_OPEN_DOCUMENT_TREE`
- Images and video are registered with `MediaStore` and appear in the gallery. Nothing else is, to avoid polluting it

### Share Roots and SAF

- The user picks a directory through `ACTION_OPEN_DOCUMENT_TREE`, followed by `takePersistableUriPermission`
- `MANAGE_EXTERNAL_STORAGE`, all-files access, is **not used**. Play Store review demands strong justification for it, and it is excessive for what users are agreeing to
- SAF incurs a Binder IPC per level. The directory tree is cached in SQLite and invalidated by a `ContentObserver`

### Foreground service

```xml
<service android:name=".TransferService"
         android:foregroundServiceType="dataSync"
         android:exported="false" />
```

- Started only during a transfer, never resident
- Android 14+ caps `dataSync` at six hours per day, so long transfers either split or warn the user as the cap approaches
- The notification shows progress, speed, path, and a cancel action

### Permissions

| Permission | API | Why | If refused |
|---|---|---|---|
| `BLUETOOTH_SCAN`, `neverForLocation` | 31+ | BLE discovery | BLE discovery off; LAN still works |
| `BLUETOOTH_ADVERTISE` | 31+ | Being findable over BLE | Others cannot find you; you can still find them |
| `BLUETOOTH_CONNECT` | 31+ | GATT connections | BLE transfer off |
| `NEARBY_WIFI_DEVICES` | 33+ | Wi-Fi Direct | Wi-Fi Direct off |
| `ACCESS_FINE_LOCATION` | up to 30 | BLE scanning on older APIs | As above |
| `POST_NOTIFICATIONS` | 33+ | Progress and arrival notifications | Works without notifications, worse experience |
| `FOREGROUND_SERVICE_DATA_SYNC` | 34+ | Continuing a transfer | Transfers only while the app is open |
| `INTERNET`, `ACCESS_NETWORK_STATE` | - | LAN and Brokr | - |

**`neverForLocation` is mandatory.** Without it, BLE scanning requires location permission, which raises users' resistance sharply. Tradr does not infer location from BLE, so the declaration is accurate.

Permissions are requested **individually, when first needed**, never in a batch at launch. Refusal disables only the affected capability; the app keeps working.

### Battery

- No continuous BLE scanning. Scans happen on screen-on and at an interval, 15 minutes by default and configurable
- Nothing runs during Doze. At Tier 2, FCM does the waking
- `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is **not requested**; only a path to the setting is offered
- On a metered link, detected via `ConnectivityManager.isActiveNetworkMetered`, relay is not used unless explicitly permitted

### Authentication

- OAuth through Chrome Custom Tabs with AppAuth. **WebViews are not used**, since Google rejects them
- Redirect on a custom scheme, `com.tradr.app:/oauth2redirect`
- The refresh token is encrypted with an Android Keystore key and stored in EncryptedSharedPreferences

## iOS constraints, for the future

Not being built, but worth confirming that **the current design does not exclude iOS**. These constraints will bite when iOS is added, and the protocol design already satisfies them.

| Constraint | Effect | How the design accommodates it |
|---|---|---|
| Local network access needs explicit permission via `NSLocalNetworkUsageDescription` | A prompt on first use; refusal blocks mDNS and direct connections | BLE and a Brokr still work when refused |
| Bonjour service types must be listed in `Info.plist` under `NSBonjourServices` | Service types cannot change at runtime | The service type is fixed at `_tradr._udp` |
| Background BLE advertising moves to the overflow area and is largely invisible to non-Apple scanners | iOS devices cannot be discovered while backgrounded | Discovery composes several channels and never depends on BLE alone |
| No Wi-Fi Direct equivalent; AWDL is private, leaving Multipeer Connectivity | `wifi-direct` is unavailable | `wifi-direct` was defined as Android-only from the start |
| No arbitrary background execution | Continuous listening is impossible | The same FCM/APNs wake-up model as Android |
| The filesystem is confined to the app sandbox | Arbitrary directories cannot be Share Roots | The `Vfs` trait abstracts this; a `FilesAppVfs` using security-scoped bookmarks slots in |
| Ed25519 is unavailable in the Secure Enclave | Key protection stops at the Keychain | Same as macOS, already documented in [05](05-security.md#key-storage) |

A `ShareViewController` provides the equivalent of `ACTION_SEND`, so UC-2 holds on iOS too.

**Whether Tauri's iOS support is good enough gets re-evaluated when iOS work begins.** It is newer than the Android support and there is not enough evidence yet. In the worst case, iOS is written natively in Swift with the Rust core linked as a static library — keeping `tradr-core` free of I/O exists partly to preserve that escape route.

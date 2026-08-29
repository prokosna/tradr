package com.tradr.plugin

import android.Manifest
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.activity.result.ActivityResult
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONArray
import org.json.JSONObject

// Only affects when logcat shows the push; Rust never blocks waiting for it.
private const val CHANNEL_PUSH_DELAY_MS = 1500L
private const val SHORTCUT_CATEGORY_SEND = "com.tradr.category.SEND"
private const val MAX_SHARING_SHORTCUTS = 5
const val ACTION_NOTIFICATION_ACCEPT = "com.tradr.plugin.ACTION_NOTIFICATION_ACCEPT"
const val ACTION_NOTIFICATION_DECLINE = "com.tradr.plugin.ACTION_NOTIFICATION_DECLINE"
const val EXTRA_NOTIFICATION_ID = "com.tradr.plugin.EXTRA_NOTIFICATION_ID"
const val EXTRA_TRANSFER_ID = "com.tradr.plugin.EXTRA_TRANSFER_ID"
private const val NOTIFICATION_CHANNEL_ID_TRANSFERS = "tradr_incoming_transfers"
private const val NOTIFICATION_CHANNEL_NAME_TRANSFERS = "Incoming Transfers"

@InvokeArg
class GreetArgs {
    var value: Int = 0
}

@InvokeArg
class OpenChannelArgs {
    var nonce: Int = 0
    var channel: Channel? = null
}

@InvokeArg
class InitShareChannelArgs {
    var channel: Channel? = null
}

@InvokeArg
class PeerShortcutDto {
    var deviceId: String = ""
    var displayName: String = ""
    var platform: String? = null
}

@InvokeArg
class PublishSharingShortcutsArgs {
    var peers: List<PeerShortcutDto> = emptyList()
}

@InvokeArg
class PluginRequestPermissionsArgs {
    var permissions: List<String>? = null
}

@InvokeArg
class ShowIncomingTransferNotificationArgs {
    var transferId: String? = null
    var senderName: String? = null
    var notificationId: Int? = null
}

// WI-M0-005 proves both ADR-0001 call directions with Rust; WI-M0-005b adds
// the ACTION_SEND intent channel; WI-M2-002 adds file caching and FD interop;
// WI-M2-003 publishes discovered peers as dynamic sharing shortcuts;
// WI-M2-004 adds SAF directory picker and persistable permission;
// WI-M2-006 adds staged platform permission requests;
// WI-M2-007 adds notification accept and decline actions.
@TauriPlugin(
    permissions = [
        Permission(strings = ["android.permission.BLUETOOTH_SCAN"], alias = "bluetoothScan"),
        Permission(strings = ["android.permission.BLUETOOTH_ADVERTISE"], alias = "bluetoothAdvertise"),
        Permission(strings = ["android.permission.BLUETOOTH_CONNECT"], alias = "bluetoothConnect"),
        Permission(strings = ["android.permission.NEARBY_WIFI_DEVICES"], alias = "nearbyWifiDevices"),
        Permission(strings = ["android.permission.ACCESS_FINE_LOCATION"], alias = "fineLocation"),
        Permission(strings = ["android.permission.POST_NOTIFICATIONS"], alias = "postNotifications"),
        Permission(strings = ["android.permission.FOREGROUND_SERVICE_DATA_SYNC"], alias = "foregroundServiceDataSync")
    ]
)
class TradrPlugin(private val activity: Activity) : Plugin(activity) {

    companion object {
        private var activeInstance: TradrPlugin? = null

        fun onNotificationAction(action: String, transferId: String?) {
            activeInstance?.forwardNotificationAction(action, transferId)
        }
    }

    init {
        activeInstance = this
    }

    // Prompts runtime permissions on demand for individual or batched capabilities.
    @Command
    override fun requestPermissions(invoke: Invoke) {
        val requested = try {
            val args = invoke.parseArgs(PluginRequestPermissionsArgs::class.java)
            args.permissions
        } catch (_: Exception) {
            null
        }

        val allPermissions = listOf(
            "bluetoothScan" to "android.permission.BLUETOOTH_SCAN",
            "bluetoothAdvertise" to "android.permission.BLUETOOTH_ADVERTISE",
            "bluetoothConnect" to "android.permission.BLUETOOTH_CONNECT",
            "nearbyWifiDevices" to "android.permission.NEARBY_WIFI_DEVICES",
            "fineLocation" to "android.permission.ACCESS_FINE_LOCATION",
            "postNotifications" to "android.permission.POST_NOTIFICATIONS",
            "foregroundServiceDataSync" to "android.permission.FOREGROUND_SERVICE_DATA_SYNC"
        )

        val aliasesToRequest = if (requested.isNullOrEmpty()) {
            allPermissions.map { it.first }.toTypedArray()
        } else {
            val matchingAliases = mutableSetOf<String>()
            for (req in requested) {
                for ((alias, permString) in allPermissions) {
                    if (req.equals(alias, ignoreCase = true) ||
                        req.equals(permString, ignoreCase = true) ||
                        req.endsWith(alias, ignoreCase = true) ||
                        permString.endsWith(req, ignoreCase = true)
                    ) {
                        matchingAliases.add(alias)
                    }
                }
            }
            if (matchingAliases.isEmpty()) {
                requested.toTypedArray()
            } else {
                matchingAliases.toTypedArray()
            }
        }

        requestPermissionForAliases(aliasesToRequest, invoke, "checkPermissions")
    }

    // Holds the channel Rust opens once at startup so share intents can be forwarded.
    private var shareChannel: Channel? = null

    // Launches the platform document tree picker for selecting a directory share root.
    @Command
    fun pickShareRoot(invoke: Invoke) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
        }
        startActivityForResult(invoke, intent, "onPickShareRootResult")
    }

    // Handles document tree picker results and persists URI permissions.
    @ActivityCallback
    fun onPickShareRootResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data
            if (uri != null) {
                val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                try {
                    activity.contentResolver.takePersistableUriPermission(uri, takeFlags)
                    val response = JSObject()
                    response.put("uri", uri.toString())
                    invoke.resolve(response)
                } catch (e: Exception) {
                    invoke.reject("Failed to take persistable URI permission: ${e.message}")
                }
            } else {
                val response = JSObject()
                response.put("uri", JSONObject.NULL)
                invoke.resolve(response)
            }
        } else {
            val response = JSObject()
            response.put("uri", JSONObject.NULL)
            invoke.resolve(response)
        }
    }

    // Direction 1, Rust calls into Kotlin: the transform and the device model both
    // only exist on this side, so Rust's printed line proves this method ran.
    @Command
    fun greet(invoke: Invoke) {
        val args = invoke.parseArgs(GreetArgs::class.java)
        val response = JSObject()
        response.put("value", args.value * 2 + 1)
        response.put("deviceModel", Build.MODEL)
        invoke.resolve(response)
    }

    // Direction 2, Kotlin initiates a call into Rust: acknowledge immediately, then
    // push the transformed nonce later, off this call's stack, through the channel
    // Rust handed us as an argument.
    @Command
    fun openChannel(invoke: Invoke) {
        val args = invoke.parseArgs(OpenChannelArgs::class.java)
        val channel = args.channel
        invoke.resolve()
        if (channel != null) {
            Handler(Looper.getMainLooper()).postDelayed({
                val push = JSObject()
                push.put("value", args.nonce + 1000)
                channel.send(push)
            }, CHANNEL_PUSH_DELAY_MS)
        }
    }

    // Rust calls this once at startup to register the intent receiving channel.
    @Command
    fun initShareChannel(invoke: Invoke) {
        val args = invoke.parseArgs(InitShareChannelArgs::class.java)
        shareChannel = args.channel
        invoke.resolve()
        forwardIfShareIntent(activity.intent)
    }

    // Android limits dynamic shortcuts per activity, so we cap entries to the top recent peers.
    @Command
    fun publishSharingShortcuts(invoke: Invoke) {
        val peersList = mutableListOf<PeerShortcutDto>()
        try {
            val args = invoke.parseArgs(PublishSharingShortcutsArgs::class.java)
            peersList.addAll(args.peers)
        } catch (_: Exception) {
            try {
                val rawObj = JSONObject(invoke.getRawArgs())
                val peersArray = rawObj.optJSONArray("peers")
                if (peersArray != null) {
                    for (i in 0 until peersArray.length()) {
                        val item = peersArray.optJSONObject(i) ?: continue
                        val dto = PeerShortcutDto().apply {
                            deviceId = item.optString("deviceId", "")
                            displayName = item.optString("displayName", "")
                            platform = if (item.has("platform") && !item.isNull("platform")) item.optString("platform") else null
                        }
                        if (dto.deviceId.isNotEmpty()) {
                            peersList.add(dto)
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }

        val maxAllowed = ShortcutManagerCompat.getMaxShortcutCountPerActivity(activity).coerceAtMost(MAX_SHARING_SHORTCUTS)
        val limit = if (maxAllowed > 0) maxAllowed else MAX_SHARING_SHORTCUTS
        val limitedPeers = peersList.filter { it.deviceId.isNotEmpty() }.take(limit)

        for (peer in limitedPeers) {
            val shortcutIntent = Intent(activity, ShareTargetActivity::class.java).apply {
                action = Intent.ACTION_SEND
                putExtra(EXTRA_TARGET_DEVICE, peer.deviceId)
            }
            val label = if (peer.displayName.isNotEmpty()) peer.displayName else peer.deviceId
            val shortcut = ShortcutInfoCompat.Builder(activity, "peer:${peer.deviceId}")
                .setShortLabel(label)
                .setIcon(IconCompat.createWithResource(activity, iconFor(activity, peer.platform)))
                .setCategories(setOf(SHORTCUT_CATEGORY_SEND))
                .setLongLived(true)
                .setIntent(shortcutIntent)
                .build()
            ShortcutManagerCompat.pushDynamicShortcut(activity, shortcut)
        }

        invoke.resolve()
    }

    private fun iconFor(context: Context, platform: String?): Int {
        val appIcon = context.applicationInfo.icon
        return if (appIcon != 0) appIcon else android.R.drawable.ic_menu_share
    }

    // singleTask delivers incoming intents to existing activity instances here.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        forwardIfShareIntent(intent)
    }

    // Pushes share intent details and cached/detached files to Rust.
    private fun forwardIfShareIntent(intent: Intent?) {
        val channel = shareChannel ?: return
        if (intent == null) {
            return
        }

        val jsonStr = intent.getStringExtra(EXTRA_SHARED_FILES_JSON)
        val filesArray = JSONArray()
        if (jsonStr != null) {
            val parsedArray = JSONArray(jsonStr)
            for (i in 0 until parsedArray.length()) {
                filesArray.put(parsedArray.getJSONObject(i))
            }
        } else if (intent.action == Intent.ACTION_SEND || intent.action == Intent.ACTION_SEND_MULTIPLE) {
            val processed = ShareIntentProcessor.processIntent(
                activity,
                activity.contentResolver,
                activity.cacheDir,
                intent
            )
            for (file in processed) {
                filesArray.put(file.toJson())
            }
        } else if (intent.action != ACTION_SHARED_FILES) {
            return
        }

        val payload = JSObject()
        payload.put("action", intent.action ?: ACTION_SHARED_FILES)
        payload.put("mimeType", intent.type)
        payload.put("extraText", intent.getStringExtra(Intent.EXTRA_TEXT))
        if (intent.hasExtra(EXTRA_TARGET_DEVICE)) {
            payload.put("targetDevice", intent.getStringExtra(EXTRA_TARGET_DEVICE))
        } else {
            payload.put("targetDevice", JSONObject.NULL)
        }
        payload.put("files", filesArray)
        channel.send(payload)
    }

    // Creates the notification channel on Android O+ for incoming transfer alerts.
    private fun createNotificationChannelIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            if (notificationManager != null) {
                val existing = notificationManager.getNotificationChannel(NOTIFICATION_CHANNEL_ID_TRANSFERS)
                if (existing == null) {
                    val channel = NotificationChannel(
                        NOTIFICATION_CHANNEL_ID_TRANSFERS,
                        NOTIFICATION_CHANNEL_NAME_TRANSFERS,
                        NotificationManager.IMPORTANCE_HIGH
                    ).apply {
                        description = "Notifications for incoming file transfers"
                    }
                    notificationManager.createNotificationChannel(channel)
                }
            }
        }
    }

    // Displays a notification with Accept and Decline actions for incoming transfers.
    @Command
    fun showIncomingTransferNotification(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(ShowIncomingTransferNotificationArgs::class.java)
        } catch (_: Exception) {
            ShowIncomingTransferNotificationArgs()
        }

        createNotificationChannelIfNeeded()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                activity,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                invoke.resolve()
                return
            }
        }

        val transferId = args.transferId
        val notifId = args.notificationId ?: (transferId?.hashCode() ?: 1001)
        val sender = args.senderName
        val contentText = if (!sender.isNullOrEmpty()) {
            "Incoming transfer from $sender"
        } else {
            "Incoming file transfer request"
        }

        val acceptIntent = Intent(activity, NotificationActionReceiver::class.java).apply {
            action = ACTION_NOTIFICATION_ACCEPT
            putExtra(EXTRA_NOTIFICATION_ID, notifId)
            if (transferId != null) {
                putExtra(EXTRA_TRANSFER_ID, transferId)
            }
        }
        val declineIntent = Intent(activity, NotificationActionReceiver::class.java).apply {
            action = ACTION_NOTIFICATION_DECLINE
            putExtra(EXTRA_NOTIFICATION_ID, notifId)
            if (transferId != null) {
                putExtra(EXTRA_TRANSFER_ID, transferId)
            }
        }

        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val acceptPendingIntent = PendingIntent.getBroadcast(
            activity,
            notifId * 2,
            acceptIntent,
            flags
        )
        val declinePendingIntent = PendingIntent.getBroadcast(
            activity,
            notifId * 2 + 1,
            declineIntent,
            flags
        )

        val iconRes = iconFor(activity, null)
        val builder = NotificationCompat.Builder(activity, NOTIFICATION_CHANNEL_ID_TRANSFERS)
            .setSmallIcon(iconRes)
            .setContentTitle("Incoming Transfer")
            .setContentText(contentText)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .addAction(0, "Accept", acceptPendingIntent)
            .addAction(0, "Decline", declinePendingIntent)

        val notificationManager = NotificationManagerCompat.from(activity)
        try {
            notificationManager.notify(notifId, builder.build())
        } catch (_: SecurityException) {
        }

        invoke.resolve()
    }

    // Forwards notification actions to Rust via the existing share channel.
    fun forwardNotificationAction(action: String, transferId: String?) {
        val channel = shareChannel ?: return
        val payload = JSObject()
        payload.put("action", action)
        if (transferId != null) {
            payload.put("transferId", transferId)
        } else {
            payload.put("transferId", JSONObject.NULL)
        }
        payload.put("mimeType", JSONObject.NULL)
        payload.put("extraText", JSONObject.NULL)
        payload.put("targetDevice", JSONObject.NULL)
        payload.put("files", JSONArray())
        channel.send(payload)
    }
}

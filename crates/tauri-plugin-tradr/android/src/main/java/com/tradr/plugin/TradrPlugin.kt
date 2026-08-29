package com.tradr.plugin

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.activity.result.ActivityResult
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
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

// WI-M0-005 proves both ADR-0001 call directions with Rust; WI-M0-005b adds
// the ACTION_SEND intent channel; WI-M2-002 adds file caching and FD interop;
// WI-M2-003 publishes discovered peers as dynamic sharing shortcuts;
// WI-M2-004 adds SAF directory picker and persistable permission.
@TauriPlugin
class TradrPlugin(private val activity: Activity) : Plugin(activity) {

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
}

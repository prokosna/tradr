package com.tradr.plugin

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

// Only affects when logcat shows the push; Rust never blocks waiting for it.
private const val CHANNEL_PUSH_DELAY_MS = 1500L

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

// WI-M0-005 proves both ADR-0001 call directions with Rust; WI-M0-005b adds
// the ACTION_SEND intent channel.
@TauriPlugin
class TradrPlugin(private val activity: Activity) : Plugin(activity) {

    // WI-M0-005b: holds the channel Rust opens once at startup, so a share
    // intent has somewhere to go however it arrives.
    private var shareChannel: Channel? = null

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

    // WI-M0-005b: Rust calls this once at startup. The activity's launch intent
    // is already set by the time this runs, so checking it here catches a cold
    // start; onNewIntent below catches the singleTask case afterward.
    @Command
    fun initShareChannel(invoke: Invoke) {
        val args = invoke.parseArgs(InitShareChannelArgs::class.java)
        shareChannel = args.channel
        invoke.resolve()
        forwardIfShareIntent(activity.intent)
    }

    // singleTask means an intent arriving while the activity is already running
    // comes through here instead of a fresh onCreate.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        forwardIfShareIntent(intent)
    }

    // Pushes an ACTION_SEND intent's action, MIME type and EXTRA_TEXT to Rust.
    // Anything else, including a null intent, is left alone.
    private fun forwardIfShareIntent(intent: Intent?) {
        val channel = shareChannel ?: return
        if (intent == null || intent.action != Intent.ACTION_SEND) {
            return
        }
        val payload = JSObject()
        payload.put("action", intent.action)
        payload.put("mimeType", intent.type)
        payload.put("extraText", intent.getStringExtra(Intent.EXTRA_TEXT))
        channel.send(payload)
    }
}

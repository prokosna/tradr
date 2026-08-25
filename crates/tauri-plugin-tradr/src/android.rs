//! Kotlin glue proving ADR-0001's second and third withdrawal conditions:
//! bidirectional calls between Rust and Kotlin, and an `ACTION_SEND` intent
//! reaching Rust. Runs once from the plugin's setup hook, no UI needed.

use serde::{Deserialize, Serialize};
use tauri::{
    Runtime,
    ipc::Channel,
    plugin::{PluginApi, PluginHandle},
};

const PLUGIN_PACKAGE: &str = "com.tradr.plugin";
const PLUGIN_CLASS: &str = "TradrPlugin";

/// Sent to Kotlin's `greet` command: an arbitrary number Kotlin must transform.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GreetRequest {
    value: i32,
}

/// Returned by Kotlin: the transformed number plus a device fact Rust has no way to
/// know except by asking Kotlin, so this line cannot be produced without the round
/// trip actually happening.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GreetResponse {
    value: i32,
    device_model: String,
}

/// Sent when opening the channel Kotlin will push through later, on its own schedule.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenChannelRequest {
    nonce: i32,
    channel: Channel<serde_json::Value>,
}

/// What Kotlin pushes back through the channel.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelPush {
    value: i32,
}

/// Sent once at startup: opens the channel Kotlin pushes every `ACTION_SEND`
/// intent through afterward, whichever launch state delivers it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitShareChannelRequest {
    channel: Channel<serde_json::Value>,
}

/// What Kotlin pushes each time the activity receives an `ACTION_SEND` intent:
/// its action, its declared MIME type, and the `EXTRA_TEXT` payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareIntent {
    action: String,
    mime_type: Option<String>,
    extra_text: Option<String>,
}

/// Runs both ADR-0001 call directions once and prints what each side proves.
pub fn demonstrate_bidirectional_calls<R: Runtime, C: serde::de::DeserializeOwned>(
    api: PluginApi<R, C>,
) -> Result<(), Box<dyn std::error::Error>> {
    let handle: PluginHandle<R> = api.register_android_plugin(PLUGIN_PACKAGE, PLUGIN_CLASS)?;

    // Direction 1, Rust calls into Kotlin: Kotlin's `greet` computes the transform
    // and reads its own device model, neither of which Rust has any other way to
    // produce, so the printed line proves the command actually ran in Kotlin.
    let sent = 41;
    let response: GreetResponse =
        handle.run_mobile_plugin("greet", GreetRequest { value: sent })?;
    println!(
        "WI-M0-005 rust-calls-kotlin: sent={sent} kotlin_returned_value={} kotlin_device_model={}",
        response.value, response.device_model
    );

    // Direction 2, Kotlin initiates a call into Rust: `openChannel` only acknowledges
    // receipt of the channel. Kotlin pushes the transformed nonce later, from a
    // Handler callback scheduled on its own timeline, well after this function and
    // the setup hook have returned, so the push cannot be part of this call's
    // response.
    let nonce = 4242;
    let channel = Channel::new(|body| {
        let push: ChannelPush = body.deserialize()?;
        println!(
            "WI-M0-005 kotlin-calls-rust: kotlin_pushed_value={}",
            push.value
        );
        Ok(())
    });
    handle.run_mobile_plugin::<()>("openChannel", OpenChannelRequest { nonce, channel })?;

    // WI-M0-005b, ADR-0001's third withdrawal condition: this channel stays open
    // for the rest of the process, and Kotlin pushes through it every time this
    // activity receives an ACTION_SEND intent, whether at cold start or through
    // onNewIntent while already running. Nothing printed here can be produced
    // without a real intent arriving from outside the app.
    let share_channel = Channel::new(|body| {
        let share: ShareIntent = body.deserialize()?;
        println!(
            "WI-M0-005b share-intent: action={} mime_type={} extra_text={}",
            share.action,
            share.mime_type.as_deref().unwrap_or("<none>"),
            share.extra_text.as_deref().unwrap_or("<none>")
        );
        Ok(())
    });
    handle.run_mobile_plugin::<()>(
        "initShareChannel",
        InitShareChannelRequest {
            channel: share_channel,
        },
    )?;

    Ok(())
}

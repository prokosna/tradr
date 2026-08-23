//! Kotlin glue proving ADR-0001's second withdrawal condition: bidirectional calls
//! between Rust and Kotlin. Runs once from the plugin's setup hook, no UI needed.

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

    Ok(())
}

//! Kotlin glue proving ADR-0001's second and third withdrawal conditions:
//! bidirectional calls between Rust and Kotlin, and an `ACTION_SEND` intent
//! reaching Rust. Runs once from the plugin's setup hook, no UI needed.

use serde::{Deserialize, Serialize};
use tauri::{
    Emitter, Runtime,
    ipc::Channel,
    plugin::{PluginApi, PluginHandle},
};

use crate::commands::ShowIncomingTransferNotificationArgs;
use tradr_app::share::{
    ACTION_NOTIFICATION_ACCEPT, ACTION_NOTIFICATION_DECLINE, PeerShortcut, PickFilesToSendResponse,
    PickShareRootResponse, ShareIntent, SharedFilePayload,
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

/// Sent to Kotlin's `publishSharingShortcuts` command.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishShortcutsRequest {
    peers: Vec<PeerShortcut>,
}

/// Handle wrapper stored in app state for invoking Android plugin methods.
#[derive(Clone)]
pub struct AndroidPluginHandle<R: Runtime>(pub PluginHandle<R>);

/// Runs both ADR-0001 call directions once and prints what each side proves.
pub fn demonstrate_bidirectional_calls<R: Runtime, C: serde::de::DeserializeOwned>(
    api: PluginApi<R, C>,
) -> Result<PluginHandle<R>, Box<dyn std::error::Error>> {
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
    let app_handle = api.app().clone();
    let share_channel = Channel::new(move |body| {
        let share: ShareIntent = body.deserialize()?;
        println!(
            "WI-M0-005b share-intent: action={} mime_type={} extra_text={} files_count={}",
            share.action,
            share.mime_type.as_deref().unwrap_or("<none>"),
            share.extra_text.as_deref().unwrap_or("<none>"),
            share.files.len()
        );
        for file in &share.files {
            println!(
                "shared file: name={} size={} cache_path={:?} fd={:?}",
                file.name, file.size, file.cache_path, file.fd
            );
        }
        if let Err(e) = app_handle.emit("share-intent", &share) {
            eprintln!("emit share-intent event failed: {e}");
        }
        if let Err(e) = app_handle.emit("shared-files", &share.files) {
            eprintln!("emit shared-files event failed: {e}");
        }
        if (share.action == ACTION_NOTIFICATION_ACCEPT
            || share.action == ACTION_NOTIFICATION_DECLINE)
            && let Err(e) = app_handle.emit("notification-action", &share)
        {
            eprintln!("emit notification-action event failed: {e}");
        }
        Ok(())
    });
    handle.run_mobile_plugin::<()>(
        "initShareChannel",
        InitShareChannelRequest {
            channel: share_channel,
        },
    )?;

    Ok(handle)
}

/// Publishes dynamic sharing shortcuts to Android's ShortcutManagerCompat.
pub fn publish_sharing_shortcuts<R: Runtime>(
    handle: &PluginHandle<R>,
    peers: Vec<PeerShortcut>,
) -> Result<(), String> {
    handle
        .run_mobile_plugin::<()>("publishSharingShortcuts", PublishShortcutsRequest { peers })
        .map_err(|e| format!("failed to publish sharing shortcuts: {e}"))
}

/// Invokes Android's SAF document tree picker and requests persistable URI permissions.
pub async fn pick_share_root<R: Runtime>(
    handle: &PluginHandle<R>,
) -> Result<Option<String>, String> {
    let response: PickShareRootResponse = handle
        .run_mobile_plugin_async("pickShareRoot", ())
        .await
        .map_err(|e| format!("failed to pick share root: {e}"))?;
    Ok(response.uri)
}

/// Invokes Android's document picker to stage selected files in the application cache.
pub async fn pick_files_to_send<R: Runtime>(
    handle: &PluginHandle<R>,
) -> Result<Vec<SharedFilePayload>, String> {
    let response: PickFilesToSendResponse = handle
        .run_mobile_plugin_async("pickFilesToSend", ())
        .await
        .map_err(|e| format!("failed to pick files to send: {e}"))?;
    Ok(response.files)
}

/// Shows an incoming transfer notification on Android with Accept and Decline actions.
pub async fn show_incoming_transfer_notification<R: Runtime>(
    handle: &PluginHandle<R>,
    transfer_id: Option<String>,
    sender_name: Option<String>,
) -> Result<(), String> {
    let args = ShowIncomingTransferNotificationArgs {
        transfer_id,
        sender_name,
    };
    handle
        .run_mobile_plugin_async("showIncomingTransferNotification", args)
        .await
        .map_err(|e| format!("failed to show incoming transfer notification: {e}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignInRequest<'a> {
    server_client_id: &'a str,
    nonce: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInResponse {
    success: bool,
    id_token: Option<String>,
    option_class: Option<String>,
    error_class: Option<String>,
    error_message: Option<String>,
}

/// Obtains an ID token from the platform credential API.
pub async fn sign_in<R: Runtime>(
    handle: &PluginHandle<R>,
    server_client_id: &str,
    nonce: &str,
) -> Result<String, String> {
    let request = SignInRequest {
        server_client_id,
        nonce,
    };
    let response: SignInResponse = handle
        .run_mobile_plugin_async("signIn", request)
        .await
        .map_err(|e| format!("failed to invoke signIn: {e}"))?;

    let option_class = response.option_class.as_deref().unwrap_or("<unknown>");
    println!("sign_in: option_class={option_class}");

    if response.success {
        response
            .id_token
            .ok_or_else(|| "credential response succeeded but contained no id_token".to_string())
    } else {
        let err_class = response
            .error_class
            .unwrap_or_else(|| "UnknownError".to_string());
        let err_msg = response.error_message.unwrap_or_default();
        Err(format!("sign-in failed: {err_class}: {err_msg}"))
    }
}

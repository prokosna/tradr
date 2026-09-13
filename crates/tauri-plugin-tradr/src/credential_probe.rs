#![forbid(unsafe_code)]
#![cfg(target_os = "android")]
//! Diagnostic probe measuring what Android's credential API returns (WI-M7-014).
//!
//! Kept in a separate module so it can be deleted in one step when
//! a subsequent Work Item acts on the measurement.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{Runtime, plugin::PluginHandle};

const PROBE_NONCE: &str = "tradr-m7-014-nonce";
const CLIENT_ID_ANDROID: &str =
    "475695468283-v4q25lmqo6kjova3crhiutnl59jnrckk.apps.googleusercontent.com";
const CLIENT_ID_WEB: &str =
    "475695468283-oa2utjksm5690ini7sguhr0luho6q6bq.apps.googleusercontent.com";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeCredentialArgs {
    server_client_id: String,
    nonce: String,
    option_class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeCredentialResponse {
    success: bool,
    id_token: Option<String>,
    error_class: Option<String>,
    error_message: Option<String>,
}

/// Spawns the credential API measurement probe without blocking the setup hook.
pub fn spawn_credential_probe<R: Runtime>(handle: PluginHandle<R>) {
    tauri::async_runtime::spawn(async move {
        // Setup returns before the Activity resumes, but the credential chooser requires a resumed Activity.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        run_probe(&handle, "googleId", CLIENT_ID_ANDROID).await;
        run_probe(&handle, "googleId", CLIENT_ID_WEB).await;
        run_probe(&handle, "signInWithGoogle", CLIENT_ID_ANDROID).await;
        run_probe(&handle, "signInWithGoogle", CLIENT_ID_WEB).await;
    });
}

async fn run_probe<R: Runtime>(handle: &PluginHandle<R>, option_class: &str, client_id: &str) {
    let args = ProbeCredentialArgs {
        server_client_id: client_id.to_string(),
        nonce: PROBE_NONCE.to_string(),
        option_class: option_class.to_string(),
    };

    let result = handle
        .run_mobile_plugin_async::<ProbeCredentialResponse>("probeCredential", args)
        .await;

    match result {
        Ok(response) => {
            if response.success {
                if let Some(token) = response.id_token {
                    match parse_and_inspect_jwt(&token) {
                        Ok(claims) => {
                            let nonce_val = claims.nonce.as_deref().unwrap_or("<missing>");
                            let nonce_matches = nonce_val == PROBE_NONCE;
                            let iss_val = claims.iss.as_deref().unwrap_or("<missing>");
                            let aud_val = claims.aud.as_deref().unwrap_or("<missing>");
                            let sub_val = claims.sub_prefix.as_deref().unwrap_or("<missing>");
                            println!(
                                "WI-M7-014 option_class={option_class} client_id={client_id}: success=true iss={iss_val} aud={aud_val} nonce={nonce_val} nonce_matches={nonce_matches} sub_prefix={sub_val}"
                            );
                        }
                        Err(parse_err) => {
                            println!(
                                "WI-M7-014 option_class={option_class} client_id={client_id}: success=false exception_class=JwtParseError message={parse_err}"
                            );
                        }
                    }
                } else {
                    println!(
                        "WI-M7-014 option_class={option_class} client_id={client_id}: success=false exception_class=MissingToken message=missing id_token in success response"
                    );
                }
            } else {
                let err_class = response
                    .error_class
                    .unwrap_or_else(|| "UnknownError".to_string());
                let err_msg = response.error_message.unwrap_or_default();
                println!(
                    "WI-M7-014 option_class={option_class} client_id={client_id}: success=false exception_class={err_class} message={err_msg}"
                );
            }
        }
        Err(err) => {
            println!(
                "WI-M7-014 option_class={option_class} client_id={client_id}: success=false exception_class=PluginInvokeError message={err}"
            );
        }
    }
}

struct InspectedClaims {
    iss: Option<String>,
    aud: Option<String>,
    nonce: Option<String>,
    sub_prefix: Option<String>,
}

fn parse_and_inspect_jwt(jwt: &str) -> Result<InspectedClaims, String> {
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or_else(|| "missing header".to_string())?;
    let payload_b64 = parts.next().ok_or_else(|| "missing payload".to_string())?;
    let _sig = parts
        .next()
        .ok_or_else(|| "missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("extraneous JWT segment".to_string());
    }

    let unpadded = payload_b64.trim_end_matches('=');
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(unpadded)
        .map_err(|e| format!("base64url decode failed: {e}"))?;

    let value: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("json parse failed: {e}"))?;

    let iss = value
        .get("iss")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let aud = value.get("aud").and_then(|v| {
        v.as_str()
            .map(str::to_string)
            .or_else(|| v.as_array().map(|a| format!("{a:?}")))
    });
    let nonce = value
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let sub_prefix = value.get("sub").and_then(|v| v.as_str()).map(|s| {
        let count = s.chars().count();
        if count <= 6 {
            s.to_string()
        } else {
            s.chars().take(6).collect()
        }
    });

    Ok(InspectedClaims {
        iss,
        aud,
        nonce,
        sub_prefix,
    })
}

//! Tauri entry point for the Tradr desktop and Android shell.
//!
//! Registers the `tauri-plugin-tradr` plugin; everything the plugin does happens
//! inside its own setup hook, since this file is only the composition root.

// Empty and absent both mean unconfigured, never distinguished: build.rs
// (DCR-030) emits an empty value when `.tradr-deployment.env` is absent
// so a fresh clone still builds, and omits the secret entirely on Android
// so `option_env!` reads it as absent rather than failing the build.
fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.filter(|v| !v.is_empty())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_tradr::init(
            non_empty(option_env!("TRADR_OAUTH_CLIENT_IDS")),
            non_empty(option_env!("TRADR_OAUTH_CLIENT_SECRET")),
        ))
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    // The only thing that will notice if build.rs stops plumbing
    // TRADR_OAUTH_CLIENT_IDS from the environment into the build (DCR-030).
    // Vacuously passes when the variable is unset, which keeps a fresh
    // clone's `cargo test` green.
    #[test]
    fn oauth_client_ids_reach_the_compiled_app() {
        if let Ok(expected) = std::env::var("TRADR_OAUTH_CLIENT_IDS")
            && !expected.is_empty()
        {
            assert_eq!(env!("TRADR_OAUTH_CLIENT_IDS"), expected);
        }
    }
}

//! Tauri entry point for the Tradr desktop and Android shell.
//!
//! Registers the `tauri-plugin-tradr` plugin; everything the plugin does happens
//! inside its own setup hook, since this file is only the composition root.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .plugin(tauri_plugin_tradr::init())
        .run(tauri::generate_context!())
}

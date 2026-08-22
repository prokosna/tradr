//! Tauri entry point for the Tradr desktop and Android shell.
//!
//! This Work Item is only about the shell starting: one window, no commands,
//! no dependency on any crate under `crates/`.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default().run(tauri::generate_context!())
}

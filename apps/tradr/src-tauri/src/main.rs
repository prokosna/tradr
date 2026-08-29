// Suppresses the console window Windows would otherwise open alongside the GUI in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> tauri::Result<()> {
    tradr_lib::run()
}

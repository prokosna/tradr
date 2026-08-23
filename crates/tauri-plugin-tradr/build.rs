// No JS-invokable commands: both call directions run from the plugin's own
// setup hook rather than through the IPC command surface.
const COMMANDS: &[&str] = &[];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}

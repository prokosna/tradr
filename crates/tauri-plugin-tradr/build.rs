// The Android call directions still run from the plugin's own setup hook,
// not through here.
const COMMANDS: &[&str] = &["device_identity", "sign_in", "sign_in_status"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}

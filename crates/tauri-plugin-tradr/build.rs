// device_identity is the only JS-invokable command; the Android call
// directions still run from the plugin's own setup hook, not through here.
const COMMANDS: &[&str] = &["device_identity"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}

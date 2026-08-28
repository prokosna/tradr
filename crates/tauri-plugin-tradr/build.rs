// The Android call directions still run from the plugin's own setup hook,
// not through here.
const COMMANDS: &[&str] = &[
    "device_identity",
    "sign_in",
    "sign_in_status",
    "attestation_bundle",
    "verify_peer_attestation",
    "get_peers",
    "send_files",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}

// The Android call directions still run from the plugin's own setup hook,
// not through here.
const COMMANDS: &[&str] = &[
    "device_identity",
    "sign_in",
    "sign_in_status",
    "attestation_bundle",
    "verify_peer_attestation",
    "get_peers",
    "get_visible_shares",
    "list_peer_directory",
    "send_files",
    "publish_sharing_shortcuts",
    "pick_share_root",
    "request_permissions",
    "check_permissions",
    "show_incoming_transfer_notification",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}

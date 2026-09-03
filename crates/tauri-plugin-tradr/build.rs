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
    "download_file",
    "send_files",
    "add_static_peer",
    "remove_static_peer",
    "list_static_peers",
    "publish_sharing_shortcuts",
    "pick_share_root",
    "request_permissions",
    "check_permissions",
    "show_incoming_transfer_notification",
    "open_link_invite",
    "reply_to_link_invite",
    "approve_link",
    "decline_link",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}

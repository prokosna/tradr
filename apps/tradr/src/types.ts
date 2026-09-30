// Mirrors the Rust struct crates/tauri-plugin-tradr/src/identity.rs
// returns from the `device_identity` command.
export interface DeviceIdentitySnapshot {
	device_id: string;
	backing: string;
	reason: string | null;
	storage: string;
}

export interface SharedFilePayload {
	name: string;
	size: number;
	cachePath: string | null;
	adoptedId: string | null;
}

export interface ShareIntent {
	action: string;
	mimeType: string | null;
	extraText: string | null;
	targetDevice: string | null;
	transferId: string | null;
	files: SharedFilePayload[];
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/sign_in.rs
// returns from `sign_in` and `sign_in_status`.
export interface SignInOutcome {
	issuer: string;
	subject: string;
	tier: string;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/attestation.rs
// returns from `attestation_bundle` and parses from `verify_peer_attestation`.
export interface AttestationBundle {
	id_token: string;
	identity_pub: string;
	agreement_pub: string;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/attestation.rs
// returns from `verify_peer_attestation`.
export interface VerifiedPeer {
	tier: string;
	account: string;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns from `get_peers`. `device_id` is empty for a peer nothing has
// identified yet -- a Static Peer entry before its first connection --
// so `key` (the Device ID, or the ObservationId before one is known) is
// what selection and list keys must use instead.
export interface PeerInfo {
	device_id: string;
	key: string;
	display_name: string | null;
	addresses: string[];
	capabilities: number;
	sources: string[];
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns from `list_static_peers`.
export interface StaticPeerInfo {
	id: string;
	label: string | null;
	endpoints: string[];
	expectDeviceId: string | null;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// received from the `transfer-progress` event.
export interface TransferProgressPayload {
	transfer_id: string;
	item_id: string;
	rel_path: string;
	bytes_transferred: number;
	total_bytes: number;
	status: string;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns from `get_visible_shares`.
export interface ShareInfo {
	shareId: string;
	label: string;
	mode: string;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns file entries in `list_peer_directory`.
export interface FileEntryDto {
	name: string;
	kind: "file" | "directory";
	sizeBytes: number;
	modified: number;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns paginated directory listing from `list_peer_directory`.
export interface DirListingDto {
	entries: FileEntryDto[];
	nextCursor: string;
	totalEstimate: number;
}

export interface LinkInviteDto {
	blob: string;
	fingerprint: string[];
}

export interface LinkProposalDto {
	peer_iss: string;
	peer_sub: string;
	peer_fingerprint: string[];
	peer_label: string | null;
	link_id: string;
}

export interface LinkDto {
	link_id: string;
	peer_iss: string;
	peer_sub: string;
	peer_label: string | null;
	created_at: number;
	full_access: boolean;
}

export interface LinkInvitePreviewDto {
	peer_fingerprint: string[];
	expired: boolean;
}

export interface LinkReplyDto {
	linked: boolean;
	link_id: string | null;
	decline_reason: string | null;
	// Read at the pause already; showing it again after the exchange would
	// be the comparison DCR-077 moved consent away from (docs/11).
	peer_fingerprint: string[];
}

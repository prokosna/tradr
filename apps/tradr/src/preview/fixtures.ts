import { emit } from "@tauri-apps/api/event";
import type {
	AttestationBundle,
	BrokrStatusDto,
	DeliveryDto,
	DeviceIdentitySnapshot,
	DirListingDto,
	FilesReceivedPayload,
	KnownDeviceDto,
	LinkDto,
	LinkInviteDto,
	LinkInvitePreviewDto,
	LinkProposalDto,
	LinkReplyDto,
	PeerInfo,
	ShareInfo,
	SignInOutcome,
	StaticPeerInfo,
	TransferProgressPayload,
	VerifiedPeer,
} from "../types.js";

export const fixtureReceivedFilesPayload: FilesReceivedPayload = {
	device_id: "dev-pixel-8",
	files: ["report-2026.pdf", "family-photo.jpg"],
};

export type Scenario = "signed-in" | "signed-out" | "empty" | "share" | "brokr";

export function getScenario(): Scenario {
	if (typeof window !== "undefined") {
		const s = new URLSearchParams(window.location.search).get("scenario");
		if (s === "signed-out" || s === "empty" || s === "share" || s === "brokr") {
			return s;
		}
	}
	return "signed-in";
}

export const fixtureIdentity: DeviceIdentitySnapshot = {
	device_id: "dev-local-preview",
	backing: "software",
	reason: null,
	storage: "software",
};

export const fixtureSignIn: SignInOutcome = {
	issuer: "https://accounts.google.com",
	subject: "109876543210987654321",
	tier: "same-account",
};

export const fixturePeers: PeerInfo[] = [
	{
		device_id: "dev-pixel-8",
		key: "dev-pixel-8",
		display_name: "Pixel 8",
		addresses: ["192.168.1.101:4433"],
		capabilities: 1,
		sources: ["mdns"],
	},
	{
		device_id: "dev-thinkpad",
		key: "dev-thinkpad",
		display_name: "ThinkPad",
		addresses: ["192.168.1.102:4433"],
		capabilities: 1,
		sources: ["mdns", "static-peer"],
	},
	{
		device_id: "dev-mac-mini",
		key: "dev-mac-mini",
		display_name: "Mac mini",
		addresses: ["100.64.0.103:4433"],
		capabilities: 1,
		sources: ["static-peer"],
	},
];

export const fixtureStaticPeers: StaticPeerInfo[] = [
	{
		id: "static-thinkpad",
		label: "ThinkPad",
		endpoints: ["192.168.1.102:4433"],
		expectDeviceId: "dev-thinkpad",
	},
];

export const fixtureLinks: LinkDto[] = [
	{
		link_id: "link-tablet",
		peer_iss: "https://accounts.google.com",
		peer_sub: "112233445566778899001",
		peer_label: "Personal Tablet",
		created_at: 1727654400,
		full_access: true,
	},
];

export const fixtureShares: ShareInfo[] = [
	{
		shareId: "share-primary",
		label: "Shared Folder",
		mode: "read-write",
	},
];

export const fixtureDirectory: DirListingDto = {
	entries: [
		{
			name: "Photos",
			kind: "directory",
			sizeBytes: 0,
			modified: 1727650000,
		},
		{
			name: "Documents",
			kind: "directory",
			sizeBytes: 0,
			modified: 1727640000,
		},
		{
			name: "report-2026.pdf",
			kind: "file",
			sizeBytes: 2457600,
			modified: 1727645000,
		},
		{
			name: "family-photo.jpg",
			kind: "file",
			sizeBytes: 4194304,
			modified: 1727635000,
		},
		{
			name: "project-notes.txt",
			kind: "file",
			sizeBytes: 12288,
			modified: 1727625000,
		},
	],
	nextCursor: "",
	totalEstimate: 5,
};

export const fixtureProgressEvents: TransferProgressPayload[] = [
	{
		transfer_id: "xfer-01",
		item_id: "item-01",
		rel_path: "report-2026.pdf",
		bytes_transferred: 1228800,
		total_bytes: 2457600,
		status: "in_progress",
	},
	{
		transfer_id: "xfer-01",
		item_id: "item-01",
		rel_path: "report-2026.pdf",
		bytes_transferred: 2457600,
		total_bytes: 2457600,
		status: "completed",
	},
];

export const fixtureAttestationBundle: AttestationBundle = {
	id_token: "preview-id-token",
	identity_pub: "preview-identity-pub",
	agreement_pub: "preview-agreement-pub",
};

export const fixtureVerifiedPeer: VerifiedPeer = {
	tier: "same-account",
	account: "preview-account",
};

const fixtureFingerprint = [
	"apple",
	"river",
	"shadow",
	"bright",
	"silver",
	"echo",
	"harbor",
	"forest",
	"quiet",
	"window",
	"amber",
	"stone",
];

export const fixtureLinkInvite: LinkInviteDto = {
	blob: "preview-invite-blob",
	fingerprint: fixtureFingerprint,
};

export const fixtureLinkProposal: LinkProposalDto = {
	peer_iss: "https://accounts.google.com",
	peer_sub: "112233445566778899001",
	peer_fingerprint: fixtureFingerprint,
	peer_label: "Personal Tablet",
	link_id: "link-tablet",
};

export const fixtureLinkInvitePreview: LinkInvitePreviewDto = {
	peer_fingerprint: fixtureFingerprint,
	expired: false,
};

export const fixtureLinkReply: LinkReplyDto = {
	linked: true,
	link_id: "link-tablet",
	decline_reason: null,
	peer_fingerprint: fixtureFingerprint,
};

export const fixtureRenameRefusal =
	"peer refused 'a.txt': that name is already taken";

export const fixtureKnownDevices: KnownDeviceDto[] = [
	{
		device_id: "dev-pixel-8",
		display_name: "Pixel 8",
		tier: "same-account",
		last_seen: 1727654400,
	},
	{
		device_id: "dev-thinkpad",
		display_name: "ThinkPad",
		tier: "same-account",
		last_seen: 1727654400,
	},
	{
		device_id: "dev-mac-mini",
		display_name: "Mac mini",
		tier: "same-account",
		last_seen: 1727654400,
	},
];

export const fixtureBrokrKnownDevices: KnownDeviceDto[] = [
	...fixtureKnownDevices,
	{
		device_id: "dev-old-laptop",
		display_name: "Old Laptop",
		tier: "same-account",
		last_seen: 1727000000,
	},
];

export const fixtureConfiguredBrokrStatus: BrokrStatusDto = {
	configured: true,
	url: "http://brokr.local:8080",
	last_pass: 1727654400,
	delivered: 1,
	last_error: null,
};

export const fixtureUnconfiguredBrokrStatus: BrokrStatusDto = {
	configured: false,
	url: null,
	last_pass: null,
	delivered: 0,
	last_error: null,
};

export const fixtureBrokrDeliveries: DeliveryDto[] = [
	{
		id: "deliv-waiting",
		recipient_device_id: "dev-old-laptop",
		recipient_name: "Old Laptop",
		names: ["notes.txt", "budget.csv"],
		sent_at: 1727650000,
		state: "waiting",
		collected_at: null,
	},
	{
		id: "deliv-delivered",
		recipient_device_id: "dev-thinkpad",
		recipient_name: "ThinkPad",
		names: ["archive.zip"],
		sent_at: 1727640000,
		state: "delivered",
		collected_at: 1727643600000,
	},
];

export interface ScenarioData {
	identity: DeviceIdentitySnapshot;
	signIn: SignInOutcome | null;
	peers: PeerInfo[];
	staticPeers: StaticPeerInfo[];
	links: LinkDto[];
	shares: ShareInfo[];
	directory: DirListingDto;
	brokrStatus: BrokrStatusDto;
	knownDevices: KnownDeviceDto[];
	deliveries: DeliveryDto[];
}

export function getScenarioData(scenario: Scenario): ScenarioData {
	switch (scenario) {
		case "signed-out":
			return {
				identity: fixtureIdentity,
				signIn: null,
				peers: [],
				staticPeers: [],
				links: [],
				shares: [],
				directory: { entries: [], nextCursor: "", totalEstimate: 0 },
				brokrStatus: fixtureUnconfiguredBrokrStatus,
				knownDevices: fixtureKnownDevices,
				deliveries: [],
			};
		case "empty":
			return {
				identity: fixtureIdentity,
				signIn: fixtureSignIn,
				peers: [],
				staticPeers: [],
				links: [],
				shares: [],
				directory: { entries: [], nextCursor: "", totalEstimate: 0 },
				brokrStatus: fixtureUnconfiguredBrokrStatus,
				knownDevices: fixtureKnownDevices,
				deliveries: [],
			};
		case "brokr":
			return {
				identity: fixtureIdentity,
				signIn: fixtureSignIn,
				peers: fixturePeers,
				staticPeers: fixtureStaticPeers,
				links: fixtureLinks,
				shares: fixtureShares,
				directory: fixtureDirectory,
				brokrStatus: fixtureConfiguredBrokrStatus,
				knownDevices: fixtureBrokrKnownDevices,
				deliveries: fixtureBrokrDeliveries,
			};
		case "share":
		case "signed-in":
			return {
				identity: fixtureIdentity,
				signIn: fixtureSignIn,
				peers: fixturePeers,
				staticPeers: fixtureStaticPeers,
				links: fixtureLinks,
				shares: fixtureShares,
				directory: fixtureDirectory,
				brokrStatus: fixtureUnconfiguredBrokrStatus,
				knownDevices: fixtureKnownDevices,
				deliveries: [],
			};
	}
}

export const activeScenario: Scenario = getScenario();
export const fixtureData: ScenarioData = getScenarioData(activeScenario);

export const currentIdentity: DeviceIdentitySnapshot = fixtureData.identity;
export const currentSignIn: SignInOutcome | null = fixtureData.signIn;
export const currentPeers: PeerInfo[] = fixtureData.peers;
export const currentStaticPeers: StaticPeerInfo[] = fixtureData.staticPeers;
export const currentLinks: LinkDto[] = fixtureData.links;
export const currentShares: ShareInfo[] = fixtureData.shares;
export const currentDirectory: DirListingDto = fixtureData.directory;

export const fixtureCommands: Record<
	string,
	(payload?: unknown) => unknown | Promise<unknown>
> = {
	"plugin:tradr|device_identity": () => fixtureData.identity,
	"plugin:tradr|sign_in_status": () => fixtureData.signIn,
	"plugin:tradr|sign_in": () => fixtureSignIn,
	"plugin:tradr|get_peers": () => fixtureData.peers,
	"plugin:tradr|list_static_peers": () => fixtureData.staticPeers,
	"plugin:tradr|add_static_peer": () => "static-thinkpad",
	"plugin:tradr|remove_static_peer": () => null,
	"plugin:tradr|get_visible_shares": () => fixtureData.shares,
	"plugin:tradr|list_peer_directory": () => fixtureData.directory,
	"plugin:tradr|download_file": () => "/tmp/report-2026.pdf",
	"plugin:tradr|rename_peer_entry": () => null,
	"plugin:tradr|delete_peer_entry": () => null,
	"plugin:tradr|make_peer_directory": () => null,
	"plugin:tradr|upload_to_peer": () => ["report-2026.pdf"],
	"plugin:tradr|pick_files_to_send": () => [
		{
			name: "report-2026.pdf",
			size: 2457600,
			cachePath: "/tmp/report-2026.pdf",
			adoptedId: null,
		},
	],
	"plugin:tradr|pick_shared_files": () => [
		{
			name: "report-2026.pdf",
			size: 2457600,
			cachePath: "/tmp/report-2026.pdf",
			adoptedId: null,
		},
	],
	"plugin:dialog|open": () => ["/tmp/report-2026.pdf"],
	"plugin:tradr|send_files": async (payload) => {
		const first = fixtureProgressEvents[0];
		const second = fixtureProgressEvents[1];
		if (first) {
			await emit("transfer-progress", first);
		}
		if (second) {
			await emit("transfer-progress", second);
		}
		const staged = payload as { paths?: string[] } | undefined;
		return staged?.paths ?? ["report-2026.pdf"];
	},
	"plugin:tradr|attestation_bundle": () => fixtureAttestationBundle,
	"plugin:tradr|verify_peer_attestation": () => fixtureVerifiedPeer,
	"plugin:tradr|list_links": () => fixtureData.links,
	"plugin:tradr|pending_link_proposal": () => null,
	"plugin:tradr|open_link_invite": () => fixtureLinkInvite,
	"plugin:tradr|preview_link_invite": () => fixtureLinkInvitePreview,
	"plugin:tradr|reply_to_link_invite": () => fixtureLinkReply,
	"plugin:tradr|approve_link": () => null,
	"plugin:tradr|decline_link": () => null,
	"plugin:tradr|remove_link": () => null,
	"plugin:tradr|set_link_full_access": () => null,
	"plugin:tradr|brokr_status": () => fixtureData.brokrStatus,
	"plugin:tradr|set_brokr": (payload) => {
		const args = payload as { url?: string; joinToken?: string } | undefined;
		return {
			configured: true,
			url: args?.url ?? "http://brokr.local:8080",
			last_pass: null,
			delivered: 0,
			last_error: null,
		};
	},
	"plugin:tradr|clear_brokr": () => null,
	"plugin:tradr|collect_brokr_now": () => null,
	"plugin:tradr|list_known_devices": () => fixtureData.knownDevices,
	"plugin:tradr|send_deferred": (payload) => {
		const args = payload as { deviceId?: string; files?: string[] } | undefined;
		return {
			id: "deliv-new",
			recipient_device_id: args?.deviceId ?? "dev-unknown",
			recipient_name: "Recipient",
			names: args?.files ?? ["file.txt"],
			sent_at: Math.floor(Date.now() / 1000),
			state: "waiting",
			collected_at: null,
		};
	},
	"plugin:tradr|list_deliveries": () => fixtureData.deliveries,
};

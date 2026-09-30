import type { PeerInfo, TransferProgressPayload } from "../types.js";

export type PeerSendStatus =
	| { status: "idle" }
	| { status: "waiting" }
	| {
			status: "sending";
			fileName: string;
			progress: TransferProgressPayload | null;
	  }
	| { status: "sent" }
	| { status: "failed"; error: string };

export interface DeviceTileProps {
	peer: PeerInfo;
	hasWaitingFiles: boolean;
	sendState?: PeerSendStatus | undefined;
	onTap: (peer: PeerInfo) => void;
	onOpenFolder: (peerKey: string) => void;
}

const SOURCE_PHRASES: Record<string, string> = {
	mdns: "on this network",
	"static-peer": "added by address",
	ble: "nearby",
};

export function DeviceTile({
	peer,
	hasWaitingFiles,
	sendState,
	onTap,
	onOpenFolder,
}: DeviceTileProps) {
	const name = peer.display_name || "Unnamed device";
	const initial = (name[0] || "?").toUpperCase();
	const sourceText = peer.sources.map((s) => SOURCE_PHRASES[s] ?? s).join(", ");

	const isBusy =
		sendState?.status === "sending" || sendState?.status === "waiting";

	const handleClick = () => {
		onTap(peer);
	};

	const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
		if (e.key === "Enter" || e.key === " ") {
			e.preventDefault();
			onTap(peer);
		}
	};

	const percent =
		sendState?.status === "sending" &&
		sendState.progress &&
		sendState.progress.total_bytes > 0
			? Math.round(
					(sendState.progress.bytes_transferred /
						sendState.progress.total_bytes) *
						100,
				)
			: 0;

	return (
		// biome-ignore lint/a11y/useSemanticElements: Tile contains an inner action button preventing nested button tags
		<div
			className={`device-tile ${isBusy ? "device-tile--busy" : ""} ${hasWaitingFiles ? "device-tile--target" : ""}`.trim()}
			role="button"
			tabIndex={0}
			data-device-key={peer.key}
			onClick={handleClick}
			onKeyDown={handleKeyDown}
		>
			<span className="avatar">{initial}</span>

			<div className="device-tile-info">
				<span className="device-tile-name">{name}</span>

				{sendState?.status === "sending" ? (
					<div className="stack">
						<span className="small muted">
							Sending {sendState.fileName} · {percent}%
						</span>
						<div className="progress">
							<progress
								className="progress-bar"
								value={sendState.progress?.bytes_transferred ?? 0}
								max={sendState.progress?.total_bytes || 1}
							/>
						</div>
					</div>
				) : sendState?.status === "waiting" ? (
					<span className="small muted">Waiting…</span>
				) : sendState?.status === "sent" ? (
					<span className="small success-text">Sent ✓</span>
				) : sendState?.status === "failed" ? (
					<div className="stack">
						<span className="small error-text">Couldn't send to {name}.</span>
						<span className="small muted">{sendState.error}</span>
					</div>
				) : (
					sourceText.length > 0 && (
						<span className="small muted device-tile-source">{sourceText}</span>
					)
				)}
			</div>

			{hasWaitingFiles && (
				<span className="device-tile-affordance">Send →</span>
			)}

			<button
				type="button"
				className="btn btn--ghost"
				onClick={(e) => {
					e.stopPropagation();
					onOpenFolder(peer.key);
				}}
			>
				Open folder
			</button>
		</div>
	);
}

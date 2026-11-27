import { useState } from "react";
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
	isOffline?: boolean | undefined;
	brokrConfigured?: boolean | undefined;
	hasWaitingFiles: boolean;
	sendState?: PeerSendStatus | undefined;
	onTap: (peer: PeerInfo) => void;
	onOpenFolder: (peerKey: string) => void;
	onForget?: ((deviceId: string) => Promise<void>) | undefined;
}

function formatDeviceSource(sources: string[]): string {
	if (sources.length === 0) return "";
	if (sources.includes("mdns")) {
		return "on this network";
	}
	return "added by address";
}

export function DeviceTile({
	peer,
	isOffline,
	brokrConfigured,
	hasWaitingFiles,
	sendState,
	onTap,
	onOpenFolder,
	onForget,
}: DeviceTileProps) {
	const [menuOpen, setMenuOpen] = useState(false);
	const [confirmingForget, setConfirmingForget] = useState(false);
	const [forgetError, setForgetError] = useState<string | undefined>(undefined);
	const canForget = Boolean(isOffline && onForget);

	const handleConfirmForget = () => {
		if (!onForget) return;
		onForget(peer.key).catch((e: unknown) => {
			setForgetError(String(e));
			setConfirmingForget(false);
		});
	};

	const name = peer.display_name || "Unnamed device";
	const initial = (name[0] || "?").toUpperCase();
	const sourceText = formatDeviceSource(peer.sources);

	const isBusy =
		sendState?.status === "sending" || sendState?.status === "waiting";
	const isTappable = isOffline
		? Boolean(brokrConfigured && hasWaitingFiles)
		: true;

	const handleClick = () => {
		if (!isTappable) return;
		onTap(peer);
	};

	const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
		if (!isTappable) return;
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

	const tileClasses = [
		"device-tile",
		isOffline ? "device-tile--offline" : "",
		!isTappable ? "device-tile--not-tappable" : "",
		isBusy ? "device-tile--busy" : "",
		hasWaitingFiles && (!isOffline || brokrConfigured)
			? "device-tile--target"
			: "",
	]
		.filter(Boolean)
		.join(" ");

	return (
		// A tile that cannot be tapped is not a button at all; marking it a
		// disabled one would disable the menu button inside it too.
		// biome-ignore lint/a11y/noStaticElementInteractions: the handlers ignore taps on a tile that is not a button
		<div
			className={tileClasses}
			role={isTappable ? "button" : undefined}
			tabIndex={isTappable ? 0 : undefined}
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
							{sendState.progress?.status === "preparing"
								? `Preparing ${sendState.fileName}`
								: `Sending ${sendState.fileName}`}
							{sendState.progress && sendState.progress.total_bytes > 0
								? ` · ${percent}%`
								: ""}
						</span>
						{sendState.progress && sendState.progress.total_bytes > 0 && (
							<div className="progress">
								<progress
									className="progress-bar"
									value={sendState.progress?.bytes_transferred ?? 0}
									max={sendState.progress?.total_bytes || 1}
								/>
							</div>
						)}
					</div>
				) : sendState?.status === "waiting" ? (
					<span className="small muted">Waiting…</span>
				) : sendState?.status === "sent" ? (
					<span className="small success-text">
						{isOffline ? "Will deliver when it's back ✓" : "Sent ✓"}
					</span>
				) : sendState?.status === "failed" ? (
					<div className="stack">
						<span className="small error-text">
							{isOffline
								? "Couldn't hand this over."
								: `Couldn't send to ${name}.`}
						</span>
						<span className="small muted">{sendState.error}</span>
					</div>
				) : isOffline ? (
					<span className="small muted device-tile-source">
						{brokrConfigured
							? "offline"
							: "offline · set up delivery in Settings to send later"}
					</span>
				) : (
					sourceText.length > 0 && (
						<span className="small muted device-tile-source">{sourceText}</span>
					)
				)}
			</div>

			{hasWaitingFiles && (!isOffline || brokrConfigured) && (
				<span className="device-tile-affordance">
					{isOffline ? "Send later →" : "Send →"}
				</span>
			)}

			{canForget &&
				(confirmingForget ? (
					// biome-ignore lint/a11y/noStaticElementInteractions: stops taps inside the confirmation from reaching the tile
					// biome-ignore lint/a11y/useKeyWithClickEvents: the buttons inside handle the keyboard
					<div
						className="inline-form device-tile-confirm"
						onClick={(e) => e.stopPropagation()}
					>
						<span className="small">Forget this device?</span>
						<button
							type="button"
							className="btn btn--danger"
							onClick={handleConfirmForget}
						>
							Forget
						</button>
						<button
							type="button"
							className="btn btn--ghost"
							onClick={() => setConfirmingForget(false)}
						>
							Cancel
						</button>
					</div>
				) : (
					<div className="device-tile-menu">
						<button
							type="button"
							className="btn btn--ghost"
							aria-label="Device actions"
							aria-expanded={menuOpen}
							onClick={(e) => {
								e.stopPropagation();
								setMenuOpen(!menuOpen);
							}}
						>
							⋯
						</button>
						{menuOpen && (
							<button
								type="button"
								className="btn btn--ghost device-tile-menu-item"
								onClick={(e) => {
									e.stopPropagation();
									setMenuOpen(false);
									setForgetError(undefined);
									setConfirmingForget(true);
								}}
							>
								Forget device
							</button>
						)}
					</div>
				))}

			{forgetError !== undefined && (
				<span className="small error-text device-tile-error">
					Couldn't forget this device. {forgetError}
				</span>
			)}

			{!isOffline && (
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
			)}
		</div>
	);
}

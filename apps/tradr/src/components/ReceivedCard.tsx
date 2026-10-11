import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { PeerInfo, ReceivedRow } from "../types.js";

/** Props for the received files history card. */
export interface ReceivedCardProps {
	items: ReceivedRow[];
	error: string | null;
	peers: PeerInfo[];
	onReload: () => void;
}

type FolderLoadState =
	| { status: "loading" }
	| { status: "loaded"; path: string | null | undefined }
	| { status: "error"; message: string };

function formatMeta(row: ReceivedRow, peers: PeerInfo[]): string {
	const peer = peers.find((p) => p.device_id === row.device_id);
	const deviceName = row.device_name || peer?.display_name || "another device";

	const receivedDate = new Date(row.received_at * 1000);
	const now = new Date();
	const isSameDay =
		receivedDate.getFullYear() === now.getFullYear() &&
		receivedDate.getMonth() === now.getMonth() &&
		receivedDate.getDate() === now.getDate();

	const whenStr = isSameDay
		? receivedDate.toLocaleTimeString([], {
				hour: "numeric",
				minute: "2-digit",
			})
		: receivedDate.toLocaleDateString();

	const prefix = row.how === "downloaded" ? "downloaded from " : "from ";
	return `${prefix}${deviceName} · ${whenStr}`;
}

/** Renders arrived files history and folder destination. */
export function ReceivedCard({
	items,
	error,
	peers,
	onReload,
}: ReceivedCardProps) {
	const [folder, setFolder] = useState<FolderLoadState>({
		status: "loading",
	});
	const [showAll, setShowAll] = useState(false);
	const [confirmingClear, setConfirmingClear] = useState(false);
	const [clearError, setClearError] = useState<string | null>(null);
	const [isClearing, setIsClearing] = useState(false);

	useEffect(() => {
		invoke<string | null | undefined>("plugin:tradr|receive_folder").then(
			(path) => setFolder({ status: "loaded", path }),
			(folderError) =>
				setFolder({ status: "error", message: String(folderError) }),
		);
	}, []);

	const handleStartClear = () => {
		setClearError(null);
		setConfirmingClear(true);
	};

	const handleCancelClear = () => {
		setConfirmingClear(false);
		setClearError(null);
	};

	const handleConfirmClear = async () => {
		setClearError(null);
		setIsClearing(true);
		try {
			await invoke("plugin:tradr|clear_received_history");
			setConfirmingClear(false);
			onReload();
		} catch (err) {
			setClearError(String(err));
		} finally {
			setIsClearing(false);
		}
	};

	const canClear = items.length > 0 || error !== null;
	const visibleItems = showAll ? items : items.slice(0, 50);

	return (
		<section className="card stack home-received">
			<div className="card-header">
				<h2 className="card-title">Received</h2>
				{canClear ? (
					confirmingClear ? (
						<div className="inline-form file-delete-confirm">
							<span className="file-delete-prompt">
								Clear this list? The files stay where they are.
							</span>
							<button
								type="button"
								className="btn btn--danger"
								onClick={handleConfirmClear}
								disabled={isClearing}
							>
								Clear
							</button>
							<button
								type="button"
								className="btn btn--ghost"
								onClick={handleCancelClear}
								disabled={isClearing}
							>
								Cancel
							</button>
						</div>
					) : (
						<button
							type="button"
							className="btn btn--ghost"
							onClick={handleStartClear}
							disabled={isClearing}
						>
							Clear
						</button>
					)
				) : null}
			</div>

			{folder.status === "loaded" && folder.path ? (
				<p className="muted received-folder">Saved in {folder.path}</p>
			) : null}
			{folder.status === "error" ? (
				<p className="error-text received-folder">
					Couldn't find where files are saved: {folder.message}
				</p>
			) : null}

			{clearError ? (
				<p className="error-text">Couldn't clear the list: {clearError}</p>
			) : null}

			{error ? (
				<p className="error-text">
					Couldn't read the list of received files: {error}
				</p>
			) : items.length === 0 ? (
				<p className="muted">Files sent to this device appear here.</p>
			) : (
				<>
					<ul className="list">
						{visibleItems.map((item) => {
							const name = item.path.split(/[/\\]/).pop() || item.path;
							return (
								<li key={item.id} className="file-row">
									<div className="file-row-content">
										<span className="file-icon">📄</span>
										<div className="file-details">
											<span className="file-name">{name}</span>
											<span className="file-meta muted">
												{formatMeta(item, peers)}
											</span>
										</div>
									</div>
								</li>
							);
						})}
					</ul>
					{items.length > 50 && !showAll ? (
						<div>
							<button
								type="button"
								className="btn btn--ghost"
								onClick={() => setShowAll(true)}
							>
								Show all ({items.length})
							</button>
						</div>
					) : null}
				</>
			)}
		</section>
	);
}

/// <reference types="vite/client" />
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useState } from "react";
import { Header } from "./components/Header.js";
import type {
	DirListingDto,
	FileEntryDto,
	PeerInfo,
	ShareInfo,
	ShareIntent,
	SharedFilePayload,
	SignInOutcome,
	TransferProgressPayload,
} from "./types.js";
import { Settings } from "./views/Settings.js";

interface StagedAdoptedFile {
	id: string;
	name: string;
}

function stagePayloads(files: SharedFilePayload[]): {
	paths: string[];
	adoptedIds: StagedAdoptedFile[];
	refused: string[];
} {
	const paths: string[] = [];
	const adoptedIds: StagedAdoptedFile[] = [];
	const refused: string[] = [];
	for (const file of files) {
		if (file.adoptedId !== null) {
			adoptedIds.push({ id: file.adoptedId, name: file.name });
		} else if (file.cachePath !== null) {
			paths.push(file.cachePath);
		} else {
			refused.push(file.name);
		}
	}
	return { paths, adoptedIds, refused };
}

export type SignInUiState =
	| { status: "signed_out" }
	| { status: "signing_in" }
	| { status: "signed_in"; outcome: SignInOutcome }
	| { status: "failed"; message: string };

const SOURCE_PHRASES: Record<string, string> = {
	mdns: "on this network",
	"static-peer": "added by hand",
	ble: "nearby over Bluetooth",
};

function formatSource(source: string): string {
	return SOURCE_PHRASES[source] ?? source;
}

type SendState =
	| { status: "idle" }
	| { status: "sending" }
	| { status: "success"; sentFiles: string[] }
	| { status: "error"; message: string };

type BrowseState =
	| { status: "idle" }
	| { status: "loading" }
	| { status: "loaded"; listing: DirListingDto }
	| { status: "error"; message: string };

function formatBytes(bytes: number): string {
	if (bytes === 0) return "0 B";
	const k = 1024;
	const sizes = ["B", "KiB", "MiB", "GiB"];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	const formatted = (bytes / k ** i).toFixed(1);
	return `${formatted} ${sizes[i]}`;
}

function formatTimestamp(timestampSecs: number): string {
	if (!timestampSecs) return "-";
	const date = new Date(timestampSecs * 1000);
	return date.toLocaleString();
}

export function App() {
	const [view, setView] = useState<"home" | "settings">("home");
	const [signIn, setSignIn] = useState<SignInUiState>({ status: "signed_out" });

	const [peers, setPeers] = useState<PeerInfo[]>([]);
	const [peerListError, setPeerListError] = useState<string | null>(null);
	const [selectedPeerId, setSelectedPeerId] = useState<string | null>(null);
	const [stagedFiles, setStagedFiles] = useState<string[]>([]);
	const [stagedAdopted, setStagedAdopted] = useState<StagedAdoptedFile[]>([]);
	const [fileSelectError, setFileSelectError] = useState<string | null>(null);
	const [isDragging, setIsDragging] = useState(false);
	const [sendState, setSendState] = useState<SendState>({ status: "idle" });
	const [progress, setProgress] = useState<TransferProgressPayload | null>(
		null,
	);

	const [shares, setShares] = useState<ShareInfo[]>([]);
	const [sharesError, setSharesError] = useState<string | null>(null);
	const [selectedShareId, setSelectedShareId] = useState<string>("");
	const [browsePath, setBrowsePath] = useState<string>("");
	const [browseState, setBrowseState] = useState<BrowseState>({
		status: "idle",
	});
	const [browseOpRunning, setBrowseOpRunning] = useState(false);
	const [browseError, setBrowseError] = useState<string | null>(null);
	const [downloadStatus, setDownloadStatus] = useState<Record<string, string>>(
		{},
	);
	const [newFolderName, setNewFolderName] = useState("");
	const [renamingEntry, setRenamingEntry] = useState<string | null>(null);
	const [renameValue, setRenameValue] = useState("");
	const [deletingEntry, setDeletingEntry] = useState<string | null>(null);

	const isBrowseBusy = browseOpRunning || browseState.status === "loading";

	const buildEntryPath = useCallback(
		(name: string) => (browsePath ? `${browsePath}/${name}` : name),
		[browsePath],
	);

	const loadShares = useCallback((peerId: string) => {
		invoke<ShareInfo[]>("plugin:tradr|get_visible_shares", { peerId })
			.then((fetchedShares) => {
				setSharesError(null);
				setShares(fetchedShares);
				if (fetchedShares.length > 0 && fetchedShares[0]) {
					setSelectedShareId(fetchedShares[0].shareId);
				} else {
					setSelectedShareId("");
				}
			})
			.catch((e) => {
				setSharesError(String(e));
				setShares([]);
				setSelectedShareId("");
			});
	}, []);

	useEffect(() => {
		if (selectedPeerId) {
			loadShares(selectedPeerId);
		} else {
			setShares([]);
			setSelectedShareId("");
			setBrowsePath("");
			setBrowseState({ status: "idle" });
			setBrowseError(null);
			setDownloadStatus({});
			setRenamingEntry(null);
			setDeletingEntry(null);
			setSharesError(null);
		}
	}, [selectedPeerId, loadShares]);

	const fetchDirectory = useCallback(
		(path: string, cursor = "") => {
			if (!selectedPeerId || !selectedShareId) {
				return;
			}
			setBrowseError(null);
			setBrowseState({ status: "loading" });
			invoke<DirListingDto>("plugin:tradr|list_peer_directory", {
				peerId: selectedPeerId,
				shareId: selectedShareId,
				path: path,
				cursor: cursor,
				limit: 200,
			})
				.then((listing) => {
					setBrowseState({ status: "loaded", listing });
				})
				.catch((error) => {
					const msg = String(error);
					setBrowseState({ status: "error", message: msg });
					setBrowseError(`Failed to browse directory: ${msg}`);
				});
		},
		[selectedPeerId, selectedShareId],
	);

	const handleNavigate = (newPath: string) => {
		setBrowseError(null);
		setDownloadStatus({});
		setRenamingEntry(null);
		setDeletingEntry(null);
		setBrowsePath(newPath);
		fetchDirectory(newPath);
	};

	const handleNavigateUp = () => {
		if (!browsePath) return;
		const parts = browsePath.split("/").filter(Boolean);
		parts.pop();
		const parentPath = parts.join("/");
		handleNavigate(parentPath);
	};

	const handleBreadcrumbClick = (index: number) => {
		if (index === -1) {
			handleNavigate("");
		} else {
			const parts = browsePath.split("/").filter(Boolean);
			const newPath = parts.slice(0, index + 1).join("/");
			handleNavigate(newPath);
		}
	};

	const handleDownloadFile = async (entryName: string) => {
		if (!selectedPeerId || !selectedShareId) return;
		setBrowseError(null);
		setBrowseOpRunning(true);
		const entryPath = buildEntryPath(entryName);
		try {
			const placedAt = await invoke<string>("plugin:tradr|download_file", {
				peerId: selectedPeerId,
				shareId: selectedShareId,
				path: entryPath,
			});
			setDownloadStatus((prev) => ({
				...prev,
				[entryName]: `Saved as ${placedAt}`,
			}));
		} catch (error) {
			const msg = String(error);
			setDownloadStatus((prev) => ({
				...prev,
				[entryName]: msg,
			}));
			setBrowseError(msg);
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleStartRename = (name: string) => {
		setBrowseError(null);
		setDeletingEntry(null);
		setRenamingEntry(name);
		setRenameValue(name);
	};

	const handleCancelRename = () => {
		setRenamingEntry(null);
		setRenameValue("");
	};

	const handleSaveRename = async (oldName: string) => {
		if (!selectedPeerId || !selectedShareId) return;
		const trimmed = renameValue.trim();
		if (!trimmed) return;
		if (trimmed === oldName) {
			setRenamingEntry(null);
			setRenameValue("");
			return;
		}
		setBrowseError(null);
		setDownloadStatus({});
		setBrowseOpRunning(true);
		const from = buildEntryPath(oldName);
		const to = buildEntryPath(trimmed);
		try {
			await invoke<void>("plugin:tradr|rename_peer_entry", {
				peerId: selectedPeerId,
				shareId: selectedShareId,
				from,
				to,
			});
			setRenamingEntry(null);
			setRenameValue("");
			fetchDirectory(browsePath);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleConfirmDelete = async (entry: FileEntryDto) => {
		if (!selectedPeerId || !selectedShareId) return;
		setBrowseError(null);
		setDownloadStatus({});
		setBrowseOpRunning(true);
		const targetPath = buildEntryPath(entry.name);
		try {
			await invoke<void>("plugin:tradr|delete_peer_entry", {
				peerId: selectedPeerId,
				shareId: selectedShareId,
				path: targetPath,
				recursive: entry.kind === "directory",
			});
			setDeletingEntry(null);
			fetchDirectory(browsePath);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleMakeDirectory = async () => {
		if (!selectedPeerId || !selectedShareId) return;
		const trimmed = newFolderName.trim();
		if (!trimmed) return;
		setBrowseError(null);
		setDownloadStatus({});
		setBrowseOpRunning(true);
		const targetPath = buildEntryPath(trimmed);
		try {
			await invoke<void>("plugin:tradr|make_peer_directory", {
				peerId: selectedPeerId,
				shareId: selectedShareId,
				path: targetPath,
			});
			setNewFolderName("");
			fetchDirectory(browsePath);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleUploadFiles = async () => {
		if (!selectedPeerId || !selectedShareId) return;
		setBrowseError(null);
		setDownloadStatus({});
		setBrowseOpRunning(true);
		try {
			let uploadFiles: string[] = [];
			let uploadAdoptedIds: string[] = [];

			const picked = await invoke<SharedFilePayload[] | null>(
				"plugin:tradr|pick_files_to_send",
			);
			if (picked === null) {
				const selected = await open({
					multiple: true,
				});
				if (Array.isArray(selected) && selected.length > 0) {
					uploadFiles = selected;
				} else if (typeof selected === "string") {
					uploadFiles = [selected];
				}
			} else if (picked.length > 0) {
				const { paths, adoptedIds, refused } = stagePayloads(picked);
				if (refused.length > 0) {
					setBrowseError(`Could not read files: ${refused.join(", ")}`);
				}
				uploadFiles = paths;
				uploadAdoptedIds = adoptedIds.map((a) => a.id);
			}

			if (uploadFiles.length > 0 || uploadAdoptedIds.length > 0) {
				await invoke<string[]>("plugin:tradr|upload_to_peer", {
					peerId: selectedPeerId,
					shareId: selectedShareId,
					destDir: browsePath,
					files: uploadFiles,
					adoptedIds: uploadAdoptedIds,
				});
				fetchDirectory(browsePath);
			}
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const refreshPeers = useCallback(() => {
		invoke<PeerInfo[]>("plugin:tradr|get_peers")
			.then((list) => {
				setPeerListError(null);
				setPeers(list);
				setSelectedPeerId((prev) => {
					if (list.length > 0 && prev === null) {
						const first = list[0];
						return first ? first.key : null;
					}
					return prev;
				});
			})
			.catch((e) => {
				setPeerListError(String(e));
			});
	}, []);

	useEffect(() => {
		refreshPeers();
		const interval = setInterval(refreshPeers, 2000);
		return () => clearInterval(interval);
	}, [refreshPeers]);

	useEffect(() => {
		// Restores an active sign-in session across webview reloads.
		invoke<SignInOutcome | null>("plugin:tradr|sign_in_status").then(
			(outcome) => {
				if (outcome) {
					setSignIn({ status: "signed_in", outcome });
				}
			},
		);

		let unlistenProgress: UnlistenFn | undefined;
		let unlistenSignInRestored: UnlistenFn | undefined;
		let unlistenDragDrop: UnlistenFn | undefined;
		let unlistenShareIntent: UnlistenFn | undefined;

		// Subscribes to transfer progress emitted by the composition root.
		listen<TransferProgressPayload>("transfer-progress", (event) => {
			setProgress(event.payload);
		}).then((unlisten) => {
			unlistenProgress = unlisten;
		});

		// Subscribes to kept sign-in restoration emitted after startup.
		listen<SignInOutcome>("sign-in-restored", (event) => {
			setSignIn({ status: "signed_in", outcome: event.payload });
		}).then((unlisten) => {
			unlistenSignInRestored = unlisten;
		});

		// Subscribes to share intents emitted by Android platform integration.
		listen<ShareIntent>("share-intent", async (event) => {
			const intent = event.payload;
			if (intent.files && intent.files.length > 0) {
				const { paths, adoptedIds, refused } = stagePayloads(intent.files);
				setStagedFiles(paths);
				setStagedAdopted(adoptedIds);
				if (refused.length > 0) {
					setFileSelectError(`Could not read files: ${refused.join(", ")}`);
				} else {
					setFileSelectError(null);
				}
				if (paths.length > 0 || adoptedIds.length > 0) {
					setSendState({ status: "idle" });

					const targetPeer = intent.targetDevice || null;

					if (!targetPeer) {
						try {
							const currentPeers = await invoke<PeerInfo[]>(
								"plugin:tradr|get_peers",
							);
							setPeerListError(null);
							if (currentPeers.length > 0) {
								setSelectedPeerId(currentPeers[0]?.key || null);
							}
						} catch (e) {
							setPeerListError(String(e));
						}
					} else {
						setSelectedPeerId(targetPeer);
						setSendState({ status: "sending" });
						invoke<string[]>("plugin:tradr|send_files", {
							peerId: targetPeer,
							files: paths,
							adoptedIds: adoptedIds.map((a) => a.id),
						})
							.then((sentFiles) => {
								setSendState({ status: "success", sentFiles });
								setStagedFiles([]);
								setStagedAdopted([]);
							})
							.catch((e) => {
								setSendState({ status: "error", message: String(e) });
							});
					}
				}
			}
		}).then((unlisten) => {
			unlistenShareIntent = unlisten;
		});

		// Subscribes to native window drag-and-drop events from Tauri.
		try {
			getCurrentWebview()
				// biome-ignore lint/suspicious/noExplicitAny: Event type not strongly typed by Tauri here
				.onDragDropEvent((event: any) => {
					if (event.payload.type === "enter" || event.payload.type === "over") {
						setIsDragging(true);
					} else if (event.payload.type === "drop") {
						setIsDragging(false);
						if (event.payload.paths.length > 0) {
							setStagedFiles(event.payload.paths);
							setStagedAdopted([]);
							setSendState({ status: "idle" });
						}
					} else {
						setIsDragging(false);
					}
				})
				.then((unlisten) => {
					unlistenDragDrop = unlisten;
				});
		} catch {
			// Fallback remains active when running in standard browser environments.
		}

		return () => {
			if (unlistenProgress) {
				unlistenProgress();
			}
			if (unlistenSignInRestored) {
				unlistenSignInRestored();
			}
			if (unlistenDragDrop) {
				unlistenDragDrop();
			}
			if (unlistenShareIntent) {
				unlistenShareIntent();
			}
		};
	}, []);

	const startSignIn = () => {
		setSignIn({ status: "signing_in" });
		invoke<SignInOutcome>("plugin:tradr|sign_in").then(
			(outcome) => setSignIn({ status: "signed_in", outcome }),
			(error) => setSignIn({ status: "failed", message: String(error) }),
		);
	};

	const handleSendFiles = () => {
		if (
			!selectedPeerId ||
			(stagedFiles.length === 0 && stagedAdopted.length === 0)
		) {
			return;
		}
		setSendState({ status: "sending" });
		invoke<string[]>("plugin:tradr|send_files", {
			peerId: selectedPeerId,
			files: stagedFiles,
			adoptedIds: stagedAdopted.map((a) => a.id),
		}).then(
			(sentFiles) => {
				setSendState({ status: "success", sentFiles });
				setStagedFiles([]);
				setStagedAdopted([]);
			},
			(error) => {
				setSendState({ status: "error", message: String(error) });
			},
		);
	};

	const handleHtmlDrop = (event: React.DragEvent<HTMLDivElement>) => {
		event.preventDefault();
		setIsDragging(false);
		const items = Array.from(event.dataTransfer.files).map((f) => f.name);
		if (items.length > 0) {
			setStagedFiles(items);
			setStagedAdopted([]);
			setSendState({ status: "idle" });
		}
	};

	return (
		// biome-ignore lint/a11y/noStaticElementInteractions: Window shell accepts file drop across the view
		<div
			className="app"
			onDragOver={(e) => {
				e.preventDefault();
				setIsDragging(true);
			}}
			onDragLeave={() => setIsDragging(false)}
			onDrop={handleHtmlDrop}
		>
			{isDragging && (
				<div
					style={{
						position: "fixed",
						inset: 0,
						backgroundColor: "rgba(0, 120, 255, 0.15)",
						border: "3px dashed #0078d4",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						zIndex: 1000,
						pointerEvents: "none",
					}}
				>
					<h2>Drop files anywhere to stage transfer</h2>
				</div>
			)}

			<Header
				status={signIn.status}
				onOpenSettings={() => setView("settings")}
			/>

			<main className="app-main">
				{view === "settings" ? (
					<Settings
						signIn={signIn}
						onSignIn={startSignIn}
						onBack={() => setView("home")}
					/>
				) : (
					<div className="stack">
						<section
							className="card"
							style={{
								marginTop: "1.5rem",
								borderTop: "1px solid #ccc",
								paddingTop: "1rem",
							}}
						>
							<h2 className="card-title">Peers</h2>
							<button type="button" onClick={refreshPeers}>
								Refresh Peers
							</button>
							{peerListError && (
								<p style={{ color: "red" }}>
									Failed to get peers: {peerListError}
								</p>
							)}
							{peers.length === 0 ? (
								<p>
									No peers found on the local network, added by hand, or nearby
									over Bluetooth yet.
								</p>
							) : (
								<ul style={{ listStyle: "none", padding: 0 }}>
									{peers.map((peer) => {
										const isIdentified = peer.device_id.length > 0;
										return (
											<li
												key={peer.key}
												style={{
													margin: "0.5rem 0",
													padding: "0.5rem",
													border:
														selectedPeerId === peer.key
															? "2px solid #0078d4"
															: "1px solid #ddd",
													borderRadius: "4px",
													cursor: "pointer",
												}}
												onClick={() => setSelectedPeerId(peer.key)}
												onKeyDown={(e) => {
													if (e.key === "Enter" || e.key === " ") {
														setSelectedPeerId(peer.key);
													}
												}}
											>
												<label style={{ cursor: "pointer", display: "block" }}>
													<input
														type="radio"
														name="peer-selection"
														value={peer.key}
														checked={selectedPeerId === peer.key}
														onChange={() => setSelectedPeerId(peer.key)}
														style={{ marginRight: "0.5rem" }}
													/>
													<strong>
														{peer.display_name || "Unnamed device"}
													</strong>
													<span
														style={{
															fontSize: "0.85em",
															color: "#666",
															marginLeft: "0.5rem",
														}}
													>
														{isIdentified
															? `(${peer.device_id.slice(0, 8)}...)`
															: "(not yet identified)"}
													</span>
												</label>
												{peer.sources.length > 0 && (
													<p
														style={{
															margin: "0.25rem 0 0 1.5rem",
															fontSize: "0.85em",
															color: "#666",
														}}
													>
														{peer.sources.map(formatSource).join(", ")}
													</p>
												)}
												{peer.addresses.length > 0 && (
													<p
														style={{
															margin: "0.25rem 0 0 1.5rem",
															fontSize: "0.8em",
															color: "#666",
														}}
													>
														Addresses: {peer.addresses.join(", ")}
													</p>
												)}
											</li>
										);
									})}
								</ul>
							)}
						</section>

						<section
							className="card"
							style={{
								marginTop: "1.5rem",
								borderTop: "1px solid #ccc",
								paddingTop: "1rem",
							}}
						>
							<h2 className="card-title">Send Files (Drag and Drop)</h2>
							<div
								style={{
									border: "2px dashed #999",
									borderRadius: "8px",
									padding: "1.5rem",
									textAlign: "center",
									backgroundColor: "#fafafa",
								}}
							>
								<p>
									Drag and drop files anywhere into the window, or choose files
									below.
								</p>
								<button
									type="button"
									onClick={async () => {
										try {
											const picked = await invoke<SharedFilePayload[] | null>(
												"plugin:tradr|pick_files_to_send",
											);
											if (picked === null) {
												const selected = await open({
													multiple: true,
												});
												setFileSelectError(null);
												if (Array.isArray(selected) && selected.length > 0) {
													setStagedFiles(selected);
													setStagedAdopted([]);
													setSendState({ status: "idle" });
												} else if (typeof selected === "string") {
													setStagedFiles([selected]);
													setStagedAdopted([]);
													setSendState({ status: "idle" });
												}
											} else if (picked.length > 0) {
												const { paths, adoptedIds, refused } =
													stagePayloads(picked);
												setStagedFiles(paths);
												setStagedAdopted(adoptedIds);
												if (refused.length > 0) {
													setFileSelectError(
														`Could not read files: ${refused.join(", ")}`,
													);
												} else {
													setFileSelectError(null);
												}
												if (paths.length > 0 || adoptedIds.length > 0) {
													setSendState({ status: "idle" });
												}
											}
										} catch (e) {
											setFileSelectError(String(e));
										}
									}}
								>
									Select Files
								</button>
								{fileSelectError && (
									<p style={{ color: "red" }}>
										Failed to open file dialog: {fileSelectError}
									</p>
								)}
							</div>

							{(stagedFiles.length > 0 || stagedAdopted.length > 0) && (
								<div style={{ marginTop: "1rem" }}>
									<h3>
										Staged files ({stagedFiles.length + stagedAdopted.length})
									</h3>
									<ul>
										{stagedFiles.map((file) => (
											<li key={file}>{file}</li>
										))}
										{stagedAdopted.map((item) => (
											<li key={`adopted-${item.id}`}>{item.name}</li>
										))}
									</ul>
									<button
										type="button"
										onClick={handleSendFiles}
										disabled={
											!selectedPeerId ||
											(stagedFiles.length === 0 &&
												stagedAdopted.length === 0) ||
											sendState.status === "sending"
										}
										style={{ marginRight: "0.5rem" }}
									>
										{sendState.status === "sending"
											? "Sending..."
											: "Send to Selected Peer"}
									</button>
									<button
										type="button"
										onClick={() => {
											setStagedFiles([]);
											setStagedAdopted([]);
										}}
										disabled={sendState.status === "sending"}
									>
										Clear Staged Files
									</button>
								</div>
							)}

							{sendState.status === "sending" && (
								<p>Sending files to peer...</p>
							)}
							{sendState.status === "error" && (
								<p style={{ color: "red" }}>
									Transfer failed: {sendState.message}
								</p>
							)}
							{sendState.status === "success" && (
								<p style={{ color: "green" }}>
									Successfully sent {sendState.sentFiles.length} file(s):{" "}
									{sendState.sentFiles.join(", ")}
								</p>
							)}

							{progress && (
								<div
									style={{
										marginTop: "1rem",
										padding: "0.75rem",
										border: "1px solid #ccc",
										borderRadius: "4px",
									}}
								>
									<h4>Transfer Progress</h4>
									<p>
										File: {progress.rel_path} ({progress.status})
									</p>
									<progress
										value={progress.bytes_transferred}
										max={progress.total_bytes || 1}
										style={{ width: "100%", height: "1.2rem" }}
									/>
									<p style={{ fontSize: "0.85em", color: "#666" }}>
										{progress.bytes_transferred} / {progress.total_bytes} bytes
										(
										{progress.total_bytes > 0
											? Math.round(
													(progress.bytes_transferred / progress.total_bytes) *
														100,
												)
											: 0}
										%)
									</p>
								</div>
							)}
						</section>

						<section
							className="card"
							style={{
								marginTop: "1.5rem",
								borderTop: "1px solid #ccc",
								paddingTop: "1rem",
							}}
						>
							<h2 className="card-title">Browse Peer Shares</h2>
							{!selectedPeerId ? (
								<p>
									Select a peer from Peers above to browse their shared files.
								</p>
							) : (
								<div>
									{sharesError && (
										<p style={{ color: "red" }}>
											Failed to load visible shares: {sharesError}
										</p>
									)}
									<div
										style={{
											display: "flex",
											alignItems: "center",
											gap: "0.5rem",
											marginBottom: "1rem",
											flexWrap: "wrap",
										}}
									>
										<label htmlFor="share-select">
											<strong>Share:</strong>
										</label>
										<select
											id="share-select"
											value={selectedShareId}
											onChange={(e) => {
												setSelectedShareId(e.target.value);
												setBrowsePath("");
												setBrowseError(null);
												setDownloadStatus({});
												setRenamingEntry(null);
												setDeletingEntry(null);
											}}
											style={{ padding: "0.25rem 0.5rem" }}
										>
											{shares.map((share) => (
												<option key={share.shareId} value={share.shareId}>
													{share.label} ({share.mode}) -{" "}
													{share.shareId.slice(0, 8)}
													...
												</option>
											))}
											{shares.length === 0 && (
												<option value="">No shares available</option>
											)}
										</select>
										<button
											type="button"
											onClick={() => fetchDirectory(browsePath)}
											disabled={isBrowseBusy}
										>
											{browseState.status === "loading"
												? "Loading..."
												: "Browse Share"}
										</button>
									</div>

									<div
										style={{
											display: "flex",
											alignItems: "center",
											gap: "0.5rem",
											marginBottom: "0.75rem",
											padding: "0.5rem",
											backgroundColor: "#f5f5f5",
											borderRadius: "4px",
										}}
									>
										<button
											type="button"
											onClick={handleNavigateUp}
											disabled={!browsePath || isBrowseBusy}
											style={{ padding: "0.2rem 0.6rem" }}
										>
											⬆ Up
										</button>

										<span style={{ fontWeight: 600 }}>Path:</span>
										<button
											type="button"
											onClick={() => handleBreadcrumbClick(-1)}
											disabled={isBrowseBusy}
											style={{
												background: "none",
												border: "none",
												color: "#0078d4",
												cursor: isBrowseBusy ? "default" : "pointer",
												padding: 0,
												textDecoration: "underline",
											}}
										>
											/
										</button>
										{browsePath
											.split("/")
											.filter(Boolean)
											.map((seg, idx, arr) => (
												<span
													key={arr.slice(0, idx + 1).join("/")}
													style={{
														display: "inline-flex",
														alignItems: "center",
														gap: "0.25rem",
													}}
												>
													<span>/</span>
													<button
														type="button"
														onClick={() => handleBreadcrumbClick(idx)}
														disabled={isBrowseBusy}
														style={{
															background: "none",
															border: "none",
															color: "#0078d4",
															cursor: isBrowseBusy ? "default" : "pointer",
															padding: 0,
															textDecoration:
																idx === arr.length - 1 ? "none" : "underline",
															fontWeight:
																idx === arr.length - 1 ? "bold" : "normal",
														}}
													>
														{seg}
													</button>
												</span>
											))}
									</div>

									{selectedShareId && (
										<div
											style={{
												display: "flex",
												alignItems: "center",
												gap: "0.5rem",
												marginBottom: "0.75rem",
												flexWrap: "wrap",
											}}
										>
											<button
												type="button"
												onClick={handleUploadFiles}
												disabled={isBrowseBusy}
											>
												Upload files
											</button>
											<div
												style={{
													display: "inline-flex",
													alignItems: "center",
													gap: "0.25rem",
												}}
											>
												<input
													type="text"
													placeholder="New folder name"
													value={newFolderName}
													onChange={(e) => setNewFolderName(e.target.value)}
													disabled={isBrowseBusy}
													onKeyDown={(e) => {
														if (e.key === "Enter") {
															handleMakeDirectory();
														}
													}}
													style={{ padding: "0.25rem 0.5rem" }}
												/>
												<button
													type="button"
													onClick={handleMakeDirectory}
													disabled={isBrowseBusy || !newFolderName.trim()}
												>
													New folder
												</button>
											</div>
										</div>
									)}

									{browseError && <p style={{ color: "red" }}>{browseError}</p>}

									{browseState.status === "loading" && (
										<p>Loading directory listing...</p>
									)}
									{browseState.status === "loaded" && (
										<div>
											{browseState.listing.entries.length === 0 ? (
												<p style={{ fontStyle: "italic", color: "#666" }}>
													This directory is empty.
												</p>
											) : (
												<table
													style={{
														width: "100%",
														borderCollapse: "collapse",
														marginTop: "0.5rem",
													}}
												>
													<thead>
														<tr
															style={{
																borderBottom: "2px solid #ddd",
																textAlign: "left",
															}}
														>
															<th style={{ padding: "0.5rem" }}>Name</th>
															<th style={{ padding: "0.5rem" }}>Type</th>
															<th style={{ padding: "0.5rem" }}>Size</th>
															<th style={{ padding: "0.5rem" }}>Modified</th>
															<th style={{ padding: "0.5rem" }}>Actions</th>
														</tr>
													</thead>
													<tbody>
														{browseState.listing.entries.map((entry) => (
															<tr
																key={entry.name}
																style={{
																	borderBottom: "1px solid #eee",
																}}
															>
																<td style={{ padding: "0.5rem" }}>
																	{renamingEntry === entry.name ? (
																		<div
																			style={{
																				display: "inline-flex",
																				alignItems: "center",
																				gap: "0.25rem",
																			}}
																		>
																			<span>
																				{entry.kind === "directory"
																					? "📁"
																					: "📄"}
																			</span>
																			<input
																				type="text"
																				value={renameValue}
																				onChange={(e) =>
																					setRenameValue(e.target.value)
																				}
																				disabled={isBrowseBusy}
																				onKeyDown={(e) => {
																					if (e.key === "Enter") {
																						handleSaveRename(entry.name);
																					} else if (e.key === "Escape") {
																						handleCancelRename();
																					}
																				}}
																				style={{ padding: "0.2rem" }}
																			/>
																			<button
																				type="button"
																				onClick={() =>
																					handleSaveRename(entry.name)
																				}
																				disabled={
																					isBrowseBusy || !renameValue.trim()
																				}
																				style={{ padding: "0.2rem 0.5rem" }}
																			>
																				Save
																			</button>
																			<button
																				type="button"
																				onClick={handleCancelRename}
																				disabled={isBrowseBusy}
																				style={{ padding: "0.2rem 0.5rem" }}
																			>
																				Cancel
																			</button>
																		</div>
																	) : entry.kind === "directory" ? (
																		<button
																			type="button"
																			onClick={() => {
																				const next = buildEntryPath(entry.name);
																				handleNavigate(next);
																			}}
																			disabled={isBrowseBusy}
																			style={{
																				background: "none",
																				border: "none",
																				color: "#0078d4",
																				cursor: isBrowseBusy
																					? "default"
																					: "pointer",
																				padding: 0,
																				font: "inherit",
																				textAlign: "left",
																				textDecoration: "underline",
																			}}
																		>
																			📁 {entry.name}
																		</button>
																	) : (
																		<span>📄 {entry.name}</span>
																	)}
																</td>
																<td
																	style={{
																		padding: "0.5rem",
																		textTransform: "capitalize",
																	}}
																>
																	{entry.kind}
																</td>
																<td style={{ padding: "0.5rem" }}>
																	{entry.kind === "directory"
																		? "-"
																		: formatBytes(entry.sizeBytes)}
																</td>
																<td style={{ padding: "0.5rem" }}>
																	{formatTimestamp(entry.modified)}
																</td>
																<td style={{ padding: "0.5rem" }}>
																	{entry.kind === "file" && (
																		<button
																			type="button"
																			onClick={() =>
																				handleDownloadFile(entry.name)
																			}
																			disabled={isBrowseBusy}
																			style={{ marginRight: "0.5rem" }}
																		>
																			Download
																		</button>
																	)}
																	{renamingEntry !== entry.name && (
																		<button
																			type="button"
																			onClick={() =>
																				handleStartRename(entry.name)
																			}
																			disabled={isBrowseBusy}
																			style={{ marginRight: "0.5rem" }}
																		>
																			Rename
																		</button>
																	)}
																	{deletingEntry === entry.name ? (
																		<button
																			type="button"
																			onClick={() => handleConfirmDelete(entry)}
																			disabled={isBrowseBusy}
																			style={{
																				color: "red",
																				fontWeight: "bold",
																			}}
																		>
																			Confirm delete
																		</button>
																	) : (
																		<button
																			type="button"
																			onClick={() => {
																				setBrowseError(null);
																				setDownloadStatus({});
																				setDeletingEntry(entry.name);
																			}}
																			disabled={isBrowseBusy}
																		>
																			Delete
																		</button>
																	)}
																	{entry.kind === "file" &&
																		downloadStatus[entry.name] && (
																			<span
																				style={{
																					marginLeft: "0.5rem",
																					fontSize: "0.85em",
																					color: downloadStatus[
																						entry.name
																					]?.startsWith("Saved as")
																						? "green"
																						: "red",
																				}}
																			>
																				{downloadStatus[entry.name]}
																			</span>
																		)}
																</td>
															</tr>
														))}
													</tbody>
												</table>
											)}
											{browseState.listing.nextCursor && (
												<div style={{ marginTop: "0.75rem" }}>
													<button
														type="button"
														onClick={() =>
															fetchDirectory(
																browsePath,
																browseState.listing.nextCursor,
															)
														}
														disabled={isBrowseBusy}
													>
														Load More Entries
													</button>
												</div>
											)}
										</div>
									)}
								</div>
							)}
						</section>
					</div>
				)}
			</main>
		</div>
	);
}

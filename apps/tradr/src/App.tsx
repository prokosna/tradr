/// <reference types="vite/client" />
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import type { PeerSendStatus } from "./components/DeviceTile.js";
import { Header } from "./components/Header.js";
import type { ActiveSendInfo, StagedFile } from "./components/SendCard.js";
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
import { Home } from "./views/Home.js";
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

function payloadsToStagedFiles(files: SharedFilePayload[]): {
	staged: StagedFile[];
	refused: string[];
} {
	const staged: StagedFile[] = [];
	const refused: string[] = [];
	for (const file of files) {
		if (file.adoptedId !== null || file.cachePath !== null) {
			staged.push({
				name: file.name,
				size: file.size,
				cachePath: file.cachePath,
				adoptedId: file.adoptedId,
			});
		} else {
			refused.push(file.name);
		}
	}
	return { staged, refused };
}

export type SignInUiState =
	| { status: "signed_out" }
	| { status: "signing_in" }
	| { status: "signed_in"; outcome: SignInOutcome }
	| { status: "failed"; message: string };

export type Route =
	| { view: "home" }
	| { view: "settings" }
	| { view: "folder"; peerKey: string };

export function parseRoute(hash: string): Route {
	const h = hash.startsWith("#") ? hash.slice(1) : hash;
	if (h === "/settings") {
		return { view: "settings" };
	}
	if (h.startsWith("/folder/")) {
		const rawKey = h.slice("/folder/".length);
		return { view: "folder", peerKey: decodeURIComponent(rawKey) };
	}
	return { view: "home" };
}

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
	const [route, setRoute] = useState<Route>(() =>
		typeof window !== "undefined"
			? parseRoute(window.location.hash)
			: { view: "home" },
	);
	const [signIn, setSignIn] = useState<SignInUiState>({ status: "signed_out" });

	const [peers, setPeers] = useState<PeerInfo[]>([]);
	const [, setPeerListError] = useState<string | null>(null);
	const [hasLoadedPeersOnce, setHasLoadedPeersOnce] = useState(false);
	const [selectedPeerId, setSelectedPeerId] = useState<string | null>(null);

	const [waitingFiles, setWaitingFiles] = useState<StagedFile[]>([]);
	const [activeSend, setActiveSend] = useState<ActiveSendInfo | null>(null);
	const [sendQueue, setSendQueue] = useState<ActiveSendInfo[]>([]);
	const [peerSendStates, setPeerSendStates] = useState<
		Record<string, PeerSendStatus>
	>({});
	const [sendError, setSendError] = useState<string | null>(null);
	const [progress, setProgress] = useState<TransferProgressPayload | null>(
		null,
	);
	const [isDragging, setIsDragging] = useState(false);

	const activeSendRef = useRef<ActiveSendInfo | null>(null);
	activeSendRef.current = activeSend;

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

	useEffect(() => {
		const handleHashChange = () => {
			setRoute(parseRoute(window.location.hash));
		};
		window.addEventListener("hashchange", handleHashChange);
		return () => window.removeEventListener("hashchange", handleHashChange);
	}, []);

	useEffect(() => {
		if (route.view === "folder") {
			setSelectedPeerId(route.peerKey);
		}
	}, [route]);

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
				setHasLoadedPeersOnce(true);
			})
			.catch((e) => {
				setPeerListError(String(e));
				setHasLoadedPeersOnce(true);
			});
	}, []);

	useEffect(() => {
		refreshPeers();
		const interval = setInterval(refreshPeers, 2000);
		return () => clearInterval(interval);
	}, [refreshPeers]);

	const enqueueSend = useCallback(
		(peerKey: string, filesToSend: StagedFile[]) => {
			if (filesToSend.length === 0) return;
			// Prevents duplicate queuing if this peer is already active or in queue.
			if (
				activeSend?.peerKey === peerKey ||
				sendQueue.some((item) => item.peerKey === peerKey)
			) {
				return;
			}

			const peer = peers.find((p) => p.key === peerKey);
			const targetName = peer?.display_name || "Unnamed device";
			const job: ActiveSendInfo = {
				peerKey,
				targetName,
				files: [...filesToSend],
			};

			if (activeSend === null) {
				setActiveSend(job);
				setPeerSendStates((prev) => ({
					...prev,
					[peerKey]: {
						status: "sending",
						fileName: job.files[0]?.name ?? "file",
						progress: null,
					},
				}));
			} else {
				setSendQueue((prev) => [...prev, job]);
				setPeerSendStates((prev) => ({
					...prev,
					[peerKey]: { status: "waiting" },
				}));
			}
		},
		[activeSend, sendQueue, peers],
	);

	useEffect(() => {
		if (!activeSend) {
			if (sendQueue.length > 0) {
				const [next, ...rest] = sendQueue;
				if (next) {
					setSendQueue(rest);
					setActiveSend(next);
					setPeerSendStates((prev) => ({
						...prev,
						[next.peerKey]: {
							status: "sending",
							fileName: next.files[0]?.name ?? "file",
							progress: null,
						},
					}));
				}
			}
			return;
		}

		let isCurrent = true;
		const { peerKey, files } = activeSend;
		const paths = files
			.filter((f) => f.cachePath !== null)
			.map((f) => f.cachePath as string);
		const adoptedIds = files
			.filter((f) => f.adoptedId !== null)
			.map((f) => f.adoptedId as string);

		invoke<string[]>("plugin:tradr|send_files", {
			peerId: peerKey,
			files: paths,
			adoptedIds: adoptedIds,
		})
			.then(() => {
				if (!isCurrent) return;
				// Clears waiting files and displays sent check for 4 seconds on success.
				setWaitingFiles([]);
				setSendError(null);
				setPeerSendStates((prev) => ({
					...prev,
					[peerKey]: { status: "sent" },
				}));
				setTimeout(() => {
					setPeerSendStates((prev) => {
						if (prev[peerKey]?.status === "sent") {
							const copy = { ...prev };
							delete copy[peerKey];
							return copy;
						}
						return prev;
					});
				}, 4000);
				setActiveSend(null);
			})
			.catch((e) => {
				if (!isCurrent) return;
				// Preserves waiting files for retry and reports error on failure.
				const msg = String(e);
				setSendError(msg);
				setPeerSendStates((prev) => ({
					...prev,
					[peerKey]: { status: "failed", error: msg },
				}));
				setActiveSend(null);
			});

		return () => {
			isCurrent = false;
		};
	}, [activeSend, sendQueue]);

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
			const current = activeSendRef.current;
			if (current) {
				const fileName =
					event.payload.rel_path || current.files[0]?.name || "file";
				setPeerSendStates((prev) => {
					if (prev[current.peerKey]?.status === "sending") {
						return {
							...prev,
							[current.peerKey]: {
								status: "sending",
								fileName,
								progress: event.payload,
							},
						};
					}
					return prev;
				});
			}
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
				const { staged, refused } = payloadsToStagedFiles(intent.files);
				if (refused.length > 0) {
					setSendError(`Could not read files: ${refused.join(", ")}`);
				} else {
					setSendError(null);
				}
				if (staged.length > 0) {
					const targetPeer = intent.targetDevice || null;
					if (targetPeer) {
						enqueueSend(targetPeer, staged);
					} else {
						setWaitingFiles(staged);
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
						const paths: string[] = event.payload.paths ?? [];
						if (paths.length > 0) {
							const staged: StagedFile[] = paths.map((path) => ({
								name: path.split(/[/\\]/).pop() || path,
								cachePath: path,
								adoptedId: null,
							}));
							const pos = event.payload.position;
							let targetPeerKey: string | null = null;
							if (
								pos &&
								typeof pos.x === "number" &&
								typeof pos.y === "number"
							) {
								const dpr = window.devicePixelRatio || 1;
								const clientX = pos.x / dpr;
								const clientY = pos.y / dpr;
								const el = document.elementFromPoint(clientX, clientY);
								const tile = el?.closest("[data-device-key]");
								if (tile) {
									targetPeerKey = tile.getAttribute("data-device-key");
								}
							}
							if (targetPeerKey) {
								enqueueSend(targetPeerKey, staged);
							} else {
								setWaitingFiles(staged);
							}
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
	}, [enqueueSend]);

	const startSignIn = () => {
		setSignIn({ status: "signing_in" });
		invoke<SignInOutcome>("plugin:tradr|sign_in").then(
			(outcome) => setSignIn({ status: "signed_in", outcome }),
			(error) => setSignIn({ status: "failed", message: String(error) }),
		);
	};

	const handleSelectFiles = async () => {
		try {
			const picked = await invoke<SharedFilePayload[] | null>(
				"plugin:tradr|pick_files_to_send",
			);
			if (picked === null) {
				const selected = await open({
					multiple: true,
				});
				setSendError(null);
				if (Array.isArray(selected) && selected.length > 0) {
					const staged: StagedFile[] = selected.map((p) => ({
						name: p.split(/[/\\]/).pop() || p,
						cachePath: p,
						adoptedId: null,
					}));
					setWaitingFiles(staged);
				}
			} else if (picked.length > 0) {
				const { staged, refused } = payloadsToStagedFiles(picked);
				if (refused.length > 0) {
					setSendError(`Could not read files: ${refused.join(", ")}`);
				} else {
					setSendError(null);
				}
				if (staged.length > 0) {
					setWaitingFiles(staged);
				}
			}
		} catch (e) {
			setSendError(String(e));
		}
	};

	const handleHtmlDrop = (event: React.DragEvent<HTMLDivElement>) => {
		event.preventDefault();
		setIsDragging(false);
		const files = Array.from(event.dataTransfer.files);
		if (files.length > 0) {
			const staged: StagedFile[] = files.map((f) => ({
				name: f.name,
				size: f.size,
				cachePath: null,
				adoptedId: null,
			}));
			const target = event.target as HTMLElement | null;
			const tile =
				target?.closest("[data-device-key]") ??
				document
					.elementFromPoint(event.clientX, event.clientY)
					?.closest("[data-device-key]");
			const targetPeerKey = tile?.getAttribute("data-device-key");
			if (targetPeerKey) {
				enqueueSend(targetPeerKey, staged);
			} else {
				setWaitingFiles(staged);
			}
		}
	};

	const handleTileTap = (peer: PeerInfo) => {
		if (waitingFiles.length > 0) {
			enqueueSend(peer.key, waitingFiles);
		} else {
			window.location.hash = `#/folder/${encodeURIComponent(peer.key)}`;
		}
	};

	const handleOpenFolder = (peerKey: string) => {
		window.location.hash = `#/folder/${encodeURIComponent(peerKey)}`;
	};

	const handleClearWaitingFiles = () => {
		setWaitingFiles([]);
	};

	const currentFolderPeer =
		route.view === "folder" ? peers.find((p) => p.key === route.peerKey) : null;
	const folderPeerName =
		currentFolderPeer?.display_name ||
		(route.view === "folder" ? route.peerKey : "") ||
		"Unnamed device";

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
				<div className="overlay">
					<h2>Drop to send</h2>
				</div>
			)}

			<Header
				status={signIn.status}
				onOpenSettings={() => {
					window.location.hash = "#/settings";
				}}
			/>

			<main className="app-main">
				{route.view === "settings" ? (
					<Settings
						signIn={signIn}
						onSignIn={startSignIn}
						onBack={() => {
							window.location.hash = "#/";
						}}
					/>
				) : route.view === "folder" ? (
					<div className="stack">
						<div className="page-header">
							<button
								type="button"
								className="btn"
								onClick={() => {
									window.location.hash = "#/";
								}}
							>
								Back
							</button>
							<h2>{folderPeerName}</h2>
						</div>

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
				) : (
					<Home
						signIn={signIn}
						onSignIn={startSignIn}
						peers={peers}
						hasLoadedPeersOnce={hasLoadedPeersOnce}
						waitingFiles={waitingFiles}
						isSending={activeSend !== null}
						activeSend={activeSend}
						progress={progress}
						sendError={sendError}
						peerSendStates={peerSendStates}
						onSelectFiles={handleSelectFiles}
						onClearWaitingFiles={handleClearWaitingFiles}
						onTileTap={handleTileTap}
						onOpenFolder={handleOpenFolder}
					/>
				)}
			</main>
		</div>
	);
}

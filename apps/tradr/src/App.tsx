/// <reference types="vite/client" />
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import type { PeerSendStatus } from "./components/DeviceTile.js";
import { Header } from "./components/Header.js";
import type { ReceivedItem } from "./components/ReceivedCard.js";
import type { ActiveSendInfo, StagedFile } from "./components/SendCard.js";
import type {
	FilesReceivedPayload,
	PeerInfo,
	ShareIntent,
	SharedFilePayload,
	SignInOutcome,
	TransferProgressPayload,
} from "./types.js";
import { Folder } from "./views/Folder.js";
import { Home } from "./views/Home.js";
import { Settings } from "./views/Settings.js";

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

function subscribe(subscribePromise: Promise<UnlistenFn>): () => void {
	let cancelled = false;
	let unlisten: UnlistenFn | undefined;
	subscribePromise.then((fn) => {
		if (cancelled) {
			fn();
		} else {
			unlisten = fn;
		}
	});
	return () => {
		cancelled = true;
		if (unlisten) {
			unlisten();
		}
	};
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
	const [receivedFiles, setReceivedFiles] = useState<ReceivedItem[]>([]);

	const activeSendRef = useRef<ActiveSendInfo | null>(null);
	activeSendRef.current = activeSend;

	useEffect(() => {
		const handleHashChange = () => {
			setRoute(parseRoute(window.location.hash));
		};
		window.addEventListener("hashchange", handleHashChange);
		return () => window.removeEventListener("hashchange", handleHashChange);
	}, []);

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

		const unlistens: (() => void)[] = [];

		// Subscribes to transfer progress emitted by the composition root.
		unlistens.push(
			subscribe(
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
				}),
			),
		);

		// Subscribes to kept sign-in restoration emitted after startup.
		unlistens.push(
			subscribe(
				listen<SignInOutcome>("sign-in-restored", (event) => {
					setSignIn({ status: "signed_in", outcome: event.payload });
				}),
			),
		);

		// Subscribes to share intents emitted by Android platform integration.
		unlistens.push(
			subscribe(
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
				}),
			),
		);

		// Subscribes to files received emitted by the transfer listener.
		unlistens.push(
			subscribe(
				listen<FilesReceivedPayload>("files-received", (event) => {
					const { device_id, files } = event.payload;
					const now = new Date();
					const incoming: ReceivedItem[] = files.map((filePath, idx) => ({
						id: `${now.getTime()}-${idx}-${filePath}`,
						deviceId: device_id,
						fileName: filePath.split(/[/\\]/).pop() || filePath,
						receivedAt: now,
					}));
					setReceivedFiles((prev) => [...incoming, ...prev].slice(0, 50));
				}),
			),
		);

		// Subscribes to native window drag-and-drop events from Tauri.
		try {
			unlistens.push(
				subscribe(
					getCurrentWebview()
						// biome-ignore lint/suspicious/noExplicitAny: Event type not strongly typed by Tauri here
						.onDragDropEvent((event: any) => {
							if (
								event.payload.type === "enter" ||
								event.payload.type === "over"
							) {
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
						}),
				),
			);
		} catch {
			// Fallback remains active when running in standard browser environments.
		}

		return () => {
			for (const unlisten of unlistens) {
				unlisten();
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
					<Folder
						peerKey={route.peerKey}
						peerName={folderPeerName}
						onBack={() => {
							window.location.hash = "#/";
						}}
					/>
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
						receivedFiles={receivedFiles}
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

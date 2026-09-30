import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useState } from "react";
import { Linking } from "./Linking.js";
import type {
	AttestationBundle,
	DeviceIdentitySnapshot,
	DirListingDto,
	FileEntryDto,
	PeerInfo,
	ShareInfo,
	ShareIntent,
	SharedFilePayload,
	SignInOutcome,
	StaticPeerInfo,
	TransferProgressPayload,
	VerifiedPeer,
} from "./types.js";

type IdentityLoadState =
	| { status: "loading" }
	| { status: "loaded"; snapshot: DeviceIdentitySnapshot }
	| { status: "error"; message: string };

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

type SignInUiState =
	| { status: "signed_out" }
	| { status: "signing_in" }
	| { status: "signed_in"; outcome: SignInOutcome }
	| { status: "failed"; message: string };

type BundleLoadState =
	| { status: "idle" }
	| { status: "loading" }
	| { status: "loaded"; bundle: AttestationBundle }
	| { status: "error"; message: string };

type PeerVerifyState =
	| { status: "idle" }
	| { status: "verifying" }
	| { status: "verified"; peer: VerifiedPeer }
	| { status: "error"; message: string };

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

type StaticPeerListState =
	| { status: "loading" }
	| { status: "loaded"; entries: StaticPeerInfo[] }
	| { status: "error"; message: string };

type StaticPeerActionState =
	| { status: "idle" }
	| { status: "adding" }
	| { status: "removing"; id: string }
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

// Main UI surface for discovery, transfer staging, and attestation verification.
export function App() {
	const [identity, setIdentity] = useState<IdentityLoadState>({
		status: "loading",
	});
	const [signIn, setSignIn] = useState<SignInUiState>({ status: "signed_out" });
	const [bundle, setBundle] = useState<BundleLoadState>({ status: "idle" });
	const [peerInput, setPeerInput] = useState("");
	const [peerVerify, setPeerVerify] = useState<PeerVerifyState>({
		status: "idle",
	});

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

	const [staticPeerList, setStaticPeerList] = useState<StaticPeerListState>({
		status: "loading",
	});
	const [staticPeerLabel, setStaticPeerLabel] = useState("");
	const [staticPeerEndpoints, setStaticPeerEndpoints] = useState("");
	const [staticPeerAction, setStaticPeerAction] =
		useState<StaticPeerActionState>({ status: "idle" });

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

	const loadStaticPeers = useCallback(() => {
		invoke<StaticPeerInfo[]>("plugin:tradr|list_static_peers")
			.then((entries) => setStaticPeerList({ status: "loaded", entries }))
			.catch((error) =>
				setStaticPeerList({ status: "error", message: String(error) }),
			);
	}, []);

	useEffect(() => {
		loadStaticPeers();
	}, [loadStaticPeers]);

	const handleAddStaticPeer = () => {
		const endpoints = staticPeerEndpoints
			.split(",")
			.map((endpoint) => endpoint.trim())
			.filter((endpoint) => endpoint.length > 0);
		if (endpoints.length === 0) {
			setStaticPeerAction({
				status: "error",
				message: "Enter at least one endpoint.",
			});
			return;
		}
		const label = staticPeerLabel.trim();
		setStaticPeerAction({ status: "adding" });
		invoke<string>("plugin:tradr|add_static_peer", {
			label: label.length > 0 ? label : null,
			endpoints,
		}).then(
			() => {
				setStaticPeerAction({ status: "idle" });
				setStaticPeerLabel("");
				setStaticPeerEndpoints("");
				loadStaticPeers();
			},
			(error) => {
				setStaticPeerAction({ status: "error", message: String(error) });
			},
		);
	};

	const handleRemoveStaticPeer = (id: string) => {
		setStaticPeerAction({ status: "removing", id });
		invoke<void>("plugin:tradr|remove_static_peer", { id }).then(
			() => {
				setStaticPeerAction({ status: "idle" });
				loadStaticPeers();
			},
			(error) => {
				setStaticPeerAction({ status: "error", message: String(error) });
			},
		);
	};

	useEffect(() => {
		invoke<DeviceIdentitySnapshot>("plugin:tradr|device_identity").then(
			(snapshot) => setIdentity({ status: "loaded", snapshot }),
			(error) => setIdentity({ status: "error", message: String(error) }),
		);

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

	const showBundle = () => {
		setBundle({ status: "loading" });
		invoke<AttestationBundle>("plugin:tradr|attestation_bundle").then(
			(bundle) => setBundle({ status: "loaded", bundle }),
			(error) => setBundle({ status: "error", message: String(error) }),
		);
	};

	const verifyPeer = () => {
		setPeerVerify({ status: "verifying" });
		invoke<VerifiedPeer>("plugin:tradr|verify_peer_attestation", {
			bundle: peerInput,
		}).then(
			(peer) => setPeerVerify({ status: "verified", peer }),
			(error) => setPeerVerify({ status: "error", message: String(error) }),
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
		<main
			style={{ position: "relative", minHeight: "100vh", padding: "1rem" }}
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

			<h1>Tradr</h1>
			{identity.status === "loading" && <p>Loading device identity...</p>}
			{identity.status === "error" && (
				<p>Could not open the key store: {identity.message}</p>
			)}
			{identity.status === "loaded" && (
				<p>
					This device is {identity.snapshot.device_id}. Its key is held in{" "}
					{identity.snapshot.backing}
					{identity.snapshot.reason ? ` (${identity.snapshot.reason})` : ""}, at
					the {identity.snapshot.storage} storage level.
				</p>
			)}

			{signIn.status === "signed_out" && (
				<button type="button" onClick={startSignIn}>
					Sign in with Google
				</button>
			)}
			{signIn.status === "signing_in" && <p>Signing in with Google...</p>}
			{signIn.status === "failed" && (
				<>
					<p>Sign-in failed: {signIn.message}</p>
					<button type="button" onClick={startSignIn}>
						Try again
					</button>
				</>
			)}
			{signIn.status === "signed_in" && (
				<p>
					Signed in as {signIn.outcome.subject} on {signIn.outcome.issuer} (
					{signIn.outcome.tier}).
				</p>
			)}

			<section
				style={{
					marginTop: "1.5rem",
					borderTop: "1px solid #ccc",
					paddingTop: "1rem",
				}}
			>
				<h2>Peers</h2>
				<button type="button" onClick={refreshPeers}>
					Refresh Peers
				</button>
				{peerListError && (
					<p style={{ color: "red" }}>Failed to get peers: {peerListError}</p>
				)}
				{peers.length === 0 ? (
					<p>
						No peers found on the local network, added by hand, or nearby over
						Bluetooth yet.
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
										<strong>{peer.display_name || "Unnamed device"}</strong>
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
				style={{
					marginTop: "1.5rem",
					borderTop: "1px solid #ccc",
					paddingTop: "1rem",
				}}
			>
				<h2>Static Peers</h2>
				<p>
					A reachable address you register by hand, for overlay networks and
					fixed IPs (Tailscale, WireGuard, ZeroTier). The first connection pins
					the peer's Device ID; later connections are refused if it changes. A
					registered entry appears in the Peers list above once it is reachable,
					and is selected there rather than here.
				</p>
				<div
					style={{
						display: "flex",
						gap: "0.5rem",
						flexWrap: "wrap",
						alignItems: "flex-end",
					}}
				>
					<label>
						<div>Label (optional)</div>
						<input
							type="text"
							value={staticPeerLabel}
							onChange={(e) => setStaticPeerLabel(e.target.value)}
							placeholder="Home desktop"
						/>
					</label>
					<label>
						<div>Endpoints</div>
						<input
							type="text"
							value={staticPeerEndpoints}
							onChange={(e) => setStaticPeerEndpoints(e.target.value)}
							placeholder="desktop.tail9f3c.ts.net, 192.168.10.5:21820"
							style={{ width: "22rem" }}
						/>
					</label>
					<button
						type="button"
						onClick={handleAddStaticPeer}
						disabled={staticPeerAction.status === "adding"}
					>
						{staticPeerAction.status === "adding"
							? "Adding..."
							: "Add Static Peer"}
					</button>
				</div>
				<p style={{ fontSize: "0.8em", color: "#666" }}>
					Separate multiple endpoints with commas. A missing port defaults to
					21820.
				</p>

				{staticPeerAction.status === "error" && (
					<p style={{ color: "red" }}>{staticPeerAction.message}</p>
				)}

				{staticPeerList.status === "loading" && <p>Loading static peers...</p>}
				{staticPeerList.status === "error" && (
					<p style={{ color: "red" }}>
						Could not load static peers: {staticPeerList.message}
					</p>
				)}
				{staticPeerList.status === "loaded" &&
					(staticPeerList.entries.length === 0 ? (
						<p>No static peers registered yet.</p>
					) : (
						<ul style={{ listStyle: "none", padding: 0 }}>
							{staticPeerList.entries.map((entry) => {
								const isRemoving =
									staticPeerAction.status === "removing" &&
									staticPeerAction.id === entry.id;
								return (
									<li
										key={entry.id}
										style={{
											margin: "0.5rem 0",
											padding: "0.5rem",
											border: "1px solid #ddd",
											borderRadius: "4px",
										}}
									>
										<strong>
											{entry.label || entry.endpoints[0] || entry.id}
										</strong>
										<p
											style={{
												margin: "0.25rem 0 0",
												fontSize: "0.85em",
												color: "#666",
											}}
										>
											Endpoints: {entry.endpoints.join(", ")}
										</p>
										<p
											style={{
												margin: "0.25rem 0 0",
												fontSize: "0.85em",
												color: "#666",
											}}
										>
											{entry.expectDeviceId
												? `Pinned to ${entry.expectDeviceId}`
												: "Not yet connected"}
										</p>
										<button
											type="button"
											onClick={() => handleRemoveStaticPeer(entry.id)}
											disabled={isRemoving}
											style={{ marginTop: "0.5rem" }}
										>
											{isRemoving ? "Removing..." : "Remove"}
										</button>
									</li>
								);
							})}
						</ul>
					))}
			</section>

			<section
				style={{
					marginTop: "1.5rem",
					borderTop: "1px solid #ccc",
					paddingTop: "1rem",
				}}
			>
				<h2>Account linking</h2>
				<Linking />
			</section>

			<section
				style={{
					marginTop: "1.5rem",
					borderTop: "1px solid #ccc",
					paddingTop: "1rem",
				}}
			>
				<h2>Send Files (Drag and Drop)</h2>
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
						Drag and drop files anywhere into the window, or choose files below.
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
									const { paths, adoptedIds, refused } = stagePayloads(picked);
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
						<h3>Staged files ({stagedFiles.length + stagedAdopted.length})</h3>
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
								(stagedFiles.length === 0 && stagedAdopted.length === 0) ||
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

				{sendState.status === "sending" && <p>Sending files to peer...</p>}
				{sendState.status === "error" && (
					<p style={{ color: "red" }}>Transfer failed: {sendState.message}</p>
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
							{progress.bytes_transferred} / {progress.total_bytes} bytes (
							{progress.total_bytes > 0
								? Math.round(
										(progress.bytes_transferred / progress.total_bytes) * 100,
									)
								: 0}
							%)
						</p>
					</div>
				)}
			</section>

			<section
				style={{
					marginTop: "1.5rem",
					borderTop: "1px solid #ccc",
					paddingTop: "1rem",
				}}
			>
				<h2>Browse Peer Shares</h2>
				{!selectedPeerId ? (
					<p>Select a peer from Peers above to browse their shared files.</p>
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
										{share.label} ({share.mode}) - {share.shareId.slice(0, 8)}
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
												fontWeight: idx === arr.length - 1 ? "bold" : "normal",
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
																	{entry.kind === "directory" ? "📁" : "📄"}
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
																	onClick={() => handleSaveRename(entry.name)}
																	disabled={isBrowseBusy || !renameValue.trim()}
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
																	cursor: isBrowseBusy ? "default" : "pointer",
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
																onClick={() => handleDownloadFile(entry.name)}
																disabled={isBrowseBusy}
																style={{ marginRight: "0.5rem" }}
															>
																Download
															</button>
														)}
														{renamingEntry !== entry.name && (
															<button
																type="button"
																onClick={() => handleStartRename(entry.name)}
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

			{signIn.status === "signed_in" && (
				<section
					style={{
						marginTop: "1.5rem",
						borderTop: "1px solid #ccc",
						paddingTop: "1rem",
					}}
				>
					<h2>This device's Attestation</h2>
					<p>Copy this to a peer, and paste theirs into the box below.</p>
					<button type="button" onClick={showBundle}>
						Show this device's Attestation
					</button>
					{bundle.status === "loading" && <p>Loading...</p>}
					{bundle.status === "error" && (
						<p>Could not build the bundle: {bundle.message}</p>
					)}
					{bundle.status === "loaded" && (
						<textarea
							readOnly
							rows={6}
							cols={80}
							value={JSON.stringify(bundle.bundle)}
						/>
					)}
				</section>
			)}

			<section
				style={{
					marginTop: "1.5rem",
					borderTop: "1px solid #ccc",
					paddingTop: "1rem",
				}}
			>
				<h2>Verify a peer's Attestation</h2>
				<textarea
					rows={6}
					cols={80}
					placeholder="Paste a peer's Attestation bundle here"
					value={peerInput}
					onChange={(event) => setPeerInput(event.target.value)}
				/>
				<div>
					<button
						type="button"
						onClick={verifyPeer}
						disabled={peerVerify.status === "verifying"}
					>
						Verify
					</button>
				</div>
				{peerVerify.status === "verifying" && <p>Verifying...</p>}
				{peerVerify.status === "error" && (
					<p>Could not verify: {peerVerify.message}</p>
				)}
				{peerVerify.status === "verified" && (
					<p>
						Peer is {peerVerify.peer.account} ({peerVerify.peer.tier}).
					</p>
				)}
			</section>
		</main>
	);
}

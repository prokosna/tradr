import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useState } from "react";

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/identity.rs
// returns from the `device_identity` command.
interface DeviceIdentitySnapshot {
	device_id: string;
	backing: string;
	reason: string | null;
	storage: string;
}

type IdentityLoadState =
	| { status: "loading" }
	| { status: "loaded"; snapshot: DeviceIdentitySnapshot }
	| { status: "error"; message: string };

interface SharedFilePayload {
	name: string;
	size: number;
	cachePath: string | null;
	fd: number | null;
}
interface ShareIntent {
	action: string;
	mimeType: string | null;
	extraText: string | null;
	targetDevice: string | null;
	transferId: string | null;
	files: SharedFilePayload[];
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/sign_in.rs
// returns from `sign_in` and `sign_in_status`.
interface SignInOutcome {
	issuer: string;
	subject: string;
	tier: string;
}

type SignInUiState =
	| { status: "signed_out" }
	| { status: "signing_in" }
	| { status: "signed_in"; outcome: SignInOutcome }
	| { status: "failed"; message: string };

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/attestation.rs
// returns from `attestation_bundle` and parses from `verify_peer_attestation`.
interface AttestationBundle {
	id_token: string;
	identity_pub: string;
	agreement_pub: string;
}

type BundleLoadState =
	| { status: "idle" }
	| { status: "loading" }
	| { status: "loaded"; bundle: AttestationBundle }
	| { status: "error"; message: string };

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/attestation.rs
// returns from `verify_peer_attestation`.
interface VerifiedPeer {
	tier: string;
	account: string;
}

type PeerVerifyState =
	| { status: "idle" }
	| { status: "verifying" }
	| { status: "verified"; peer: VerifiedPeer }
	| { status: "error"; message: string };

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns from `get_peers`. `device_id` is empty for a peer nothing has
// identified yet -- a Static Peer entry before its first connection --
// so `key` (the Device ID, or the ObservationId before one is known) is
// what selection and list keys must use instead.
interface PeerInfo {
	device_id: string;
	key: string;
	display_name: string | null;
	addresses: string[];
	capabilities: number;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns from `list_static_peers`.
interface StaticPeerInfo {
	id: string;
	label: string | null;
	endpoints: string[];
	expectDeviceId: string | null;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// received from the `transfer-progress` event.
interface TransferProgressPayload {
	transfer_id: string;
	item_id: string;
	rel_path: string;
	bytes_transferred: number;
	total_bytes: number;
	status: string;
}

type SendState =
	| { status: "idle" }
	| { status: "sending" }
	| { status: "success"; sentFiles: string[] }
	| { status: "error"; message: string };

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns from `get_visible_shares`.
interface ShareInfo {
	shareId: string;
	label: string;
	mode: string;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns file entries in `list_peer_directory`.
interface FileEntryDto {
	name: string;
	kind: "file" | "directory";
	sizeBytes: number;
	modified: number;
}

// Mirrors the Rust struct crates/tauri-plugin-tradr/src/commands.rs
// returns paginated directory listing from `list_peer_directory`.
interface DirListingDto {
	entries: FileEntryDto[];
	nextCursor: string;
	totalEstimate: number;
}

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
	const [selectedPeerId, setSelectedPeerId] = useState<string | null>(null);
	const [stagedFiles, setStagedFiles] = useState<string[]>([]);
	const [isDragging, setIsDragging] = useState(false);
	const [sendState, setSendState] = useState<SendState>({ status: "idle" });
	const [progress, setProgress] = useState<TransferProgressPayload | null>(
		null,
	);

	const [shares, setShares] = useState<ShareInfo[]>([]);
	const [selectedShareId, setSelectedShareId] = useState<string>("");
	const [browsePath, setBrowsePath] = useState<string>("");
	const [browseState, setBrowseState] = useState<BrowseState>({
		status: "idle",
	});

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
				setShares(fetchedShares);
				if (fetchedShares.length > 0 && fetchedShares[0]) {
					setSelectedShareId(fetchedShares[0].shareId);
				} else {
					setSelectedShareId("017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
				}
			})
			.catch((e) => {
				console.error("Failed to load visible shares:", e);
				setSelectedShareId("017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
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
		}
	}, [selectedPeerId, loadShares]);

	const fetchDirectory = useCallback(
		(path: string, cursor = "") => {
			if (!selectedPeerId || !selectedShareId) {
				return;
			}
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
					setBrowseState({ status: "error", message: String(error) });
				});
		},
		[selectedPeerId, selectedShareId],
	);

	const handleNavigate = (newPath: string) => {
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

	const refreshPeers = useCallback(() => {
		invoke<PeerInfo[]>("plugin:tradr|get_peers")
			.then((list) => {
				setPeers(list);
				setSelectedPeerId((prev) => {
					if (list.length > 0 && prev === null) {
						const first = list[0];
						return first ? first.key : null;
					}
					return prev;
				});
			})
			.catch((e) => console.error("Failed to get peers:", e));
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
		let unlistenDragDrop: UnlistenFn | undefined;
		let unlistenShareIntent: UnlistenFn | undefined;

		// Subscribes to transfer progress emitted by the composition root.
		listen<TransferProgressPayload>("transfer-progress", (event) => {
			setProgress(event.payload);
		}).then((unlisten) => {
			unlistenProgress = unlisten;
		});

		// Subscribes to share intents emitted by Android platform integration.
		listen<ShareIntent>("share-intent", async (event) => {
			const intent = event.payload;
			if (intent.files && intent.files.length > 0) {
				const filePaths = intent.files.map((f) => f.cachePath || f.name);
				setStagedFiles(filePaths);
				setSendState({ status: "idle" });

				const targetPeer = intent.targetDevice || null;

				if (!targetPeer) {
					try {
						const currentPeers = await invoke<PeerInfo[]>(
							"plugin:tradr|get_peers",
						);
						if (currentPeers.length > 0) {
							setSelectedPeerId(currentPeers[0]?.key || null);
						}
					} catch (e) {
						console.error("Failed to get peers for share intent", e);
					}
				} else {
					setSelectedPeerId(targetPeer);
					setSendState({ status: "sending" });
					invoke<string[]>("plugin:tradr|send_files", {
						peerId: targetPeer,
						files: filePaths,
					})
						.then((sentFiles) => {
							setSendState({ status: "success", sentFiles });
							setStagedFiles([]);
						})
						.catch((e) => {
							console.error("Failed to send files from share intent", e);
							setSendState({ status: "error", message: String(e) });
						});
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
		if (!selectedPeerId || stagedFiles.length === 0) {
			return;
		}
		setSendState({ status: "sending" });
		invoke<string[]>("plugin:tradr|send_files", {
			peerId: selectedPeerId,
			files: stagedFiles,
		}).then(
			(sentFiles) => {
				setSendState({ status: "success", sentFiles });
				setStagedFiles([]);
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
				<h2>Discovered Peers</h2>
				<button type="button" onClick={refreshPeers}>
					Refresh Peers
				</button>
				{peers.length === 0 ? (
					<p>No peers discovered on local network yet.</p>
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
										<strong>{peer.display_name || "Unidentified peer"}</strong>
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
					the peer's Device ID; later connections are refused if it changes.
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
								const selected = await open({
									multiple: true,
								});
								if (Array.isArray(selected) && selected.length > 0) {
									setStagedFiles(selected);
									setSendState({ status: "idle" });
								} else if (typeof selected === "string") {
									setStagedFiles([selected]);
									setSendState({ status: "idle" });
								}
							} catch (e) {
								console.error("Failed to open file dialog", e);
							}
						}}
					>
						Select Files
					</button>
				</div>

				{stagedFiles.length > 0 && (
					<div style={{ marginTop: "1rem" }}>
						<h3>Staged files ({stagedFiles.length})</h3>
						<ul>
							{stagedFiles.map((file) => (
								<li key={file}>{file}</li>
							))}
						</ul>
						<button
							type="button"
							onClick={handleSendFiles}
							disabled={!selectedPeerId || sendState.status === "sending"}
							style={{ marginRight: "0.5rem" }}
						>
							{sendState.status === "sending"
								? "Sending..."
								: "Send to Selected Peer"}
						</button>
						<button
							type="button"
							onClick={() => setStagedFiles([])}
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
					<p>
						Select a peer from Discovered Peers above to browse their shared
						files.
					</p>
				) : (
					<div>
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
								onChange={(e) => setSelectedShareId(e.target.value)}
								style={{ padding: "0.25rem 0.5rem" }}
							>
								{shares.map((share) => (
									<option key={share.shareId} value={share.shareId}>
										{share.label} ({share.mode}) - {share.shareId.slice(0, 8)}
										...
									</option>
								))}
								{shares.length === 0 && (
									<option value="017f22e2-79b0-7cc3-98c4-dc0c0c07398f">
										Default Share (017f22e2...)
									</option>
								)}
							</select>
							<button
								type="button"
								onClick={() => fetchDirectory(browsePath)}
								disabled={browseState.status === "loading"}
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
								disabled={!browsePath || browseState.status === "loading"}
								style={{ padding: "0.2rem 0.6rem" }}
							>
								⬆ Up
							</button>

							<span style={{ fontWeight: 600 }}>Path:</span>
							<button
								type="button"
								onClick={() => handleBreadcrumbClick(-1)}
								style={{
									background: "none",
									border: "none",
									color: "#0078d4",
									cursor: "pointer",
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
											style={{
												background: "none",
												border: "none",
												color: "#0078d4",
												cursor: "pointer",
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

						{browseState.status === "loading" && (
							<p>Loading directory listing...</p>
						)}
						{browseState.status === "error" && (
							<p style={{ color: "red" }}>
								Failed to browse directory: {browseState.message}
							</p>
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
														{entry.kind === "directory" ? (
															<button
																type="button"
																onClick={() => {
																	const next = browsePath
																		? `${browsePath}/${entry.name}`
																		: entry.name;
																	handleNavigate(next);
																}}
																style={{
																	background: "none",
																	border: "none",
																	color: "#0078d4",
																	cursor: "pointer",
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

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
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
// returns from `get_peers`.
interface PeerInfo {
	device_id: string;
	display_name: string | null;
	addresses: string[];
	capabilities: number;
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

	const refreshPeers = useCallback(() => {
		invoke<PeerInfo[]>("plugin:tradr|get_peers")
			.then((list) => {
				setPeers(list);
				setSelectedPeerId((prev) => {
					if (list.length > 0 && prev === null) {
						const first = list[0];
						return first ? first.device_id : null;
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
				let targetPeer = intent.targetDevice || null;
				if (!targetPeer) {
					try {
						const currentPeers = await invoke<PeerInfo[]>(
							"plugin:tradr|get_peers",
						);
						if (currentPeers.length > 0) {
							targetPeer = currentPeers[0]?.device_id || null;
						}
					} catch (e) {
						console.error("Failed to get peers for share intent", e);
					}
				}
				if (targetPeer) {
					const filePaths = intent.files.map((f) => f.cachePath || f.name);
					setSendState({ status: "sending" });
					invoke<string[]>("plugin:tradr|send_files", {
						peerId: targetPeer,
						files: filePaths,
					})
						.then((sentFiles) => {
							setSendState({ status: "success", sentFiles });
						})
						.catch((e) => {
							console.error("Failed to send files from share intent", e);
							setSendState({ status: "error", message: String(e) });
						});
				} else {
					setSendState({
						status: "error",
						message: "No peers available to auto-send to.",
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
						{peers.map((peer) => (
							<li
								key={peer.device_id}
								style={{
									margin: "0.5rem 0",
									padding: "0.5rem",
									border:
										selectedPeerId === peer.device_id
											? "2px solid #0078d4"
											: "1px solid #ddd",
									borderRadius: "4px",
									cursor: "pointer",
								}}
								onClick={() => setSelectedPeerId(peer.device_id)}
								onKeyDown={(e) => {
									if (e.key === "Enter" || e.key === " ") {
										setSelectedPeerId(peer.device_id);
									}
								}}
							>
								<label style={{ cursor: "pointer", display: "block" }}>
									<input
										type="radio"
										name="peer-selection"
										value={peer.device_id}
										checked={selectedPeerId === peer.device_id}
										onChange={() => setSelectedPeerId(peer.device_id)}
										style={{ marginRight: "0.5rem" }}
									/>
									<strong>{peer.display_name || peer.device_id}</strong>
									<span
										style={{
											fontSize: "0.85em",
											color: "#666",
											marginLeft: "0.5rem",
										}}
									>
										({peer.device_id.slice(0, 8)}...)
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
						))}
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
					<input
						type="file"
						multiple
						onChange={(e) => {
							if (e.target.files && e.target.files.length > 0) {
								const names = Array.from(e.target.files).map((f) => f.name);
								setStagedFiles(names);
								setSendState({ status: "idle" });
							}
						}}
					/>
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

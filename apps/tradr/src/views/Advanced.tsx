import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type {
	AttestationBundle,
	DeviceIdentitySnapshot,
	VerifiedPeer,
} from "../types.js";

type IdentityLoadState =
	| { status: "loading" }
	| { status: "loaded"; snapshot: DeviceIdentitySnapshot }
	| { status: "error"; message: string };

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

export interface AdvancedProps {
	signedIn?: boolean;
}

export function Advanced({ signedIn = false }: AdvancedProps) {
	const [identity, setIdentity] = useState<IdentityLoadState>({
		status: "loading",
	});
	const [bundle, setBundle] = useState<BundleLoadState>({ status: "idle" });
	const [peerInput, setPeerInput] = useState("");
	const [peerVerify, setPeerVerify] = useState<PeerVerifyState>({
		status: "idle",
	});

	useEffect(() => {
		invoke<DeviceIdentitySnapshot>("plugin:tradr|device_identity").then(
			(snapshot) => setIdentity({ status: "loaded", snapshot }),
			(error) => setIdentity({ status: "error", message: String(error) }),
		);
	}, []);

	const showBundle = () => {
		setBundle({ status: "loading" });
		invoke<AttestationBundle>("plugin:tradr|attestation_bundle").then(
			(loadedBundle) => setBundle({ status: "loaded", bundle: loadedBundle }),
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

	return (
		<div className="stack">
			{identity.status === "loading" && <p>Loading device identity...</p>}
			{identity.status === "error" && (
				<p className="error-text">
					Could not open the key store: {identity.message}
				</p>
			)}
			{identity.status === "loaded" && (
				<p>
					This device is {identity.snapshot.device_id}. Its key is held in{" "}
					{identity.snapshot.backing}
					{identity.snapshot.reason ? ` (${identity.snapshot.reason})` : ""}, at
					the {identity.snapshot.storage} storage level.
				</p>
			)}

			{signedIn && (
				<div className="stack">
					<h3>This device's Attestation</h3>
					<p>Copy this to a peer, and paste theirs into the box below.</p>
					<div>
						<button type="button" className="btn" onClick={showBundle}>
							Show this device's Attestation
						</button>
					</div>
					{bundle.status === "loading" && <p>Loading...</p>}
					{bundle.status === "error" && (
						<p className="error-text">
							Could not build the bundle: {bundle.message}
						</p>
					)}
					{bundle.status === "loaded" && (
						<textarea
							className="input"
							readOnly
							rows={6}
							cols={80}
							value={JSON.stringify(bundle.bundle)}
						/>
					)}
				</div>
			)}

			<div className="stack">
				<h3>Verify a peer's Attestation</h3>
				<textarea
					className="input"
					rows={6}
					cols={80}
					placeholder="Paste a peer's Attestation bundle here"
					value={peerInput}
					onChange={(event) => setPeerInput(event.target.value)}
				/>
				<div>
					<button
						type="button"
						className="btn"
						onClick={verifyPeer}
						disabled={peerVerify.status === "verifying"}
					>
						Verify
					</button>
				</div>
				{peerVerify.status === "verifying" && <p>Verifying...</p>}
				{peerVerify.status === "error" && (
					<p className="error-text">Could not verify: {peerVerify.message}</p>
				)}
				{peerVerify.status === "verified" && (
					<p>
						Peer is {peerVerify.peer.account} ({peerVerify.peer.tier}).
					</p>
				)}
			</div>
		</div>
	);
}

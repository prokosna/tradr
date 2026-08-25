import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";

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

// The app's first screen (WI-M0-014a, WI-M0-014b): shows the Device Key
// the store opened at startup, and lets a person sign in with Google to
// see which account this device now belongs to. Design and the rest of
// the UI belong to a later Work Item; this one proves both paths reach
// the app.
export function App() {
	const [identity, setIdentity] = useState<IdentityLoadState>({ status: "loading" });
	const [signIn, setSignIn] = useState<SignInUiState>({ status: "signed_out" });
	const [bundle, setBundle] = useState<BundleLoadState>({ status: "idle" });
	const [peerInput, setPeerInput] = useState("");
	const [peerVerify, setPeerVerify] = useState<PeerVerifyState>({ status: "idle" });

	useEffect(() => {
		invoke<DeviceIdentitySnapshot>("plugin:tradr|device_identity").then(
			(snapshot) => setIdentity({ status: "loaded", snapshot }),
			(error) => setIdentity({ status: "error", message: String(error) }),
		);

		// Restores a sign-in already completed before this reload, without
		// running the flow again.
		invoke<SignInOutcome | null>("plugin:tradr|sign_in_status").then((outcome) => {
			if (outcome) {
				setSignIn({ status: "signed_in", outcome });
			}
		});
	}, []);

	const startSignIn = () => {
		setSignIn({ status: "signing_in" });
		invoke<SignInOutcome>("plugin:tradr|sign_in").then(
			(outcome) => setSignIn({ status: "signed_in", outcome }),
			(error) => setSignIn({ status: "failed", message: String(error) }),
		);
	};

	// Shows what a peer needs to verify this device (WI-M0-016): the
	// id_token this device's own sign-in obtained, plus its two public
	// keys, as one JSON blob a person selects and copies by hand.
	const showBundle = () => {
		setBundle({ status: "loading" });
		invoke<AttestationBundle>("plugin:tradr|attestation_bundle").then(
			(bundle) => setBundle({ status: "loaded", bundle }),
			(error) => setBundle({ status: "error", message: String(error) }),
		);
	};

	// Runs docs/05's seven steps against a peer's pasted bundle.
	const verifyPeer = () => {
		setPeerVerify({ status: "verifying" });
		invoke<VerifiedPeer>("plugin:tradr|verify_peer_attestation", { bundle: peerInput }).then(
			(peer) => setPeerVerify({ status: "verified", peer }),
			(error) => setPeerVerify({ status: "error", message: String(error) }),
		);
	};

	return (
		<main>
			<h1>Tradr</h1>
			{identity.status === "loading" && <p>Loading device identity...</p>}
			{identity.status === "error" && <p>Could not open the key store: {identity.message}</p>}
			{identity.status === "loaded" && (
				<p>
					This device is {identity.snapshot.device_id}. Its key is held in{" "}
					{identity.snapshot.backing}
					{identity.snapshot.reason ? ` (${identity.snapshot.reason})` : ""}, at the{" "}
					{identity.snapshot.storage} storage level.
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

			{signIn.status === "signed_in" && (
				<section>
					<h2>This device's Attestation</h2>
					<p>Copy this to a peer, and paste theirs into the box below.</p>
					<button type="button" onClick={showBundle}>
						Show this device's Attestation
					</button>
					{bundle.status === "loading" && <p>Loading...</p>}
					{bundle.status === "error" && <p>Could not build the bundle: {bundle.message}</p>}
					{bundle.status === "loaded" && (
						<textarea readOnly rows={6} cols={80} value={JSON.stringify(bundle.bundle)} />
					)}
				</section>
			)}

			<section>
				<h2>Verify a peer's Attestation</h2>
				<textarea
					rows={6}
					cols={80}
					placeholder="Paste a peer's Attestation bundle here"
					value={peerInput}
					onChange={(event) => setPeerInput(event.target.value)}
				/>
				<div>
					<button type="button" onClick={verifyPeer} disabled={peerVerify.status === "verifying"}>
						Verify
					</button>
				</div>
				{peerVerify.status === "verifying" && <p>Verifying...</p>}
				{peerVerify.status === "error" && <p>Could not verify: {peerVerify.message}</p>}
				{peerVerify.status === "verified" && (
					<p>
						Peer is {peerVerify.peer.account} ({peerVerify.peer.tier}).
					</p>
				)}
			</section>
		</main>
	);
}

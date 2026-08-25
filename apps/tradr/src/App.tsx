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

// The app's first screen (WI-M0-014a, WI-M0-014b): shows the Device Key
// the store opened at startup, and lets a person sign in with Google to
// see which account this device now belongs to. Design and the rest of
// the UI belong to a later Work Item; this one proves both paths reach
// the app.
export function App() {
	const [identity, setIdentity] = useState<IdentityLoadState>({ status: "loading" });
	const [signIn, setSignIn] = useState<SignInUiState>({ status: "signed_out" });

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
		</main>
	);
}

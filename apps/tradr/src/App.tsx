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

// The app's first screen (WI-M0-014a): shows the Device Key the store
// opened at startup, or why it could not. Design and the rest of the UI
// belong to a later Work Item; this one proves the key store was reached.
export function App() {
	const [state, setState] = useState<IdentityLoadState>({ status: "loading" });

	useEffect(() => {
		invoke<DeviceIdentitySnapshot>("device_identity").then(
			(snapshot) => setState({ status: "loaded", snapshot }),
			(error) => setState({ status: "error", message: String(error) }),
		);
	}, []);

	return (
		<main>
			<h1>Tradr</h1>
			{state.status === "loading" && <p>Loading device identity...</p>}
			{state.status === "error" && <p>Could not open the key store: {state.message}</p>}
			{state.status === "loaded" && (
				<p>
					This device is {state.snapshot.device_id}. Its key is held in{" "}
					{state.snapshot.backing}
					{state.snapshot.reason ? ` (${state.snapshot.reason})` : ""}, at the{" "}
					{state.snapshot.storage} storage level.
				</p>
			)}
		</main>
	);
}

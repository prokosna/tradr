import type { SignInUiState } from "../App.js";
import { Linking } from "../Linking.js";
import { Advanced } from "./Advanced.js";
import { StaticPeers } from "./StaticPeers.js";

export interface SettingsProps {
	signIn: SignInUiState;
	onSignIn: () => void;
	onBack: () => void;
}

export function Settings({ signIn, onSignIn, onBack }: SettingsProps) {
	return (
		<div className="card stack">
			<div className="page-header">
				<button type="button" className="btn" onClick={onBack}>
					Back
				</button>
				<h2>Settings</h2>
			</div>

			<section className="settings-section">
				<h2>Account</h2>
				{signIn.status === "signed_in" && (
					<div className="stack">
						<p>Signed in with your Google account.</p>
						<div>
							<button type="button" className="btn" onClick={onSignIn}>
								Sign in again
							</button>
						</div>
					</div>
				)}
				{signIn.status === "signed_out" && (
					<div className="stack">
						<p>Not signed in.</p>
						<div>
							<button type="button" className="btn" onClick={onSignIn}>
								Sign in with Google
							</button>
						</div>
					</div>
				)}
				{signIn.status === "signing_in" && <p>Signing in with Google…</p>}
				{signIn.status === "failed" && (
					<div className="stack">
						<p>Not signed in.</p>
						<p className="error-text">Sign-in failed: {signIn.message}</p>
						<div>
							<button type="button" className="btn" onClick={onSignIn}>
								Try again
							</button>
						</div>
					</div>
				)}
			</section>

			<section className="settings-section">
				<h2>Linked accounts</h2>
				<Linking />
			</section>

			<section className="settings-section">
				<h2>Add a device by address</h2>
				<StaticPeers />
			</section>

			<section className="settings-section">
				<details>
					<summary>Advanced</summary>
					<Advanced signedIn={signIn.status === "signed_in"} />
				</details>
			</section>
		</div>
	);
}

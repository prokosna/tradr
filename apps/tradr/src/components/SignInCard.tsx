import type { SignInUiState } from "../App.js";
import { SwitchConfirm } from "./SwitchConfirm.js";

export interface SignInCardProps {
	signIn: SignInUiState;
	onSignIn: () => void;
	onConfirmSwitch: () => void;
	onCancelSwitch: () => void;
}

export function SignInCard({
	signIn,
	onSignIn,
	onConfirmSwitch,
	onCancelSwitch,
}: SignInCardProps) {
	return (
		<section className="card stack home-sign-in">
			<h2 className="card-title">Sign in to reach your devices</h2>
			<p className="muted">
				Tradr uses your Google account to recognise your own devices. Nothing is
				uploaded.
			</p>
			{signIn.status === "confirm_switch" ? (
				<SwitchConfirm
					pending={signIn}
					onConfirm={onConfirmSwitch}
					onCancel={onCancelSwitch}
				/>
			) : (
				<div>
					<button
						type="button"
						className="btn btn--primary"
						onClick={onSignIn}
						disabled={signIn.status === "signing_in"}
					>
						{signIn.status === "signing_in"
							? "Signing in…"
							: "Sign in with Google"}
					</button>
				</div>
			)}
			{signIn.status === "failed" && (
				<p className="error-text">Sign-in failed: {signIn.message}</p>
			)}
		</section>
	);
}

import type { SignInUiState } from "./App.js";

// A switch waiting for confirmation still has the previous account signed in.
export function signedInNow(signIn: SignInUiState): boolean {
	return (
		signIn.status === "signed_in" ||
		(signIn.status === "confirm_switch" && signIn.previous !== null)
	);
}

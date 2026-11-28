import { mockIPC } from "@tauri-apps/api/mocks";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { fixtureCommands } from "../preview/fixtures.js";
import { Settings } from "./Settings.js";

const noop = () => {};

function renderSignedIn(email: string | null) {
	render(
		<Settings
			signIn={{
				status: "signed_in",
				outcome: { issuer: "iss", subject: "sub", tier: "same-account", email },
			}}
			onSignIn={noop}
			onConfirmSwitch={noop}
			onCancelSwitch={noop}
			onBack={noop}
		/>,
	);
}

describe("Settings account section", () => {
	beforeEach(() => {
		mockIPC(async (cmd: string, payload?: unknown) => {
			const handler = fixtureCommands[cmd];
			return handler ? handler(payload) : null;
		});
	});

	it("names the signed-in Google account", () => {
		renderSignedIn("me@example.com");
		expect(screen.getByText("Signed in as me@example.com")).toBeDefined();
	});

	it("falls back to a generic line when the token carried no email", () => {
		renderSignedIn(null);
		expect(
			screen.getByText("Signed in with your Google account."),
		).toBeDefined();
	});
});

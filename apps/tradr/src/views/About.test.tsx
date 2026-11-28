import { mockIPC } from "@tauri-apps/api/mocks";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { About } from "./About.js";

function serve(service: unknown) {
	mockIPC(async (cmd: string) => {
		if (cmd === "plugin:app|version") {
			return "0.1.7";
		}
		if (cmd === "plugin:tradr|receive_service_status") {
			return service;
		}
		return null;
	});
}

describe("About", () => {
	it("shows the app version", async () => {
		serve(null);
		render(<About />);
		expect(await screen.findByText(/^Version 0\.1\.7 \(/)).toBeDefined();
	});

	it("says background receiving is on when the service runs", async () => {
		serve({ running: true, error: null });
		render(<About />);
		expect(
			await screen.findByText("Receiving in the background."),
		).toBeDefined();
	});

	it("names the reason Android refused the receive service", async () => {
		serve({
			running: false,
			error: "startForeground: SecurityException: denied",
		});
		render(<About />);
		expect(
			await screen.findByText(
				"Not receiving in the background. Files arrive only while Tradr is open.",
			),
		).toBeDefined();
		expect(
			screen.getByText("startForeground: SecurityException: denied"),
		).toBeDefined();
	});

	it("says nothing about background receiving on desktop", async () => {
		serve(null);
		render(<About />);
		await screen.findByText(/^Version 0\.1\.7/);
		expect(screen.queryByText(/in the background/)).toBeNull();
	});
});

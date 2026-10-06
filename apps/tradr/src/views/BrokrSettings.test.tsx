import { mockIPC } from "@tauri-apps/api/mocks";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fixtureCommands } from "../preview/fixtures.js";
import { BrokrSettings } from "./BrokrSettings.js";

describe("BrokrSettings component", () => {
	const recordedCalls: { cmd: string; payload?: unknown }[] = [];
	let customHandlers: Record<
		string,
		(payload?: unknown) => unknown | Promise<unknown>
	> = {};

	beforeEach(() => {
		recordedCalls.length = 0;
		customHandlers = {};
		window.location.hash = "";
		mockIPC(
			async (cmd: string, payload?: unknown) => {
				recordedCalls.push({ cmd, payload });
				if (customHandlers[cmd]) {
					return customHandlers[cmd](payload);
				}
				const handler = fixtureCommands[cmd];
				if (handler) {
					return handler(payload);
				}
				return null;
			},
			{ shouldMockEvents: true },
		);
	});

	afterEach(() => {
		window.location.hash = "";
	});

	it("invokes set_brokr with url and joinToken when Connect is clicked", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: false,
			url: null,
			last_pass: null,
			delivered: 0,
			last_error: null,
		});

		render(<BrokrSettings />);

		const addressInput = await screen.findByPlaceholderText(
			"http://192.168.1.50:8080",
		);
		const tokenInput = screen.getByLabelText("Join token");

		fireEvent.change(addressInput, {
			target: { value: "http://brokr.example.com:8080" },
		});
		fireEvent.change(tokenInput, { target: { value: "secret-token-xyz" } });

		const connectButton = screen.getByRole("button", { name: "Connect" });
		fireEvent.click(connectButton);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|set_brokr",
				payload: {
					url: "http://brokr.example.com:8080",
					joinToken: "secret-token-xyz",
				},
			});
		});
	});

	it("shows the address and invokes collect_brokr_now when Check now is clicked", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});

		render(<BrokrSettings />);

		await screen.findByText("http://brokr.myhome.net:8080");

		const checkNowButton = screen.getByRole("button", { name: "Check now" });
		fireEvent.click(checkNowButton);

		await waitFor(() => {
			expect(
				recordedCalls.some((c) => c.cmd === "plugin:tradr|collect_brokr_now"),
			).toBe(true);
		});
	});

	it("invokes clear_brokr when Disconnect is clicked", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});

		render(<BrokrSettings />);

		const disconnectButton = await screen.findByRole("button", {
			name: "Disconnect",
		});
		fireEvent.click(disconnectButton);

		await waitFor(() => {
			expect(
				recordedCalls.some((c) => c.cmd === "plugin:tradr|clear_brokr"),
			).toBe(true);
		});
	});
});

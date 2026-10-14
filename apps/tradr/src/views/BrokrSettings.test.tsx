import { mockIPC } from "@tauri-apps/api/mocks";
import {
	act,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
		vi.useRealTimers();
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

	it("invokes connect_brokr_link with the trimmed link and does not invoke set_brokr", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: false,
			url: null,
			last_pass: null,
			delivered: 0,
			last_error: null,
		});

		render(<BrokrSettings />);

		const linkInput = await screen.findByPlaceholderText(
			"tradr://brokr?url=...&token=...",
		);
		fireEvent.change(linkInput, {
			target: {
				value:
					"  tradr://brokr?url=http%3A%2F%2Fbrokr.local%3A8080&token=xyz  ",
			},
		});

		const connectButton = screen.getByRole("button", { name: "Connect" });
		fireEvent.click(connectButton);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|connect_brokr_link",
				payload: {
					link: "tradr://brokr?url=http%3A%2F%2Fbrokr.local%3A8080&token=xyz",
				},
			});
		});
		expect(recordedCalls.some((c) => c.cmd === "plugin:tradr|set_brokr")).toBe(
			false,
		);
	});

	it("shows rejection text when connect_brokr_link rejects", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: false,
			url: null,
			last_pass: null,
			delivered: 0,
			last_error: null,
		});
		customHandlers["plugin:tradr|connect_brokr_link"] = () => {
			throw "invalid link scheme: expected tradr://";
		};

		render(<BrokrSettings />);

		const linkInput = await screen.findByPlaceholderText(
			"tradr://brokr?url=...&token=...",
		);
		fireEvent.change(linkInput, {
			target: { value: "https://example.com" },
		});

		const connectButton = screen.getByRole("button", { name: "Connect" });
		fireEvent.click(connectButton);

		await screen.findByText("invalid link scheme: expected tradr://");
	});

	it("invokes brokr_link and shows the link, sentence and Copy, and Hide link removes the link", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});
		customHandlers["plugin:tradr|brokr_link"] = () =>
			"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok";

		render(<BrokrSettings />);

		const showButton = await screen.findByRole("button", {
			name: "Show link",
		});
		fireEvent.click(showButton);

		await screen.findByDisplayValue(
			"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok",
		);
		expect(
			screen.getByText("Anyone with this link can add a device to your Brokr."),
		).toBeDefined();
		expect(screen.getByRole("button", { name: "Copy" })).toBeDefined();
		expect(recordedCalls.some((c) => c.cmd === "plugin:tradr|brokr_link")).toBe(
			true,
		);

		const hideButton = screen.getByRole("button", { name: "Hide link" });
		fireEvent.click(hideButton);

		expect(
			screen.queryByDisplayValue(
				"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok",
			),
		).toBeNull();
		expect(
			screen.queryByText(
				"Anyone with this link can add a device to your Brokr.",
			),
		).toBeNull();
		expect(screen.getByRole("button", { name: "Show link" })).toBeDefined();
	});

	it("calls navigator.clipboard.writeText with the link and button reads Copied", async () => {
		const writeTextMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			configurable: true,
			writable: true,
		});

		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});
		customHandlers["plugin:tradr|brokr_link"] = () =>
			"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok";

		render(<BrokrSettings />);

		const showButton = await screen.findByRole("button", {
			name: "Show link",
		});
		fireEvent.click(showButton);

		const copyButton = await screen.findByRole("button", { name: "Copy" });

		vi.useFakeTimers();
		await act(async () => {
			fireEvent.click(copyButton);
		});

		expect(writeTextMock).toHaveBeenCalledWith(
			"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok",
		);
		expect(screen.getByRole("button", { name: "Copied" })).toBeDefined();

		act(() => {
			vi.advanceTimersByTime(2000);
		});
		expect(screen.getByRole("button", { name: "Copy" })).toBeDefined();
	});

	it("shows Couldn't copy text when writeText rejects", async () => {
		const writeTextMock = vi.fn().mockRejectedValue(new Error("denied"));
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			configurable: true,
			writable: true,
		});

		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});
		customHandlers["plugin:tradr|brokr_link"] = () =>
			"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok";

		render(<BrokrSettings />);

		const showButton = await screen.findByRole("button", {
			name: "Show link",
		});
		fireEvent.click(showButton);

		const copyButton = await screen.findByRole("button", { name: "Copy" });
		fireEvent.click(copyButton);

		await screen.findByText("Couldn't copy. Select the link and copy it.");
	});

	it("shows Couldn't copy text when navigator.clipboard is undefined", async () => {
		Object.defineProperty(navigator, "clipboard", {
			value: undefined,
			configurable: true,
			writable: true,
		});

		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});
		customHandlers["plugin:tradr|brokr_link"] = () =>
			"tradr://brokr?url=http%3A%2F%2Fbrokr.myhome.net%3A8080&token=test-tok";

		render(<BrokrSettings />);

		const showButton = await screen.findByRole("button", {
			name: "Show link",
		});
		fireEvent.click(showButton);

		const copyButton = await screen.findByRole("button", { name: "Copy" });
		fireEvent.click(copyButton);

		await screen.findByText("Couldn't copy. Select the link and copy it.");
	});

	it("shows error text and no read-only field when brokr_link rejects", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.myhome.net:8080",
			last_pass: 1727654400,
			delivered: 2,
			last_error: null,
		});
		customHandlers["plugin:tradr|brokr_link"] = () => {
			throw "could not read join token";
		};

		render(<BrokrSettings />);

		const showButton = await screen.findByRole("button", {
			name: "Show link",
		});
		fireEvent.click(showButton);

		await screen.findByText("could not read join token");
		expect(screen.queryByRole("textbox", { name: "Brokr link" })).toBeNull();
	});
});

import { StrictMode } from "react";
import { emit } from "@tauri-apps/api/event";
import { mockIPC } from "@tauri-apps/api/mocks";
import {
	act,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { App } from "./App.js";
import { fixtureCommands, fixtureKnownDevices } from "./preview/fixtures.js";
import type { ShareIntent, SharedFilePayload } from "./types.js";

describe("App component", () => {
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

	it("sets location.hash to the peer folder without invoking send_files when tapped with no waiting files", async () => {
		render(<App />);

		const pixelTile = await screen.findByText("Pixel 8");
		fireEvent.click(pixelTile);

		expect(window.location.hash).toBe("#/folder/dev-pixel-8");
		const sendCalls = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCalls).toHaveLength(0);
	});

	it("sends staged files when a device tile is tapped and displays Sent ✓ on resolution", async () => {
		render(<App />);
		await screen.findByText("Pixel 8");

		const stagedFiles: SharedFilePayload[] = [
			{
				name: "photo.jpg",
				size: 1024,
				cachePath: "/tmp/photo.jpg",
				adoptedId: null,
			},
			{
				name: "doc.pdf",
				size: 2048,
				cachePath: "/tmp/doc.pdf",
				adoptedId: null,
			},
		];

		const intent: ShareIntent = {
			action: "send",
			mimeType: null,
			extraText: null,
			targetDevice: null,
			transferId: null,
			files: stagedFiles,
		};

		await act(async () => {
			await emit("share-intent", intent);
		});

		expect(screen.getByRole("heading", { name: "Send to" })).toBeDefined();

		const pixelTile = screen.getByText("Pixel 8");
		fireEvent.click(pixelTile);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|send_files",
				payload: {
					peerId: "dev-pixel-8",
					files: ["/tmp/photo.jpg", "/tmp/doc.pdf"],
					adoptedIds: [],
				},
			});
		});

		await screen.findByText("Sent ✓");
		expect(screen.getByRole("button", { name: "Select files" })).toBeDefined();
	});

	it("displays Waiting… on a second device tile when queued behind an active send", async () => {
		let resolveFirstSend!: (paths: string[]) => void;
		const firstSendPromise = new Promise<string[]>((resolve) => {
			resolveFirstSend = resolve;
		});

		customHandlers["plugin:tradr|send_files"] = () => {
			return firstSendPromise;
		};

		render(<App />);
		await screen.findByText("Pixel 8");
		await screen.findByText("ThinkPad");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "first.txt",
						size: 100,
						cachePath: "/tmp/first.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Pixel 8"));

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "second.txt",
						size: 200,
						cachePath: "/tmp/second.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("ThinkPad"));

		expect(screen.getByText("Waiting…")).toBeDefined();

		await act(async () => {
			resolveFirstSend(["/tmp/first.txt"]);
		});
	});

	it("preserves waiting files and displays failure notice when send rejects", async () => {
		customHandlers["plugin:tradr|send_files"] = () => {
			return Promise.reject("Transfer timeout");
		};

		render(<App />);
		await screen.findByText("Pixel 8");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "important-document.pdf",
						size: 4096,
						cachePath: "/tmp/important-document.pdf",
						adoptedId: null,
					},
				],
			});
		});

		expect(screen.getByText("important-document.pdf")).toBeDefined();

		fireEvent.click(screen.getByText("Pixel 8"));

		await screen.findByText("Couldn't send to Pixel 8.");
		expect(screen.getByText("important-document.pdf")).toBeDefined();
		expect(screen.getByRole("heading", { name: "Send to" })).toBeDefined();
	});

	it("records incoming transfers newest first with sender label and enforces 50 item cap", async () => {
		const { container } = render(<App />);
		await screen.findByText("Pixel 8");

		await act(async () => {
			await emit("files-received", {
				device_id: "dev-pixel-8",
				files: ["first.pdf", "second.png"],
			});
		});

		await screen.findByText("first.pdf");
		expect(screen.getByText("second.png")).toBeDefined();

		const initialRows = container.querySelectorAll(".home-received .file-row");
		expect(initialRows).toHaveLength(2);
		expect(initialRows[0]?.textContent).toContain("from Pixel 8");
		expect(initialRows[1]?.textContent).toContain("from Pixel 8");

		await act(async () => {
			await emit("files-received", {
				device_id: "unknown-device-id",
				files: ["newest.txt"],
			});
		});

		await screen.findByText("newest.txt");
		const updatedRows = container.querySelectorAll(".home-received .file-row");
		expect(updatedRows).toHaveLength(3);
		expect(updatedRows[0]?.textContent).toContain("newest.txt");
		expect(updatedRows[0]?.textContent).toContain("from another device");

		const sixtyFiles = Array.from(
			{ length: 60 },
			(_, i) => `overflow-${i}.dat`,
		);
		await act(async () => {
			await emit("files-received", {
				device_id: "dev-pixel-8",
				files: sixtyFiles,
			});
		});

		await waitFor(() => {
			const cappedRows = container.querySelectorAll(".home-received .file-row");
			expect(cappedRows).toHaveLength(50);
		});
	});

	it("dispatches each queued send exactly once sequentially across different peers", async () => {
		let resolveFirstSend!: (paths: string[]) => void;
		const firstSendPromise = new Promise<string[]>((resolve) => {
			resolveFirstSend = resolve;
		});
		let resolveSecondSend!: (paths: string[]) => void;
		const secondSendPromise = new Promise<string[]>((resolve) => {
			resolveSecondSend = resolve;
		});

		let sendFilesCallCount = 0;
		customHandlers["plugin:tradr|send_files"] = () => {
			sendFilesCallCount++;
			if (sendFilesCallCount === 1) {
				return firstSendPromise;
			}
			return secondSendPromise;
		};

		render(<App />);
		await screen.findByText("Pixel 8");
		await screen.findByText("ThinkPad");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "first.txt",
						size: 100,
						cachePath: "/tmp/first.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Pixel 8"));

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "second.txt",
						size: 200,
						cachePath: "/tmp/second.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("ThinkPad"));

		const sendCallsBeforeResolve = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsBeforeResolve).toHaveLength(1);
		expect(sendCallsBeforeResolve[0]?.payload).toMatchObject({
			peerId: "dev-pixel-8",
		});
		expect(screen.getByText("Waiting…")).toBeDefined();

		await act(async () => {
			resolveFirstSend(["/tmp/first.txt"]);
		});

		await waitFor(() => {
			const sendCallsAfterFirst = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|send_files",
			);
			expect(sendCallsAfterFirst).toHaveLength(2);
		});

		const sendCallsAfterFirst = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsAfterFirst[1]?.payload).toMatchObject({
			peerId: "dev-thinkpad",
		});

		await act(async () => {
			resolveSecondSend(["/tmp/second.txt"]);
		});

		const sendCallsAfterSecond = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsAfterSecond).toHaveLength(2);
	});

	it("dispatches each queued send exactly once sequentially under StrictMode", async () => {
		let resolveFirstSend!: (paths: string[]) => void;
		const firstSendPromise = new Promise<string[]>((resolve) => {
			resolveFirstSend = resolve;
		});
		let resolveSecondSend!: (paths: string[]) => void;
		const secondSendPromise = new Promise<string[]>((resolve) => {
			resolveSecondSend = resolve;
		});

		let sendFilesCallCount = 0;
		customHandlers["plugin:tradr|send_files"] = () => {
			sendFilesCallCount++;
			if (sendFilesCallCount === 1) {
				return firstSendPromise;
			}
			return secondSendPromise;
		};

		render(
			<StrictMode>
				<App />
			</StrictMode>,
		);
		await screen.findByText("Pixel 8");
		await screen.findByText("ThinkPad");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "first.txt",
						size: 100,
						cachePath: "/tmp/first.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Pixel 8"));

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "second.txt",
						size: 200,
						cachePath: "/tmp/second.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("ThinkPad"));

		const sendCallsBeforeResolve = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsBeforeResolve).toHaveLength(1);
		expect(sendCallsBeforeResolve[0]?.payload).toMatchObject({
			peerId: "dev-pixel-8",
		});
		expect(screen.getByText("Waiting…")).toBeDefined();

		await act(async () => {
			resolveFirstSend(["/tmp/first.txt"]);
		});

		await waitFor(() => {
			const sendCallsAfterFirst = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|send_files",
			);
			expect(sendCallsAfterFirst).toHaveLength(2);
		});

		const sendCallsAfterFirst = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsAfterFirst[1]?.payload).toMatchObject({
			peerId: "dev-thinkpad",
		});

		await act(async () => {
			resolveSecondSend(["/tmp/second.txt"]);
		});

		const sendCallsAfterSecond = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsAfterSecond).toHaveLength(2);
	});

	it("queues a second send to the same device after the first rather than dispatching both at once", async () => {
		let resolveFirstSend!: (paths: string[]) => void;
		const firstSendPromise = new Promise<string[]>((resolve) => {
			resolveFirstSend = resolve;
		});
		let resolveSecondSend!: (paths: string[]) => void;
		const secondSendPromise = new Promise<string[]>((resolve) => {
			resolveSecondSend = resolve;
		});

		let sendFilesCallCount = 0;
		customHandlers["plugin:tradr|send_files"] = () => {
			sendFilesCallCount++;
			if (sendFilesCallCount === 1) {
				return firstSendPromise;
			}
			return secondSendPromise;
		};

		render(<App />);
		await screen.findByText("Pixel 8");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "first.txt",
						size: 100,
						cachePath: "/tmp/first.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Pixel 8"));

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "second.txt",
						size: 200,
						cachePath: "/tmp/second.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Pixel 8"));

		const sendCallsBeforeResolve = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsBeforeResolve).toHaveLength(1);
		expect(sendCallsBeforeResolve[0]?.payload).toMatchObject({
			peerId: "dev-pixel-8",
			files: ["/tmp/first.txt"],
		});

		await act(async () => {
			resolveFirstSend(["/tmp/first.txt"]);
		});

		await waitFor(() => {
			const sendCallsAfterFirst = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|send_files",
			);
			expect(sendCallsAfterFirst).toHaveLength(2);
		});

		const sendCallsAfterFirst = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsAfterFirst[1]?.payload).toMatchObject({
			peerId: "dev-pixel-8",
			files: ["/tmp/second.txt"],
		});

		await act(async () => {
			resolveSecondSend(["/tmp/second.txt"]);
		});

		const sendCallsAfterSecond = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|send_files",
		);
		expect(sendCallsAfterSecond).toHaveLength(2);
	});

	it("lists a known device absent from peers as offline without Open folder button", async () => {
		customHandlers["plugin:tradr|list_known_devices"] = () => [
			...fixtureKnownDevices,
			{
				device_id: "dev-offline-tablet",
				display_name: "Offline Tablet",
				tier: "same-account",
				last_seen: 1727000000,
			},
		];

		const { container } = render(<App />);
		await screen.findByText("Offline Tablet");

		expect(
			screen.getByText("offline · set up delivery in Settings to send later"),
		).toBeDefined();

		const tabletTile = container.querySelector(
			'[data-device-key="dev-offline-tablet"]',
		);
		expect(tabletTile).not.toBeNull();
		expect(tabletTile?.textContent).toContain("Offline Tablet");
		expect(tabletTile?.querySelector("button")).toBeNull();
	});

	it("renders a known device that is also a peer only once as reachable", async () => {
		customHandlers["plugin:tradr|list_known_devices"] = () => [
			{
				device_id: "dev-pixel-8",
				display_name: "Pixel 8",
				tier: "same-account",
				last_seen: 1727654400,
			},
		];

		const { container } = render(<App />);
		await screen.findByText("Pixel 8");

		const pixelTiles = container.querySelectorAll(
			'[data-device-key="dev-pixel-8"]',
		);
		expect(pixelTiles).toHaveLength(1);
		expect(pixelTiles[0]?.textContent).toContain("Open folder");
	});

	it("invokes send_deferred with deviceId and staged paths exactly once and re-lists deliveries when offline tile is tapped with configured Brokr", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.local:8080",
			last_pass: 1727654400,
			delivered: 0,
			last_error: null,
		});
		customHandlers["plugin:tradr|list_known_devices"] = () => [
			...fixtureKnownDevices,
			{
				device_id: "dev-offline-tablet",
				display_name: "Offline Tablet",
				tier: "same-account",
				last_seen: 1727000000,
			},
		];

		render(<App />);
		await screen.findByText("Offline Tablet");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "offline-notes.txt",
						size: 512,
						cachePath: "/tmp/offline-notes.txt",
						adoptedId: null,
					},
				],
			});
		});

		await screen.findByText("Send later →");

		const initialListDeliveriesCalls = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|list_deliveries",
		).length;

		fireEvent.click(screen.getByText("Offline Tablet"));

		await waitFor(() => {
			const deferredCalls = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|send_deferred",
			);
			expect(deferredCalls).toHaveLength(1);
			expect(deferredCalls[0]?.payload).toMatchObject({
				deviceId: "dev-offline-tablet",
				files: ["/tmp/offline-notes.txt"],
				adoptedIds: [],
			});
		});

		await screen.findByText("Will deliver when it's back ✓");

		await waitFor(() => {
			const afterListDeliveriesCalls = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|list_deliveries",
			).length;
			expect(afterListDeliveriesCalls).toBeGreaterThan(
				initialListDeliveriesCalls,
			);
		});
	});

	it("invokes neither send_files nor send_deferred when offline tile is tapped without configured Brokr", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: false,
			url: null,
			last_pass: null,
			delivered: 0,
			last_error: null,
		});
		customHandlers["plugin:tradr|list_known_devices"] = () => [
			...fixtureKnownDevices,
			{
				device_id: "dev-offline-tablet",
				display_name: "Offline Tablet",
				tier: "same-account",
				last_seen: 1727000000,
			},
		];

		render(<App />);
		await screen.findByText("Offline Tablet");

		await act(async () => {
			await emit("share-intent", {
				action: "send",
				mimeType: null,
				extraText: null,
				targetDevice: null,
				transferId: null,
				files: [
					{
						name: "doc.txt",
						size: 100,
						cachePath: "/tmp/doc.txt",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Offline Tablet"));

		const sendCalls = recordedCalls.filter(
			(c) =>
				c.cmd === "plugin:tradr|send_files" ||
				c.cmd === "plugin:tradr|send_deferred",
		);
		expect(sendCalls).toHaveLength(0);
	});

	it("renders waiting, delivered, and expired rows when deliveries are present and remains absent when empty", async () => {
		customHandlers["plugin:tradr|list_deliveries"] = () => [];

		const { unmount } = render(<App />);
		await screen.findByText("Pixel 8");

		expect(
			screen.queryByRole("heading", { name: "Waiting to deliver" }),
		).toBeNull();

		unmount();

		customHandlers["plugin:tradr|list_deliveries"] = () => [
			{
				id: "deliv-1",
				recipient_device_id: "dev-tablet",
				recipient_name: "Personal Tablet",
				names: ["report.pdf", "appendix.pdf"],
				sent_at: 1727650000,
				state: "waiting",
				collected_at: null,
			},
			{
				id: "deliv-2",
				recipient_device_id: "dev-laptop",
				recipient_name: "Home Laptop",
				names: ["photos.zip"],
				sent_at: 1727640000,
				state: "delivered",
				collected_at: 1727643600000,
			},
			{
				id: "deliv-3",
				recipient_device_id: "dev-old",
				recipient_name: null,
				names: ["old-doc.txt"],
				sent_at: 1727000000,
				state: "expired",
				collected_at: null,
			},
		];

		render(<App />);

		await screen.findByRole("heading", { name: "Waiting to deliver" });
		expect(screen.getByText("report.pdf +1 more")).toBeDefined();
		expect(screen.getByText(/to Personal Tablet · Waiting/)).toBeDefined();
		expect(screen.getByText("photos.zip")).toBeDefined();
		expect(screen.getByText(/to Home Laptop · Delivered/)).toBeDefined();
		expect(screen.getByText("old-doc.txt")).toBeDefined();
		expect(screen.getByText(/to a device · Expired/)).toBeDefined();
	});

	it("invokes collect_brokr_now on visibilitychange to visible only when Brokr is configured", async () => {
		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: false,
			url: null,
			last_pass: null,
			delivered: 0,
			last_error: null,
		});

		render(<App />);
		await screen.findByText("Pixel 8");

		Object.defineProperty(document, "visibilityState", {
			configurable: true,
			value: "visible",
		});
		fireEvent(document, new Event("visibilitychange"));

		const collectCallsUnconfigured = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|collect_brokr_now",
		);
		expect(collectCallsUnconfigured).toHaveLength(0);

		customHandlers["plugin:tradr|brokr_status"] = () => ({
			configured: true,
			url: "http://brokr.local:8080",
			last_pass: 1727654400,
			delivered: 1,
			last_error: null,
		});

		render(<App />);
		await screen.findByText("Pixel 8");

		fireEvent(document, new Event("visibilitychange"));

		await waitFor(() => {
			const collectCallsConfigured = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|collect_brokr_now",
			);
			expect(collectCallsConfigured).toHaveLength(1);
		});
	});
});

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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App.js";
import {
	fixtureCommands,
	fixtureKnownDevices,
	resetFixtureReceived,
} from "./preview/fixtures.js";
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
		resetFixtureReceived();
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

	it("shows Preparing on tile and card during preparing progress and turns back to Sending on transferring", async () => {
		let resolveSend!: (paths: string[]) => void;
		const sendPromise = new Promise<string[]>((resolve) => {
			resolveSend = resolve;
		});

		customHandlers["plugin:tradr|send_files"] = () => {
			return sendPromise;
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
						name: "photo.jpg",
						size: 4,
						cachePath: "/tmp/photo.jpg",
						adoptedId: null,
					},
				],
			});
		});

		fireEvent.click(screen.getByText("Pixel 8"));

		await act(async () => {
			await emit("transfer-progress", {
				transfer_id: "tx-test-1",
				item_id: "item-1",
				rel_path: "photo.jpg",
				bytes_transferred: 1,
				total_bytes: 4,
				status: "preparing",
			});
		});

		expect(screen.getByText("Preparing photo.jpg · 25%")).toBeDefined();
		expect(screen.getByText("Preparing to send to Pixel 8…")).toBeDefined();
		expect(screen.queryByText(/Sending/)).toBeNull();

		await act(async () => {
			await emit("transfer-progress", {
				transfer_id: "tx-test-1",
				item_id: "item-1",
				rel_path: "photo.jpg",
				bytes_transferred: 2,
				total_bytes: 4,
				status: "transferring",
			});
		});

		expect(screen.getByText("Sending photo.jpg · 50%")).toBeDefined();
		expect(screen.getByText("Sending to Pixel 8…")).toBeDefined();

		await act(async () => {
			resolveSend(["/tmp/photo.jpg"]);
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

	it("lists rows answered at mount in the order answered with sender name from device_name", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		customHandlers["plugin:tradr|received_history"] = () => [
			{
				id: 1,
				path: "first.pdf",
				device_id: "dev-pixel-8",
				device_name: "Pixel 8",
				received_at: nowSecs,
				how: "sent",
			},
			{
				id: 2,
				path: "second.png",
				device_id: "dev-thinkpad",
				device_name: "ThinkPad Device",
				received_at: nowSecs,
				how: "sent",
			},
		];

		const { container } = render(<App />);
		await screen.findByText("first.pdf");
		expect(screen.getByText("second.png")).toBeDefined();

		expect(
			recordedCalls.some((c) => c.cmd === "plugin:tradr|received_history"),
		).toBe(true);

		const rows = container.querySelectorAll(".home-received .file-row");
		expect(rows).toHaveLength(2);
		expect(rows[0]?.textContent).toContain("first.pdf");
		expect(rows[0]?.textContent).toContain("from Pixel 8");
		expect(rows[1]?.textContent).toContain("second.png");
		expect(rows[1]?.textContent).toContain("from ThinkPad Device");
	});

	it("shows device list name when device_name is null or from another device for unknown device_id", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		customHandlers["plugin:tradr|received_history"] = () => [
			{
				id: 1,
				path: "known-peer.txt",
				device_id: "dev-thinkpad",
				device_name: null,
				received_at: nowSecs,
				how: "sent",
			},
			{
				id: 2,
				path: "unknown-peer.txt",
				device_id: "dev-unknown-404",
				device_name: null,
				received_at: nowSecs,
				how: "sent",
			},
		];

		const { container } = render(<App />);
		await screen.findByText("known-peer.txt");
		expect(screen.getByText("unknown-peer.txt")).toBeDefined();

		expect(
			recordedCalls.some((c) => c.cmd === "plugin:tradr|received_history"),
		).toBe(true);

		const rows = container.querySelectorAll(".home-received .file-row");
		expect(rows).toHaveLength(2);
		expect(rows[0]?.textContent).toContain("from ThinkPad");
		expect(rows[1]?.textContent).toContain("from another device");
	});

	it("reads downloaded from for downloaded row", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		customHandlers["plugin:tradr|received_history"] = () => [
			{
				id: 1,
				path: "fetched-archive.zip",
				device_id: "dev-pixel-8",
				device_name: "Pixel 8",
				received_at: nowSecs,
				how: "downloaded",
			},
		];

		const { container } = render(<App />);
		await screen.findByText("fetched-archive.zip");

		expect(
			recordedCalls.some((c) => c.cmd === "plugin:tradr|received_history"),
		).toBe(true);

		const row = container.querySelector(".home-received .file-row");
		expect(row?.textContent).toContain("downloaded from Pixel 8");
	});

	it("shows time for row received now and date for row received three days ago", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		const threeDaysAgoSecs = nowSecs - 3 * 86400;

		const expectedTime = new Date(nowSecs * 1000).toLocaleTimeString([], {
			hour: "numeric",
			minute: "2-digit",
		});
		const expectedDate = new Date(threeDaysAgoSecs * 1000).toLocaleDateString();

		customHandlers["plugin:tradr|received_history"] = () => [
			{
				id: 1,
				path: "today-file.pdf",
				device_id: "dev-pixel-8",
				device_name: "Pixel 8",
				received_at: nowSecs,
				how: "sent",
			},
			{
				id: 2,
				path: "past-file.pdf",
				device_id: "dev-pixel-8",
				device_name: "Pixel 8",
				received_at: threeDaysAgoSecs,
				how: "sent",
			},
		];

		const { container } = render(<App />);
		await screen.findByText("today-file.pdf");

		expect(
			recordedCalls.some((c) => c.cmd === "plugin:tradr|received_history"),
		).toBe(true);

		const rows = container.querySelectorAll(".home-received .file-row");
		expect(rows).toHaveLength(2);
		expect(rows[0]?.textContent).toContain(expectedTime);
		expect(rows[1]?.textContent).toContain(expectedDate);
	});

	it("causes a second received_history invocation on files-received event and renders newly answered row", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		let callCount = 0;
		customHandlers["plugin:tradr|received_history"] = () => {
			callCount++;
			if (callCount === 1) {
				return [
					{
						id: 1,
						path: "initial.txt",
						device_id: "dev-pixel-8",
						device_name: "Pixel 8",
						received_at: nowSecs,
						how: "sent",
					},
				];
			}
			return [
				{
					id: 2,
					path: "new-arrival.txt",
					device_id: "dev-pixel-8",
					device_name: "Pixel 8",
					received_at: nowSecs,
					how: "sent",
				},
				{
					id: 1,
					path: "initial.txt",
					device_id: "dev-pixel-8",
					device_name: "Pixel 8",
					received_at: nowSecs,
					how: "sent",
				},
			];
		};

		render(<App />);
		await screen.findByText("initial.txt");

		const initialCalls = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|received_history",
		).length;
		expect(initialCalls).toBe(1);

		await act(async () => {
			await emit("files-received", {
				device_id: "ignored-id",
				files: ["ignored-path.txt"],
			});
		});

		await screen.findByText("new-arrival.txt");
		const secondCalls = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|received_history",
		).length;
		expect(secondCalls).toBe(2);
	});

	it("shows fifty of sixty rows and Show all (60), then shows sixty rows on click", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		const sixtyRows = Array.from({ length: 60 }, (_, i) => ({
			id: i + 1,
			path: `overflow-${i}.dat`,
			device_id: "dev-pixel-8",
			device_name: "Pixel 8",
			received_at: nowSecs - i,
			how: "sent" as const,
		}));

		customHandlers["plugin:tradr|received_history"] = () => sixtyRows;

		const { container } = render(<App />);
		await screen.findByText("overflow-0.dat");

		expect(
			recordedCalls.some((c) => c.cmd === "plugin:tradr|received_history"),
		).toBe(true);

		const initialRows = container.querySelectorAll(".home-received .file-row");
		expect(initialRows).toHaveLength(50);

		const showAllBtn = screen.getByRole("button", { name: "Show all (60)" });
		expect(showAllBtn).toBeDefined();

		fireEvent.click(showAllBtn);

		const expandedRows = container.querySelectorAll(".home-received .file-row");
		expect(expandedRows).toHaveLength(60);
		expect(screen.queryByRole("button", { name: /Show all/ })).toBeNull();
	});

	it("asks before clearing, does nothing on Cancel, and clears on confirm", async () => {
		let rows = [
			{
				id: 1,
				path: "doc.pdf",
				device_id: "dev-pixel-8",
				device_name: "Pixel 8",
				received_at: Math.floor(Date.now() / 1000),
				how: "sent" as const,
			},
		];
		customHandlers["plugin:tradr|received_history"] = () => rows;
		customHandlers["plugin:tradr|clear_received_history"] = () => {
			rows = [];
			return null;
		};

		const { container } = render(<App />);
		await screen.findByText("doc.pdf");

		const clearGhostBtn = screen.getByRole("button", { name: "Clear" });
		fireEvent.click(clearGhostBtn);

		expect(
			screen.getByText("Clear this list? The files stay where they are."),
		).toBeDefined();
		const cancelBtn = screen.getByRole("button", { name: "Cancel" });
		fireEvent.click(cancelBtn);

		expect(
			recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|clear_received_history",
			),
		).toHaveLength(0);
		expect(screen.getByRole("button", { name: "Clear" })).toBeDefined();
		expect(
			screen.queryByText("Clear this list? The files stay where they are."),
		).toBeNull();

		fireEvent.click(screen.getByRole("button", { name: "Clear" }));
		const confirmClearBtn = screen.getByRole("button", { name: "Clear" });
		fireEvent.click(confirmClearBtn);

		await screen.findByText("Files sent to this device appear here.");
		expect(
			recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|clear_received_history",
			),
		).toHaveLength(1);
		const remainingRows = container.querySelectorAll(
			".home-received .file-row",
		);
		expect(remainingRows).toHaveLength(0);
		expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
	});

	it("shows load error sentence on rejected received_history and still offers Clear", async () => {
		customHandlers["plugin:tradr|received_history"] = () =>
			Promise.reject("disk error");

		render(<App />);

		const errorMsg = await screen.findByText(
			"Couldn't read the list of received files: disk error",
		);
		expect(errorMsg.className).toContain("error-text");
		expect(screen.getByRole("button", { name: "Clear" })).toBeDefined();
		expect(
			recordedCalls.some((c) => c.cmd === "plugin:tradr|received_history"),
		).toBe(true);
	});

	it("shows error sentence on rejected clear_received_history", async () => {
		const nowSecs = Math.floor(Date.now() / 1000);
		customHandlers["plugin:tradr|received_history"] = () => [
			{
				id: 1,
				path: "locked.pdf",
				device_id: "dev-pixel-8",
				device_name: "Pixel 8",
				received_at: nowSecs,
				how: "sent",
			},
		];
		customHandlers["plugin:tradr|clear_received_history"] = () =>
			Promise.reject("io error");

		render(<App />);
		await screen.findByText("locked.pdf");

		fireEvent.click(screen.getByRole("button", { name: "Clear" }));
		fireEvent.click(screen.getByRole("button", { name: "Clear" }));

		const errorMsg = await screen.findByText(
			"Couldn't clear the list: io error",
		);
		expect(errorMsg.className).toContain("error-text");
		expect(
			recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|clear_received_history",
			),
		).toHaveLength(1);
	});

	it("shows Open and Show in folder with ['open', 'reveal'], Open and Share with ['open', 'share'], and no buttons with []", async () => {
		customHandlers["plugin:tradr|received_actions"] = () => ["open", "reveal"];
		const { container, unmount } = render(<App />);
		await screen.findByText("report-2026.pdf");

		const rowsA = container.querySelectorAll(".home-received .file-row");
		expect(rowsA).toHaveLength(2);
		for (const row of rowsA) {
			const buttons = Array.from(row.querySelectorAll("button")).map(
				(b) => b.textContent,
			);
			expect(buttons).toEqual(["Open", "Show in folder"]);
		}
		unmount();

		customHandlers["plugin:tradr|received_actions"] = () => ["open", "share"];
		const { container: containerB, unmount: unmountB } = render(<App />);
		await screen.findByText("report-2026.pdf");

		const rowsB = containerB.querySelectorAll(".home-received .file-row");
		expect(rowsB).toHaveLength(2);
		for (const row of rowsB) {
			const buttons = Array.from(row.querySelectorAll("button")).map(
				(b) => b.textContent,
			);
			expect(buttons).toEqual(["Open", "Share"]);
		}
		unmountB();

		customHandlers["plugin:tradr|received_actions"] = () => [];
		const { container: containerC } = render(<App />);
		await screen.findByText("report-2026.pdf");

		const rowsC = containerC.querySelectorAll(".home-received .file-row");
		expect(rowsC).toHaveLength(2);
		for (const row of rowsC) {
			expect(row.querySelectorAll("button")).toHaveLength(0);
		}
	});

	it("pressing Open on the second of two rows invokes open_received once with that row's id, and nothing for the other row", async () => {
		render(<App />);
		await screen.findByText("report-2026.pdf");

		const openSecondBtn = screen.getByRole("button", {
			name: "Open family-photo.jpg",
		});
		fireEvent.click(openSecondBtn);

		await waitFor(() => {
			const openCalls = recordedCalls.filter(
				(c) => c.cmd === "plugin:tradr|open_received",
			);
			expect(openCalls).toEqual([
				{
					cmd: "plugin:tradr|open_received",
					payload: { id: 2 },
				},
			]);
		});
	});

	it("pressing Show in folder invokes reveal_received, and Share invokes share_received, each with the row's id", async () => {
		customHandlers["plugin:tradr|received_actions"] = () => ["reveal", "share"];
		render(<App />);
		await screen.findByText("report-2026.pdf");

		const revealBtn = screen.getByRole("button", {
			name: "Show in folder report-2026.pdf",
		});
		fireEvent.click(revealBtn);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|reveal_received",
				payload: { id: 1 },
			});
		});

		const shareBtn = screen.getByRole("button", {
			name: "Share report-2026.pdf",
		});
		fireEvent.click(shareBtn);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|share_received",
				payload: { id: 1 },
			});
		});
	});

	it("a rejected open_received shows its text under that row and not under the other row, and pressing Open again clears it while pending", async () => {
		customHandlers["plugin:tradr|open_received"] = () =>
			Promise.reject("This file is no longer where it was saved.");

		const { container } = render(<App />);
		await screen.findByText("report-2026.pdf");

		const openBtnRow1 = screen.getByRole("button", {
			name: "Open report-2026.pdf",
		});
		fireEvent.click(openBtnRow1);

		const errorText = await screen.findByText(
			"This file is no longer where it was saved.",
		);
		expect(errorText.className).toContain("error-text");

		const rows = container.querySelectorAll(".home-received .file-row");
		expect(rows).toHaveLength(2);
		expect(rows[0]?.textContent).toContain(
			"This file is no longer where it was saved.",
		);
		expect(rows[1]?.textContent).not.toContain(
			"This file is no longer where it was saved.",
		);

		let resolveSecondOpen!: () => void;
		const secondOpenPromise = new Promise<void>((resolve) => {
			resolveSecondOpen = resolve;
		});
		customHandlers["plugin:tradr|open_received"] = () => secondOpenPromise;

		fireEvent.click(openBtnRow1);

		expect(
			screen.queryByText("This file is no longer where it was saved."),
		).toBeNull();
		expect((openBtnRow1 as HTMLButtonElement).disabled).toBe(true);

		const revealBtnRow1 = screen.getByRole("button", {
			name: "Show in folder report-2026.pdf",
		});
		expect((revealBtnRow1 as HTMLButtonElement).disabled).toBe(true);

		const openBtnRow2 = screen.getByRole("button", {
			name: "Open family-photo.jpg",
		});
		expect((openBtnRow2 as HTMLButtonElement).disabled).toBe(false);

		await act(async () => {
			resolveSecondOpen();
		});

		expect((openBtnRow1 as HTMLButtonElement).disabled).toBe(false);
	});

	it("renders the rows with no buttons when received_actions rejects", async () => {
		customHandlers["plugin:tradr|received_actions"] = () =>
			Promise.reject("actions unavailable");

		const { container } = render(<App />);
		await screen.findByText("report-2026.pdf");

		const errorLine = await screen.findByText(
			"Couldn't find what this device can do with a file: actions unavailable",
		);
		expect(errorLine.className).toContain("error-text");

		const rows = container.querySelectorAll(".home-received .file-row");
		expect(rows).toHaveLength(2);
		expect(rows[0]?.querySelectorAll("button")).toHaveLength(0);
		expect(rows[1]?.querySelectorAll("button")).toHaveLength(0);
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

	it("does not give the offline tile the dimmed class, whose pointer-events: none would swallow the tap", async () => {
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

		const { container } = render(<App />);
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

		const tabletTile = container.querySelector(
			'[data-device-key="dev-offline-tablet"]',
		);
		expect(tabletTile).not.toBeNull();
		expect(tabletTile?.classList.contains("dimmed")).toBe(false);
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

	it("renders the default fixture receive folder on the Received card", async () => {
		render(<App />);

		expect(
			await screen.findByText("Saved in /home/haruka/Downloads"),
		).toBeDefined();
	});

	it("renders custom receive folder when resolved", async () => {
		customHandlers["plugin:tradr|receive_folder"] = () =>
			"/storage/emulated/0/Download";

		render(<App />);

		expect(
			await screen.findByText("Saved in /storage/emulated/0/Download"),
		).toBeDefined();
	});

	it("renders error notice when receive_folder rejects", async () => {
		customHandlers["plugin:tradr|receive_folder"] = () =>
			Promise.reject("no folder");

		render(<App />);

		expect(
			await screen.findByText("Couldn't find where files are saved: no folder"),
		).toBeDefined();
	});

	it("renders no Saved in text when receive_folder resolves null", async () => {
		customHandlers["plugin:tradr|receive_folder"] = () => null;

		render(<App />);

		await screen.findByRole("heading", { name: "Received" });
		await waitFor(() => {
			expect(
				recordedCalls.some((c) => c.cmd === "plugin:tradr|receive_folder"),
			).toBe(true);
			expect(screen.queryByText(/^Saved in/)).toBeNull();
		});
	});

	it("records exactly one refresh_peers call and shows disabled Checking… when Refresh is pressed", async () => {
		render(<App />);
		await screen.findByText("Pixel 8");

		const refreshBtn = screen.getByRole("button", { name: "Refresh" });

		vi.useFakeTimers();
		await act(async () => {
			fireEvent.click(refreshBtn);
		});

		const refreshCalls = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|refresh_peers",
		);
		expect(refreshCalls).toHaveLength(1);

		const checkingBtn = screen.getByRole("button", { name: "Checking…" });
		expect(checkingBtn).toBeDefined();
		expect((checkingBtn as HTMLButtonElement).disabled).toBe(true);
	});

	it("reads Refresh and is enabled after ten seconds, remaining disabled at nine seconds", async () => {
		render(<App />);
		await screen.findByText("Pixel 8");

		const refreshBtn = screen.getByRole("button", { name: "Refresh" });

		vi.useFakeTimers();
		await act(async () => {
			fireEvent.click(refreshBtn);
		});

		const checkingBtn = screen.getByRole("button", { name: "Checking…" });
		expect((checkingBtn as HTMLButtonElement).disabled).toBe(true);

		act(() => {
			vi.advanceTimersByTime(9000);
		});
		expect(screen.getByRole("button", { name: "Checking…" })).toBeDefined();
		expect(
			(screen.getByRole("button", { name: "Checking…" }) as HTMLButtonElement)
				.disabled,
		).toBe(true);

		act(() => {
			vi.advanceTimersByTime(1000);
		});
		const enabledBtn = screen.getByRole("button", { name: "Refresh" });
		expect(enabledBtn).toBeDefined();
		expect((enabledBtn as HTMLButtonElement).disabled).toBe(false);
	});

	it("shows Couldn't check your devices. and keeps button enabled when refresh_peers rejects", async () => {
		customHandlers["plugin:tradr|refresh_peers"] = () =>
			Promise.reject("check failure");

		render(<App />);
		await screen.findByText("Pixel 8");

		const refreshBtn = screen.getByRole("button", { name: "Refresh" });

		await act(async () => {
			fireEvent.click(refreshBtn);
		});

		const errorMsg = await screen.findByText("Couldn't check your devices.");
		expect(errorMsg.className).toContain("error-text");
		expect(screen.getByText("check failure")).toBeDefined();

		const enabledBtn = screen.getByRole("button", { name: "Refresh" });
		expect(enabledBtn).toBeDefined();
		expect((enabledBtn as HTMLButtonElement).disabled).toBe(false);

		customHandlers["plugin:tradr|refresh_peers"] = () => 1;
		await act(async () => {
			fireEvent.click(enabledBtn);
		});
		expect(screen.queryByText("Couldn't check your devices.")).toBeNull();
	});

	it("renders no Refresh button when signed out", async () => {
		customHandlers["plugin:tradr|sign_in_status"] = () => null;

		render(<App />);
		await screen.findByRole("button", { name: "Sign in with Google" });

		expect(screen.queryByRole("button", { name: "Refresh" })).toBeNull();
		expect(screen.queryByRole("button", { name: "Checking…" })).toBeNull();
	});
});

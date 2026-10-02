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
import { fixtureCommands } from "./preview/fixtures.js";
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
});

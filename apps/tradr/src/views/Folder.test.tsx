import { mockIPC } from "@tauri-apps/api/mocks";
import {
	fireEvent,
	render,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fixtureCommands, fixtureRenameRefusal } from "../preview/fixtures.js";
import { Folder } from "./Folder.js";

describe("Folder component", () => {
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

	it("renders directory entries automatically without button press and without share selector", async () => {
		render(
			<Folder peerKey="dev-pixel-8" peerName="Pixel 8" onBack={() => {}} />,
		);

		await screen.findByText("Photos");
		expect(screen.getByText("Documents")).toBeDefined();
		expect(screen.getByText("report-2026.pdf")).toBeDefined();
		expect(screen.getByText("family-photo.jpg")).toBeDefined();
		expect(screen.getByText("project-notes.txt")).toBeDefined();

		expect(screen.queryByRole("combobox")).toBeNull();
		expect(screen.queryByLabelText(/share/i)).toBeNull();
	});

	it("displays refusal message when rename operation rejects", async () => {
		customHandlers["plugin:tradr|rename_peer_entry"] = () => {
			return Promise.reject(fixtureRenameRefusal);
		};

		render(
			<Folder peerKey="dev-pixel-8" peerName="Pixel 8" onBack={() => {}} />,
		);

		await screen.findByText("report-2026.pdf");
		const fileRow = screen.getByText("report-2026.pdf").closest(".file-row");
		expect(fileRow).toBeInstanceOf(HTMLElement);
		if (!(fileRow instanceof HTMLElement)) return;

		const renameButton = within(fileRow).getByRole("button", {
			name: "Rename",
		});
		fireEvent.click(renameButton);

		const input = within(fileRow).getByRole("textbox");
		fireEvent.change(input, { target: { value: "a.txt" } });

		const saveButton = within(fileRow).getByRole("button", { name: "Save" });
		fireEvent.click(saveButton);

		const errorMessage = await screen.findByText(fixtureRenameRefusal);
		expect(errorMessage.className).toContain("notice notice--error");
	});

	it("prompts for confirmation before invoking delete_peer_entry", async () => {
		render(
			<Folder peerKey="dev-pixel-8" peerName="Pixel 8" onBack={() => {}} />,
		);

		await screen.findByText("project-notes.txt");
		const fileRow = screen.getByText("project-notes.txt").closest(".file-row");
		expect(fileRow).toBeInstanceOf(HTMLElement);
		if (!(fileRow instanceof HTMLElement)) return;

		const initialDeleteButton = within(fileRow).getByRole("button", {
			name: "Delete",
		});
		fireEvent.click(initialDeleteButton);

		expect(within(fileRow).getByText("Delete?")).toBeDefined();
		const deleteCallsBefore = recordedCalls.filter(
			(c) => c.cmd === "plugin:tradr|delete_peer_entry",
		);
		expect(deleteCallsBefore).toHaveLength(0);

		const confirmDeleteButton = within(fileRow).getByRole("button", {
			name: "Delete",
		});
		fireEvent.click(confirmDeleteButton);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|delete_peer_entry",
				payload: {
					peerId: "dev-pixel-8",
					shareId: "share-primary",
					path: "project-notes.txt",
					recursive: false,
				},
			});
		});
	});
});

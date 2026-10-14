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
import { Linking } from "./Linking.js";
import {
	fixtureCommands,
	fixtureLinkInvite,
	fixtureLinkProposal,
} from "./preview/fixtures.js";
import type { LinkProposalDto } from "./types.js";

describe("Linking component", () => {
	const recordedCalls: { cmd: string; payload?: unknown }[] = [];

	beforeEach(() => {
		recordedCalls.length = 0;
		mockIPC(
			async (cmd: string, payload?: unknown) => {
				recordedCalls.push({ cmd, payload });
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
	});

	it("invokes reply_to_link_invite with the previewed blob when Link accounts is clicked", async () => {
		render(<Linking />);

		const textarea = screen.getByPlaceholderText(
			"Paste a code from another account",
		);
		fireEvent.change(textarea, { target: { value: "code-A" } });

		const checkButton = screen.getByRole("button", { name: "Check code" });
		fireEvent.click(checkButton);

		const linkAccountsButton = await screen.findByRole("button", {
			name: "Link accounts",
		});
		fireEvent.click(linkAccountsButton);

		await waitFor(() => {
			expect(recordedCalls).toContainEqual({
				cmd: "plugin:tradr|reply_to_link_invite",
				payload: { blob: "code-A" },
			});
		});
	});

	it("discards the preview and leaves reply_to_link_invite uncalled when textarea changes", async () => {
		render(<Linking />);

		const textarea = screen.getByPlaceholderText(
			"Paste a code from another account",
		);
		fireEvent.change(textarea, { target: { value: "code-A" } });

		const checkButton = screen.getByRole("button", { name: "Check code" });
		fireEvent.click(checkButton);

		await screen.findByRole("button", { name: "Link accounts" });
		expect(
			screen.getByText("Check these words match the other device's screen"),
		).toBeDefined();

		fireEvent.change(textarea, { target: { value: "code-B" } });

		expect(screen.queryByRole("button", { name: "Link accounts" })).toBeNull();
		expect(
			screen.queryByText("Check these words match the other device's screen"),
		).toBeNull();

		const replyCalls = recordedCalls.filter(
			(call) => call.cmd === "plugin:tradr|reply_to_link_invite",
		);
		expect(replyCalls).toHaveLength(0);
	});

	it("shows wants to link with the label and invokes approve_link on Link click", async () => {
		render(<Linking />);

		const proposal: LinkProposalDto = {
			...fixtureLinkProposal,
			peer_label: "Personal Tablet",
		};

		await act(async () => {
			await emit("link-proposal", proposal);
		});

		const proposalHeading = await screen.findByText(
			"Personal Tablet wants to link",
		);
		expect(proposalHeading).toBeDefined();

		const approveButton = screen.getByRole("button", { name: "Link" });
		fireEvent.click(approveButton);

		await waitFor(() => {
			const approveCalls = recordedCalls.filter(
				(call) => call.cmd === "plugin:tradr|approve_link",
			);
			expect(approveCalls.length).toBeGreaterThan(0);
		});
	});

	it("calls navigator.clipboard.writeText with the invite blob and button reads Copied", async () => {
		const writeTextMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			configurable: true,
			writable: true,
		});

		render(<Linking />);

		const inviteButton = screen.getByRole("button", {
			name: "Invite another account",
		});
		fireEvent.click(inviteButton);

		const copyButton = await screen.findByRole("button", {
			name: "Copy code",
		});

		vi.useFakeTimers();
		await act(async () => {
			fireEvent.click(copyButton);
		});

		expect(writeTextMock).toHaveBeenCalledWith(fixtureLinkInvite.blob);
		expect(screen.getByRole("button", { name: "Copied" })).toBeDefined();

		act(() => {
			vi.advanceTimersByTime(2000);
		});
		expect(screen.getByRole("button", { name: "Copy code" })).toBeDefined();
	});

	it("shows Couldn't copy text when writeText rejects", async () => {
		const writeTextMock = vi.fn().mockRejectedValue(new Error("denied"));
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			configurable: true,
			writable: true,
		});

		render(<Linking />);

		const inviteButton = screen.getByRole("button", {
			name: "Invite another account",
		});
		fireEvent.click(inviteButton);

		const copyButton = await screen.findByRole("button", {
			name: "Copy code",
		});
		fireEvent.click(copyButton);

		await screen.findByText("Couldn't copy. Select the code and copy it.");
	});

	it("shows Couldn't copy text when navigator.clipboard is undefined", async () => {
		Object.defineProperty(navigator, "clipboard", {
			value: undefined,
			configurable: true,
			writable: true,
		});

		render(<Linking />);

		const inviteButton = screen.getByRole("button", {
			name: "Invite another account",
		});
		fireEvent.click(inviteButton);

		const copyButton = await screen.findByRole("button", {
			name: "Copy code",
		});

		expect(() => {
			fireEvent.click(copyButton);
		}).not.toThrow();

		await screen.findByText("Couldn't copy. Select the code and copy it.");
	});
});

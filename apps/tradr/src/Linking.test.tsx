import { emit } from "@tauri-apps/api/event";
import { mockIPC } from "@tauri-apps/api/mocks";
import {
	act,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { Linking } from "./Linking.js";
import { fixtureCommands, fixtureLinkProposal } from "./preview/fixtures.js";
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
});

import { emit } from "@tauri-apps/api/event";
import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { createRoot } from "react-dom/client";
import { App } from "../App.js";
import {
	activeScenario,
	fixtureCommands,
	fixtureReceivedFilesPayload,
} from "./fixtures.js";
/* stylesheet */ import "../styles.css";

mockWindows("main");

let onShareIntentSubscribed: (() => void) | null = null;
const shareIntentSubscribed = new Promise<void>((resolve) => {
	onShareIntentSubscribed = resolve;
});

let onFilesReceivedSubscribed: (() => void) | null = null;
const filesReceivedSubscribed = new Promise<void>((resolve) => {
	onFilesReceivedSubscribed = resolve;
});

mockIPC(
	async (cmd: string, payload?: unknown) => {
		const handler = fixtureCommands[cmd];
		if (handler) {
			return handler(payload);
		}
		return null;
	},
	{ shouldMockEvents: true },
);

// Signals when the frontend registers listeners so the harness can emit mock events.
const tauriInternals = (
	window as unknown as {
		__TAURI_INTERNALS__?: {
			invoke: (
				cmd: string,
				args?: unknown,
				options?: unknown,
			) => Promise<unknown>;
		};
	}
).__TAURI_INTERNALS__;
if (tauriInternals) {
	const rawInvoke = tauriInternals.invoke;
	tauriInternals.invoke = async (
		cmd: string,
		args?: unknown,
		options?: unknown,
	) => {
		if (cmd === "plugin:event|listen") {
			const payload = args as { event?: string } | undefined;
			if (payload?.event === "share-intent") {
				onShareIntentSubscribed?.();
			}
			if (payload?.event === "files-received") {
				onFilesReceivedSubscribed?.();
			}
		}
		return rawInvoke(cmd, args, options);
	};
}

const container = document.getElementById("root");
if (!container) {
	throw new Error("root element missing from index.html");
}

// Mirrors a production build so each event is subscribed once.
createRoot(container).render(<App />);

if (activeScenario === "signed-in") {
	await filesReceivedSubscribed;
	await emit("files-received", fixtureReceivedFilesPayload);
	await new Promise((resolve) => setTimeout(resolve, 300));
}

if (activeScenario === "share") {
	await shareIntentSubscribed;
	await emit("share-intent", {
		action: "android.intent.action.SEND_MULTIPLE",
		mimeType: null,
		extraText: null,
		targetDevice: null,
		transferId: null,
		files: [
			{
				name: "quarterly-report.pdf",
				size: 2457600,
				cachePath: "/tmp/quarterly-report.pdf",
				adoptedId: null,
			},
			{
				name: "team-photo.jpg",
				size: 4194304,
				cachePath: "/tmp/team-photo.jpg",
				adoptedId: null,
			},
		],
	});
	await new Promise((resolve) => setTimeout(resolve, 300));
}

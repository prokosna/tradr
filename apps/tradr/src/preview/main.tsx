import { emit } from "@tauri-apps/api/event";
import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "../App.js";
import { activeScenario, fixtureCommands } from "./fixtures.js";
/* stylesheet */ import "../styles.css";

mockWindows("main");

let onShareIntentSubscribed: (() => void) | null = null;
const shareIntentSubscribed = new Promise<void>((resolve) => {
	onShareIntentSubscribed = resolve;
});

mockIPC(
	async (cmd: string, payload?: unknown) => {
		if (cmd === "plugin:event|listen") {
			const args = payload as { event?: string } | undefined;
			if (args?.event === "share-intent") {
				onShareIntentSubscribed?.();
			}
		}
		const handler = fixtureCommands[cmd];
		if (handler) {
			return handler(payload);
		}
		return null;
	},
	{ shouldMockEvents: true },
);

// Intercepts IPC invocations to resolve once the frontend registers the share listener.
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
		}
		return rawInvoke(cmd, args, options);
	};
}

const container = document.getElementById("root");
if (!container) {
	throw new Error("root element missing from index.html");
}

createRoot(container).render(
	<StrictMode>
		<App />
	</StrictMode>,
);

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

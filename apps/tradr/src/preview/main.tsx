import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "../App.js";
import { fixtureCommands } from "./fixtures.js";
/* stylesheet */ import "../styles.css";

mockWindows("main");
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

const container = document.getElementById("root");
if (!container) {
	throw new Error("root element missing from index.html");
}

createRoot(container).render(
	<StrictMode>
		<App />
	</StrictMode>,
);

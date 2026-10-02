import { clearMocks, mockWindows } from "@tauri-apps/api/mocks";
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";

// Prepares the window label for Tauri IPC and webview APIs.
beforeEach(() => {
	mockWindows("main");
});

// Cleans up rendered React trees and resets Tauri mocks between tests.
afterEach(() => {
	cleanup();
	clearMocks();
});

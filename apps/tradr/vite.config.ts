import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { buildCommit } from "./build-commit.js";

// Tauri needs a fixed dev-server port, and must not watch src-tauri --
// a Rust rebuild would otherwise retrigger the frontend dev server.
export default defineConfig({
	plugins: [react()],
	define: { __TRADR_COMMIT__: JSON.stringify(buildCommit()) },
	clearScreen: false,
	server: {
		port: 1420,
		strictPort: true,
		watch: {
			ignored: ["**/src-tauri/**"],
		},
	},
});

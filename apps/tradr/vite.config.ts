import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Tauri needs a fixed dev-server port, and must not watch src-tauri --
// a Rust rebuild would otherwise retrigger the frontend dev server.
export default defineConfig({
	plugins: [react()],
	clearScreen: false,
	server: {
		port: 1420,
		strictPort: true,
		watch: {
			ignored: ["**/src-tauri/**"],
		},
	},
});

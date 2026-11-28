import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import { buildCommit } from "./build-commit.js";

export default defineConfig({
	plugins: [react()],
	define: { __TRADR_COMMIT__: JSON.stringify(buildCommit()) },
	test: {
		environment: "jsdom",
		include: ["src/**/*.test.{ts,tsx}"],
		setupFiles: ["src/test/setup.ts"],
	},
});

import { execFileSync } from "node:child_process";

// The short commit a build came from, so a device can say which build it runs.
export function buildCommit(): string {
	try {
		return execFileSync("git", ["rev-parse", "--short", "HEAD"], {
			encoding: "utf8",
		}).trim();
	} catch (e) {
		console.warn(`build commit unavailable: ${String(e)}`);
		return "unknown";
	}
}

import fs from "node:fs";
import path from "node:path";

export interface BrokrEnvConfig {
	host: string;
	port: number;
	dataDir: string;
	dbPath: string;
	joinToken: string;
}

export function loadConfigFromEnv(): BrokrEnvConfig {
	const host = process.env.BROKR_HOST || "0.0.0.0";
	const port = process.env.BROKR_PORT
		? Number.parseInt(process.env.BROKR_PORT, 10)
		: 8780;
	const dataDir = process.env.BROKR_DATA_DIR || "./data";

	let joinToken: string | undefined = process.env.BROKR_JOIN_TOKEN;
	if (!joinToken && process.env.BROKR_JOIN_TOKEN_FILE) {
		try {
			joinToken = fs
				.readFileSync(process.env.BROKR_JOIN_TOKEN_FILE, "utf-8")
				.trim();
		} catch (err) {
			throw new Error(`Failed to read BROKR_JOIN_TOKEN_FILE: ${String(err)}`);
		}
	}

	if (!joinToken) {
		throw new Error(
			"Neither BROKR_JOIN_TOKEN nor BROKR_JOIN_TOKEN_FILE is set",
		);
	}

	fs.mkdirSync(dataDir, { recursive: true });
	const dbPath = path.join(dataDir, "brokr.db");

	return {
		host,
		port,
		dataDir,
		dbPath,
		joinToken,
	};
}

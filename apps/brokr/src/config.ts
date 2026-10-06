import fs from "node:fs";
import path from "node:path";

export interface BrokrEnvConfig {
	host: string;
	port: number;
	dataDir: string;
	dbPath: string;
	joinToken: string;
	deliveryTtlDays: number;
	deliveryMaxBytes: number;
	storageMaxBytes: number;
	maxPendingPerSender: number;
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

	const deliveryMaxBytesStr = process.env.BROKR_DELIVERY_MAX_BYTES;
	if (!deliveryMaxBytesStr) {
		throw new Error("BROKR_DELIVERY_MAX_BYTES is required but not set");
	}
	const deliveryMaxBytes = Number.parseInt(deliveryMaxBytesStr, 10);
	if (Number.isNaN(deliveryMaxBytes) || deliveryMaxBytes <= 0) {
		throw new Error("BROKR_DELIVERY_MAX_BYTES must be a positive integer");
	}

	const storageMaxBytesStr = process.env.BROKR_STORAGE_MAX_BYTES;
	if (!storageMaxBytesStr) {
		throw new Error("BROKR_STORAGE_MAX_BYTES is required but not set");
	}
	const storageMaxBytes = Number.parseInt(storageMaxBytesStr, 10);
	if (Number.isNaN(storageMaxBytes) || storageMaxBytes <= 0) {
		throw new Error("BROKR_STORAGE_MAX_BYTES must be a positive integer");
	}

	const deliveryTtlDays = process.env.BROKR_DELIVERY_TTL_DAYS
		? Number.parseInt(process.env.BROKR_DELIVERY_TTL_DAYS, 10)
		: 30;
	if (Number.isNaN(deliveryTtlDays) || deliveryTtlDays <= 0) {
		throw new Error("BROKR_DELIVERY_TTL_DAYS must be a positive integer");
	}

	const maxPendingPerSender = process.env.BROKR_MAX_PENDING_PER_SENDER
		? Number.parseInt(process.env.BROKR_MAX_PENDING_PER_SENDER, 10)
		: 100;
	if (Number.isNaN(maxPendingPerSender) || maxPendingPerSender <= 0) {
		throw new Error("BROKR_MAX_PENDING_PER_SENDER must be a positive integer");
	}

	fs.mkdirSync(dataDir, { recursive: true });
	const dbPath = path.join(dataDir, "brokr.db");

	return {
		host,
		port,
		dataDir,
		dbPath,
		joinToken,
		deliveryTtlDays,
		deliveryMaxBytes,
		storageMaxBytes,
		maxPendingPerSender,
	};
}

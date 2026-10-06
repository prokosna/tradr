import crypto from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { hashSessionToken } from "./crypto.js";

export function initDatabase(db: DatabaseSync): { accountSalt: string } {
	db.exec("PRAGMA foreign_keys = ON;");

	db.exec(`
		CREATE TABLE IF NOT EXISTS server_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS devices (
			device_id TEXT PRIMARY KEY,
			identity_pub TEXT NOT NULL,
			account_tag TEXT NOT NULL,
			registered_at INTEGER NOT NULL,
			last_seen INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_tag);

		CREATE TABLE IF NOT EXISTS device_link_tags (
			device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
			link_tag TEXT NOT NULL,
			PRIMARY KEY (device_id, link_tag)
		);
		CREATE INDEX IF NOT EXISTS idx_link_tags ON device_link_tags(link_tag);

		CREATE TABLE IF NOT EXISTS challenges (
			nonce TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS sessions (
			token_hash TEXT PRIMARY KEY,
			device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	`);

	const existing = db
		.prepare("SELECT value FROM server_meta WHERE key = 'account_salt'")
		.get() as { value: string } | undefined;

	if (existing) {
		return { accountSalt: existing.value };
	}

	const newSalt = crypto.randomBytes(16).toString("hex");
	db.prepare(
		"INSERT INTO server_meta (key, value) VALUES ('account_salt', ?)",
	).run(newSalt);
	return { accountSalt: newSalt };
}

export function createChallenge(
	db: DatabaseSync,
	nonce: string,
	now: number,
): void {
	db.prepare("INSERT INTO challenges (nonce, created_at) VALUES (?, ?)").run(
		nonce.toLowerCase(),
		now,
	);
}

export function consumeChallenge(
	db: DatabaseSync,
	nonce: string,
): { createdAt: number } | null {
	const row = db
		.prepare("SELECT created_at FROM challenges WHERE nonce = ?")
		.get(nonce.toLowerCase()) as { created_at: number } | undefined;

	if (!row) {
		return null;
	}

	db.prepare("DELETE FROM challenges WHERE nonce = ?").run(nonce.toLowerCase());
	return { createdAt: row.created_at };
}

export function upsertDevice(
	db: DatabaseSync,
	params: {
		deviceId: string;
		identityPub: string;
		accountTag: string;
		linkTags: string[];
		now: number;
	},
): void {
	db.exec("BEGIN");
	try {
		db.prepare(`
			INSERT INTO devices (device_id, identity_pub, account_tag, registered_at, last_seen)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(device_id) DO UPDATE SET
				identity_pub = excluded.identity_pub,
				account_tag = excluded.account_tag,
				registered_at = excluded.registered_at,
				last_seen = excluded.last_seen
		`).run(
			params.deviceId,
			params.identityPub,
			params.accountTag,
			params.now,
			params.now,
		);

		db.prepare("DELETE FROM device_link_tags WHERE device_id = ?").run(
			params.deviceId,
		);

		const insertLink = db.prepare(
			"INSERT OR IGNORE INTO device_link_tags (device_id, link_tag) VALUES (?, ?)",
		);
		for (const tag of params.linkTags) {
			insertLink.run(params.deviceId, tag);
		}

		db.exec("COMMIT");
	} catch (err) {
		db.exec("ROLLBACK");
		throw err;
	}
}

export function createSession(
	db: DatabaseSync,
	tokenHash: string,
	deviceId: string,
	now: number,
	expiresAt: number,
): void {
	db.prepare(
		"INSERT INTO sessions (token_hash, device_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
	).run(tokenHash, deviceId, now, expiresAt);
}

export function resolveSession(
	db: DatabaseSync,
	bearerToken: string,
	now: number = Date.now(),
): string | null {
	let token = bearerToken.trim();
	if (token.toLowerCase().startsWith("bearer ")) {
		token = token.slice(7).trim();
	}
	if (!token) {
		return null;
	}

	const tokenHash = hashSessionToken(token);
	const row = db
		.prepare("SELECT device_id, expires_at FROM sessions WHERE token_hash = ?")
		.get(tokenHash) as { device_id: string; expires_at: number } | undefined;

	if (!row) {
		return null;
	}
	if (row.expires_at <= now) {
		return null;
	}
	return row.device_id;
}

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
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

		CREATE TABLE IF NOT EXISTS deliveries (
			id TEXT PRIMARY KEY,
			sender_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
			recipient_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
			size INTEGER NOT NULL,
			uploaded_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			collected_at INTEGER,
			expired_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_deliveries_recipient ON deliveries(recipient_device_id);
		CREATE INDEX IF NOT EXISTS idx_deliveries_sender ON deliveries(sender_device_id);
		CREATE INDEX IF NOT EXISTS idx_deliveries_expires ON deliveries(expires_at);
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

export interface DeliveryRow {
	id: string;
	sender_device_id: string;
	recipient_device_id: string;
	size: number;
	uploaded_at: number;
	expires_at: number;
	collected_at: number | null;
	expired_at: number | null;
}

export function areDevicesRelated(
	db: DatabaseSync,
	senderDeviceId: string,
	recipientDeviceId: string,
): { allowed: boolean; recipientExists: boolean } {
	const recipient = db
		.prepare("SELECT account_tag FROM devices WHERE device_id = ?")
		.get(recipientDeviceId.toLowerCase()) as
		| { account_tag: string }
		| undefined;

	if (!recipient) {
		return { allowed: false, recipientExists: false };
	}

	const sender = db
		.prepare("SELECT account_tag FROM devices WHERE device_id = ?")
		.get(senderDeviceId.toLowerCase()) as { account_tag: string } | undefined;

	if (!sender) {
		return { allowed: false, recipientExists: true };
	}

	if (
		sender.account_tag.toLowerCase() === recipient.account_tag.toLowerCase()
	) {
		return { allowed: true, recipientExists: true };
	}

	const sharedLink = db
		.prepare(`
			SELECT 1 FROM device_link_tags t1
			JOIN device_link_tags t2 ON t1.link_tag = t2.link_tag
			WHERE t1.device_id = ? AND t2.device_id = ?
			LIMIT 1
		`)
		.get(senderDeviceId.toLowerCase(), recipientDeviceId.toLowerCase());

	return { allowed: sharedLink !== undefined, recipientExists: true };
}

export function getWaitingDeliveriesTotalSize(db: DatabaseSync): number {
	const row = db
		.prepare(
			"SELECT COALESCE(SUM(size), 0) AS total FROM deliveries WHERE collected_at IS NULL AND expired_at IS NULL",
		)
		.get() as { total: number };
	return row.total;
}

export function getSenderPendingCount(
	db: DatabaseSync,
	senderDeviceId: string,
): number {
	const row = db
		.prepare(
			"SELECT COUNT(*) AS count FROM deliveries WHERE sender_device_id = ? AND collected_at IS NULL AND expired_at IS NULL",
		)
		.get(senderDeviceId.toLowerCase()) as { count: number };
	return row.count;
}

export function insertDelivery(
	db: DatabaseSync,
	params: {
		id: string;
		senderDeviceId: string;
		recipientDeviceId: string;
		size: number;
		uploadedAt: number;
		expiresAt: number;
	},
): void {
	db.prepare(`
		INSERT INTO deliveries (id, sender_device_id, recipient_device_id, size, uploaded_at, expires_at, collected_at, expired_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
	`).run(
		params.id,
		params.senderDeviceId.toLowerCase(),
		params.recipientDeviceId.toLowerCase(),
		params.size,
		params.uploadedAt,
		params.expiresAt,
	);
}

export function getInboxDeliveries(
	db: DatabaseSync,
	recipientDeviceId: string,
	now: number,
): Array<{
	id: string;
	sender_device_id: string;
	size: number;
	uploaded_at: number;
}> {
	return db
		.prepare(`
			SELECT id, sender_device_id, size, uploaded_at
			FROM deliveries
			WHERE recipient_device_id = ? AND collected_at IS NULL AND expired_at IS NULL AND expires_at > ?
			ORDER BY uploaded_at ASC, id ASC
		`)
		.all(recipientDeviceId.toLowerCase(), now) as Array<{
		id: string;
		sender_device_id: string;
		size: number;
		uploaded_at: number;
	}>;
}

export function getDelivery(db: DatabaseSync, id: string): DeliveryRow | null {
	const row = db.prepare("SELECT * FROM deliveries WHERE id = ?").get(id) as
		| DeliveryRow
		| undefined;
	return row ?? null;
}

export function markDeliveryCollected(
	db: DatabaseSync,
	id: string,
	now: number,
): boolean {
	const res = db
		.prepare(
			"UPDATE deliveries SET collected_at = ? WHERE id = ? AND collected_at IS NULL",
		)
		.run(now, id);
	return res.changes > 0;
}

export function getOutboxDeliveries(
	db: DatabaseSync,
	senderDeviceId: string,
	now: number,
): Array<{
	id: string;
	recipient_device_id: string;
	size: number;
	uploaded_at: number;
	state: "waiting" | "delivered" | "expired";
	collected_at: number | null;
}> {
	const rows = db
		.prepare(`
			SELECT id, recipient_device_id, size, uploaded_at, expires_at, collected_at, expired_at
			FROM deliveries
			WHERE sender_device_id = ?
			ORDER BY uploaded_at ASC, id ASC
		`)
		.all(senderDeviceId.toLowerCase()) as unknown as DeliveryRow[];

	return rows.map((r) => {
		let state: "waiting" | "delivered" | "expired";
		let collectedAt: number | null = null;
		if (r.collected_at !== null) {
			state = "delivered";
			collectedAt = r.collected_at;
		} else if (r.expired_at !== null || r.expires_at <= now) {
			state = "expired";
		} else {
			state = "waiting";
		}
		return {
			id: r.id,
			recipient_device_id: r.recipient_device_id,
			size: r.size,
			uploaded_at: r.uploaded_at,
			state,
			collected_at: collectedAt,
		};
	});
}

export function sweepDeliveries(
	db: DatabaseSync,
	dataDir: string,
	now: number,
): void {
	const expiredRows = db
		.prepare(`
			SELECT id, expires_at FROM deliveries
			WHERE collected_at IS NULL AND expired_at IS NULL AND expires_at <= ?
		`)
		.all(now) as Array<{ id: string; expires_at: number }>;

	const deliveriesDir = path.join(dataDir, "deliveries");
	for (const row of expiredRows) {
		const filePath = path.join(deliveriesDir, row.id);
		fs.rmSync(filePath, { force: true });
		db.prepare("UPDATE deliveries SET expired_at = ? WHERE id = ?").run(
			row.expires_at,
			row.id,
		);
	}

	const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;
	db.prepare(`
		DELETE FROM deliveries
		WHERE (collected_at IS NOT NULL AND collected_at <= ?)
		   OR (expired_at IS NOT NULL AND expired_at <= ?)
	`).run(thirtyDaysAgo, thirtyDaysAgo);
}

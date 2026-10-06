import crypto from "node:crypto";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import fastify, { type FastifyInstance } from "fastify";
import {
	constantTimeEqual,
	deriveDeviceId,
	hashSessionToken,
	isHex,
	parseP256PublicKey,
	verifyChallengeSignature,
} from "./crypto.js";
import {
	consumeChallenge,
	createChallenge,
	createSession,
	initDatabase,
	resolveSession,
	upsertDevice,
} from "./db.js";

export interface BrokrServerConfig {
	host?: string;
	port?: number;
	db?: DatabaseSync;
	dbPath?: string;
	dataDir?: string;
	joinToken: string;
	clock?: () => number;
}

export function buildServer(config: BrokrServerConfig): FastifyInstance {
	let db: DatabaseSync;
	let shouldCloseDb = false;

	if (config.db) {
		db = config.db;
	} else if (config.dbPath) {
		db = new DatabaseSync(config.dbPath);
		shouldCloseDb = true;
	} else if (config.dataDir) {
		db = new DatabaseSync(path.join(config.dataDir, "brokr.db"));
		shouldCloseDb = true;
	} else {
		db = new DatabaseSync(":memory:");
		shouldCloseDb = true;
	}

	const { accountSalt } = initDatabase(db);
	const clock = config.clock ?? Date.now;

	const app = fastify({ logger: false });

	app.addHook("onClose", () => {
		if (shouldCloseDb) {
			db.close();
		}
	});

	app.get("/v1/health", async (_request, reply) => {
		return reply.status(200).send({ ok: true });
	});

	app.get("/v1/info", async (_request, reply) => {
		return reply.status(200).send({
			version: 1,
			account_salt: accountSalt,
		});
	});

	app.post("/v1/challenge", async (_request, reply) => {
		const nonce = crypto.randomBytes(32).toString("hex");
		createChallenge(db, nonce, clock());
		return reply.status(200).send({ nonce });
	});

	app.post("/v1/register", async (request, reply) => {
		const body = request.body;
		if (!body || typeof body !== "object") {
			return reply.status(400).send({ error: "Malformed body" });
		}

		const {
			device_id,
			identity_pub,
			join_token,
			account_tag,
			link_tags,
			nonce,
			signature,
		} = body as Record<string, unknown>;

		if (
			typeof device_id !== "string" ||
			typeof identity_pub !== "string" ||
			typeof join_token !== "string" ||
			typeof account_tag !== "string" ||
			!Array.isArray(link_tags) ||
			typeof nonce !== "string" ||
			typeof signature !== "string"
		) {
			return reply.status(400).send({ error: "Malformed field" });
		}

		for (const tag of link_tags) {
			if (typeof tag !== "string" || !isHex(tag)) {
				return reply.status(400).send({ error: "Malformed link tag" });
			}
		}

		if (
			!isHex(device_id, 16) ||
			!isHex(identity_pub, 65) ||
			!isHex(account_tag) ||
			!isHex(nonce, 32) ||
			!isHex(signature, 64)
		) {
			return reply.status(400).send({ error: "Malformed field" });
		}

		const keyObject = parseP256PublicKey(identity_pub);
		if (!keyObject) {
			return reply.status(400).send({ error: "Invalid identity_pub" });
		}

		const expectedDeviceId = deriveDeviceId(identity_pub);
		if (device_id.toLowerCase() !== expectedDeviceId.toLowerCase()) {
			return reply.status(400).send({ error: "Device ID mismatch" });
		}

		if (!constantTimeEqual(join_token, config.joinToken)) {
			return reply.status(401).send({ error: "Unauthorized" });
		}

		const now = clock();
		const challenge = consumeChallenge(db, nonce);
		if (!challenge) {
			return reply.status(401).send({ error: "Unknown or reused nonce" });
		}

		if (now - challenge.createdAt > 60_000) {
			return reply.status(401).send({ error: "Expired nonce" });
		}

		if (!verifyChallengeSignature(keyObject, nonce, signature)) {
			return reply.status(401).send({ error: "Invalid signature" });
		}

		upsertDevice(db, {
			deviceId: device_id.toLowerCase(),
			identityPub: identity_pub.toLowerCase(),
			accountTag: account_tag.toLowerCase(),
			linkTags: link_tags.map((t) => (t as string).toLowerCase()),
			now,
		});

		const session = crypto.randomBytes(32).toString("hex");
		const tokenHash = hashSessionToken(session);
		const expiresAt = now + 30 * 24 * 60 * 60 * 1000;
		createSession(db, tokenHash, device_id.toLowerCase(), now, expiresAt);

		return reply.status(200).send({ session });
	});

	return app;
}

export { resolveSession };

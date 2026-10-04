import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
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
	areDevicesRelated,
	consumeChallenge,
	createChallenge,
	createSession,
	getDelivery,
	getInboxDeliveries,
	getOutboxDeliveries,
	getSenderPendingCount,
	getWaitingDeliveriesTotalSize,
	initDatabase,
	insertDelivery,
	markDeliveryCollected,
	resolveSession,
	sweepDeliveries,
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
	deliveryTtlDays?: number;
	deliveryMaxBytes?: number;
	storageMaxBytes?: number;
	maxPendingPerSender?: number;
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

	const deliveryTtlDays = config.deliveryTtlDays ?? 30;
	const deliveryMaxBytes = config.deliveryMaxBytes ?? 100 * 1024 * 1024;
	const storageMaxBytes = config.storageMaxBytes ?? 1024 * 1024 * 1024;
	const maxPendingPerSender = config.maxPendingPerSender ?? 100;

	let dataDir: string;
	let shouldCleanupDataDir = false;
	if (config.dataDir) {
		dataDir = config.dataDir;
	} else if (process.env.BROKR_DATA_DIR) {
		dataDir = process.env.BROKR_DATA_DIR;
	} else {
		dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "brokr-data-"));
		shouldCleanupDataDir = true;
	}
	const deliveriesDir = path.join(dataDir, "deliveries");
	fs.mkdirSync(deliveriesDir, { recursive: true });

	sweepDeliveries(db, dataDir, clock());

	const sweepInterval = setInterval(
		() => {
			sweepDeliveries(db, dataDir, clock());
		},
		60 * 60 * 1000,
	);
	sweepInterval.unref();

	const app = fastify({ logger: false });

	app.addHook("onClose", () => {
		clearInterval(sweepInterval);
		if (shouldCloseDb) {
			db.close();
		}
		if (shouldCleanupDataDir) {
			fs.rmSync(dataDir, { recursive: true, force: true });
		}
	});

	app.addContentTypeParser(
		"application/octet-stream",
		(_request, payload, done) => {
			done(null, payload);
		},
	);

	const requireCallerDeviceId = (
		authHeader: string | undefined,
	): string | null => {
		if (!authHeader) {
			return null;
		}
		return resolveSession(db, authHeader, clock());
	};

	app.get("/v1/health", async (_request, reply) => {
		return reply.status(200).send({ ok: true });
	});

	app.get("/v1/info", async (_request, reply) => {
		return reply.status(200).send({
			version: 1,
			account_salt: accountSalt,
			delivery_ttl_days: deliveryTtlDays,
			delivery_max_bytes: deliveryMaxBytes,
			storage_max_bytes: storageMaxBytes,
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

	app.put("/v1/deliveries", async (request, reply) => {
		const callerDeviceId = requireCallerDeviceId(request.headers.authorization);
		if (!callerDeviceId) {
			return reply.status(401).send({ error: "Unauthorized" });
		}

		const contentType = request.headers["content-type"];
		if (!contentType?.toLowerCase().startsWith("application/octet-stream")) {
			return reply
				.status(400)
				.send({ error: "Expected application/octet-stream" });
		}

		const deliveryId = crypto.randomBytes(16).toString("hex");
		const filePath = path.join(deliveriesDir, deliveryId);
		const fileStream = fs.createWriteStream(filePath);
		let fileStreamError: Error | null = null;
		fileStream.on("error", (err) => {
			fileStreamError = err;
		});

		let bytesReceived = 0;
		let headerBuf: Buffer | null = null;
		const headerChunks: Buffer[] = [];
		let headerLen = 0;
		let totalLenBig: bigint | null = null;
		let recipientDeviceId = "";
		let senderDeviceId = "";
		let validationError: { status: number; message: string } | null = null;

		const bodyStream = request.body as AsyncIterable<Buffer>;
		try {
			for await (const chunk of bodyStream) {
				if (validationError) {
					continue;
				}

				bytesReceived += chunk.length;
				fileStream.write(chunk);

				if (!headerBuf) {
					headerChunks.push(chunk);
					headerLen += chunk.length;
					if (headerLen >= 106) {
						headerBuf = Buffer.concat(headerChunks).subarray(0, 106);
						const version = headerBuf.readUInt8(0);
						recipientDeviceId = headerBuf.subarray(1, 17).toString("hex");
						senderDeviceId = headerBuf.subarray(17, 33).toString("hex");
						totalLenBig = headerBuf.readBigUInt64BE(98);

						if (version !== 1) {
							validationError = {
								status: 400,
								message: "Unsupported envelope version",
							};
						} else if (
							senderDeviceId.toLowerCase() !== callerDeviceId.toLowerCase()
						) {
							validationError = {
								status: 400,
								message: "Sender device ID does not match session",
							};
						} else if (
							totalLenBig > BigInt(deliveryMaxBytes) ||
							totalLenBig < 106n
						) {
							validationError = {
								status: 400,
								message: "Delivery exceeds maximum allowed size",
							};
						} else {
							const { allowed, recipientExists } = areDevicesRelated(
								db,
								senderDeviceId,
								recipientDeviceId,
							);
							if (!recipientExists || !allowed) {
								validationError = {
									status: 403,
									message: "Recipient is not eligible for delivery",
								};
							} else {
								const storedTotal = getWaitingDeliveriesTotalSize(db);
								if (
									BigInt(storedTotal) + totalLenBig >
									BigInt(storageMaxBytes)
								) {
									validationError = {
										status: 413,
										message: "Storage limit exceeded",
									};
								} else {
									const pendingCount = getSenderPendingCount(
										db,
										senderDeviceId,
									);
									if (pendingCount >= maxPendingPerSender) {
										validationError = {
											status: 429,
											message: "Sender pending limit reached",
										};
									}
								}
							}
						}

						if (validationError) {
							request.raw.destroy();
							break;
						}
					}
				}

				if (totalLenBig !== null && BigInt(bytesReceived) > totalLenBig) {
					validationError = {
						status: 400,
						message: "Body length exceeds total_len",
					};
					request.raw.destroy();
					break;
				}
			}
		} catch (err) {
			if (!validationError) {
				validationError = {
					status: 400,
					message: `Stream read error: ${String(err)}`,
				};
			}
		}

		if (
			validationError ||
			totalLenBig === null ||
			BigInt(bytesReceived) !== totalLenBig
		) {
			await new Promise<void>((resolve) => {
				if (fileStream.closed) {
					resolve();
				} else {
					fileStream.once("close", () => resolve());
					fileStream.destroy();
				}
			});
			fs.rmSync(filePath, { force: true });
			if (validationError) {
				return reply
					.status(validationError.status)
					.send({ error: validationError.message });
			}
			return reply
				.status(400)
				.send({ error: "Body length does not match total_len" });
		}

		await new Promise<void>((resolve) => {
			if (fileStream.closed) {
				resolve();
			} else {
				fileStream.once("close", () => resolve());
				fileStream.end();
			}
		});

		if (fileStreamError) {
			fs.rmSync(filePath, { force: true });
			return reply.status(500).send({ error: "Failed to write delivery file" });
		}

		const now = clock();
		const expiresAt = now + deliveryTtlDays * 24 * 60 * 60 * 1000;
		insertDelivery(db, {
			id: deliveryId,
			senderDeviceId,
			recipientDeviceId,
			size: bytesReceived,
			uploadedAt: now,
			expiresAt,
		});

		return reply.status(200).send({ id: deliveryId });
	});

	app.get("/v1/deliveries/inbox", async (request, reply) => {
		const callerDeviceId = requireCallerDeviceId(request.headers.authorization);
		if (!callerDeviceId) {
			return reply.status(401).send({ error: "Unauthorized" });
		}

		const items = getInboxDeliveries(db, callerDeviceId, clock());
		return reply.status(200).send(items);
	});

	app.get<{ Params: { id: string } }>(
		"/v1/deliveries/:id",
		async (request, reply) => {
			const callerDeviceId = requireCallerDeviceId(
				request.headers.authorization,
			);
			if (!callerDeviceId) {
				return reply.status(401).send({ error: "Unauthorized" });
			}

			const { id } = request.params;
			const delivery = getDelivery(db, id);
			if (
				!delivery ||
				delivery.recipient_device_id.toLowerCase() !==
					callerDeviceId.toLowerCase() ||
				delivery.collected_at !== null ||
				delivery.expired_at !== null ||
				delivery.expires_at <= clock()
			) {
				return reply.status(404).send({ error: "Not found" });
			}

			const filePath = path.join(deliveriesDir, id);
			if (!fs.existsSync(filePath)) {
				return reply.status(404).send({ error: "Not found" });
			}

			const stream = fs.createReadStream(filePath);
			return reply
				.status(200)
				.header("content-type", "application/octet-stream")
				.header("content-length", delivery.size)
				.send(stream);
		},
	);

	app.delete<{ Params: { id: string } }>(
		"/v1/deliveries/:id",
		async (request, reply) => {
			const callerDeviceId = requireCallerDeviceId(
				request.headers.authorization,
			);
			if (!callerDeviceId) {
				return reply.status(401).send({ error: "Unauthorized" });
			}

			const { id } = request.params;
			const delivery = getDelivery(db, id);
			if (
				!delivery ||
				delivery.recipient_device_id.toLowerCase() !==
					callerDeviceId.toLowerCase()
			) {
				return reply.status(404).send({ error: "Not found" });
			}

			const filePath = path.join(deliveriesDir, id);
			fs.rmSync(filePath, { force: true });
			markDeliveryCollected(db, id, clock());

			return reply.status(200).send({ ok: true });
		},
	);

	app.get("/v1/deliveries/outbox", async (request, reply) => {
		const callerDeviceId = requireCallerDeviceId(request.headers.authorization);
		if (!callerDeviceId) {
			return reply.status(401).send({ error: "Unauthorized" });
		}

		const items = getOutboxDeliveries(db, callerDeviceId, clock());
		return reply.status(200).send(items);
	});

	return app;
}

export { resolveSession, sweepDeliveries };

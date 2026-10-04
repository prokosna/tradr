import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { blake3 } from "@noble/hashes/blake3.js";
import { describe, expect, it } from "vitest";
import {
	buildServer,
	loadConfigFromEnv,
	resolveSession,
	sweepDeliveries,
} from "../src/index.js";

function generateTestDevice(): {
	publicKeyHex: string;
	deviceIdHex: string;
	privateKey: crypto.KeyObject;
} {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
		namedCurve: "P-256",
	});
	const der = publicKey.export({ format: "der", type: "spki" });
	const rawPoint = der.subarray(26);
	const publicKeyHex = rawPoint.toString("hex");
	const deviceIdHex = Buffer.from(blake3(rawPoint).subarray(0, 16)).toString(
		"hex",
	);

	return {
		publicKeyHex,
		deviceIdHex,
		privateKey,
	};
}

function signChallenge(privateKey: crypto.KeyObject, nonceHex: string): string {
	const nonceBytes = Buffer.from(nonceHex, "hex");
	const prefix = Buffer.from("tradr-brokr-v1", "utf-8");
	const data = Buffer.concat([prefix, nonceBytes]);
	return crypto
		.sign("sha256", data, {
			key: privateKey,
			dsaEncoding: "ieee-p1363",
		})
		.toString("hex");
}

async function registerTestDevice(
	server: ReturnType<typeof buildServer>,
	device: ReturnType<typeof generateTestDevice>,
	params: {
		accountTag?: string;
		linkTags?: string[];
		joinToken?: string;
	} = {},
): Promise<string> {
	const chalRes = await server.inject({
		method: "POST",
		url: "/v1/challenge",
	});
	const { nonce } = chalRes.json() as { nonce: string };
	const signature = signChallenge(device.privateKey, nonce);

	const regRes = await server.inject({
		method: "POST",
		url: "/v1/register",
		payload: {
			device_id: device.deviceIdHex,
			identity_pub: device.publicKeyHex,
			join_token: params.joinToken ?? "test-token",
			account_tag: params.accountTag ?? "00".repeat(32),
			link_tags: params.linkTags ?? [],
			nonce,
			signature,
		},
	});
	return (regRes.json() as { session: string }).session;
}

function buildEnvelope(
	senderDeviceIdHex: string,
	recipientDeviceIdHex: string,
	payloadBytes: Buffer,
	version = 1,
	overrideTotalLen?: bigint,
): Buffer {
	const header = Buffer.alloc(106, 0);
	header.writeUInt8(version, 0);
	Buffer.from(recipientDeviceIdHex, "hex").copy(header, 1, 0, 16);
	Buffer.from(senderDeviceIdHex, "hex").copy(header, 17, 0, 16);
	Buffer.alloc(65, 0x5a).copy(header, 33, 0, 65);
	const totalLen = overrideTotalLen ?? BigInt(106 + payloadBytes.length);
	header.writeBigUInt64BE(totalLen, 98);
	return Buffer.concat([header, payloadBytes]);
}

describe("Brokr HTTP Server", () => {
	it("responds to /v1/health with ok: true", async () => {
		const server = buildServer({ joinToken: "test-token" });
		const res = await server.inject({
			method: "GET",
			url: "/v1/health",
		});
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({ ok: true });
		await server.close();
	});

	it("responds to /v1/info with version and 16-byte hex account_salt", async () => {
		const server = buildServer({ joinToken: "test-token" });
		const res = await server.inject({
			method: "GET",
			url: "/v1/info",
		});
		expect(res.statusCode).toBe(200);
		const body = res.json() as { version: number; account_salt: string };
		expect(body.version).toBe(1);
		expect(typeof body.account_salt).toBe("string");
		expect(body.account_salt).toHaveLength(32);
		expect(/^[0-9a-fA-F]{32}$/.test(body.account_salt)).toBe(true);
		await server.close();
	});

	it("preserves account_salt across server restarts on the same data directory", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "brokr-salt-"));
		try {
			const server1 = buildServer({ joinToken: "test-token", dataDir: tmpDir });
			const res1 = await server1.inject({
				method: "GET",
				url: "/v1/info",
			});
			const salt1 = (res1.json() as { account_salt: string }).account_salt;
			await server1.close();

			const server2 = buildServer({ joinToken: "test-token", dataDir: tmpDir });
			const res2 = await server2.inject({
				method: "GET",
				url: "/v1/info",
			});
			const salt2 = (res2.json() as { account_salt: string }).account_salt;
			await server2.close();

			expect(salt1).toBe(salt2);
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("issues a 32-byte hex challenge nonce on POST /v1/challenge", async () => {
		const server = buildServer({ joinToken: "test-token" });
		const res = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		expect(res.statusCode).toBe(200);
		const body = res.json() as { nonce: string };
		expect(body.nonce).toHaveLength(64);
		expect(/^[0-9a-fA-F]{64}$/.test(body.nonce)).toBe(true);
		await server.close();
	});

	it("registers a device successfully with valid challenge signature and join token", async () => {
		const db = new DatabaseSync(":memory:");
		const currentTime = 1_700_000_000_000;
		const server = buildServer({
			db,
			joinToken: "correct-join-token",
			clock: () => currentTime,
		});

		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		const device = generateTestDevice();
		const signature = signChallenge(device.privateKey, nonce);

		const regRes = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device.deviceIdHex,
				identity_pub: device.publicKeyHex,
				join_token: "correct-join-token",
				account_tag: "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				link_tags: ["1122334455667788", "aabbccddeeff0011"],
				nonce,
				signature,
			},
		});

		expect(regRes.statusCode).toBe(200);
		const body = regRes.json() as { session: string };
		expect(body.session).toHaveLength(64);

		// Resolve session bearer token
		const resolvedDeviceId = resolveSession(db, body.session, currentTime);
		expect(resolvedDeviceId).toBe(device.deviceIdHex);

		const resolvedWithBearerPrefix = resolveSession(
			db,
			`Bearer ${body.session}`,
			currentTime,
		);
		expect(resolvedWithBearerPrefix).toBe(device.deviceIdHex);

		// Expired session resolves to null after 30 days
		const thirtyOneDaysLater = currentTime + 31 * 24 * 60 * 60 * 1000;
		expect(resolveSession(db, body.session, thirtyOneDaysLater)).toBeNull();

		// Unknown token resolves to null
		expect(resolveSession(db, "00".repeat(32), currentTime)).toBeNull();

		await server.close();
		db.close();
	});

	it("refuses registration with 401 when join token is incorrect", async () => {
		const server = buildServer({ joinToken: "secret-token" });
		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		const device = generateTestDevice();
		const signature = signChallenge(device.privateKey, nonce);

		const res = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device.deviceIdHex,
				identity_pub: device.publicKeyHex,
				join_token: "wrong-token",
				account_tag: "00".repeat(32),
				link_tags: [],
				nonce,
				signature,
			},
		});

		expect(res.statusCode).toBe(401);
		await server.close();
	});

	it("refuses registration with 401 when nonce is unknown", async () => {
		const server = buildServer({ joinToken: "secret-token" });
		const device = generateTestDevice();
		const randomNonce = "ff".repeat(32);
		const signature = signChallenge(device.privateKey, randomNonce);

		const res = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device.deviceIdHex,
				identity_pub: device.publicKeyHex,
				join_token: "secret-token",
				account_tag: "00".repeat(32),
				link_tags: [],
				nonce: randomNonce,
				signature,
			},
		});

		expect(res.statusCode).toBe(401);
		await server.close();
	});

	it("refuses registration with 401 when nonce is older than 60 seconds", async () => {
		let currentTime = 1_000_000;
		const server = buildServer({
			joinToken: "secret-token",
			clock: () => currentTime,
		});

		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		// Advance clock by 61 seconds
		currentTime += 61_000;

		const device = generateTestDevice();
		const signature = signChallenge(device.privateKey, nonce);

		const res = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device.deviceIdHex,
				identity_pub: device.publicKeyHex,
				join_token: "secret-token",
				account_tag: "00".repeat(32),
				link_tags: [],
				nonce,
				signature,
			},
		});

		expect(res.statusCode).toBe(401);
		await server.close();
	});

	it("refuses registration with 401 when nonce is reused", async () => {
		const server = buildServer({ joinToken: "secret-token" });
		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		const device = generateTestDevice();
		const signature = signChallenge(device.privateKey, nonce);

		const payload = {
			device_id: device.deviceIdHex,
			identity_pub: device.publicKeyHex,
			join_token: "secret-token",
			account_tag: "00".repeat(32),
			link_tags: [],
			nonce,
			signature,
		};

		const firstRes = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload,
		});
		expect(firstRes.statusCode).toBe(200);

		const secondRes = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload,
		});
		expect(secondRes.statusCode).toBe(401);

		await server.close();
	});

	it("refuses registration with 401 when signature does not verify", async () => {
		const server = buildServer({ joinToken: "secret-token" });
		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		const device1 = generateTestDevice();
		const device2 = generateTestDevice();
		// Signed by device2 private key instead of device1
		const wrongSignature = signChallenge(device2.privateKey, nonce);

		const res = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device1.deviceIdHex,
				identity_pub: device1.publicKeyHex,
				join_token: "secret-token",
				account_tag: "00".repeat(32),
				link_tags: [],
				nonce,
				signature: wrongSignature,
			},
		});

		expect(res.statusCode).toBe(401);
		await server.close();
	});

	it("refuses registration with 400 when device_id does not match identity_pub", async () => {
		const server = buildServer({ joinToken: "secret-token" });
		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		const device = generateTestDevice();
		const signature = signChallenge(device.privateKey, nonce);
		const mismatchedDeviceId = "00".repeat(16);

		const res = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: mismatchedDeviceId,
				identity_pub: device.publicKeyHex,
				join_token: "secret-token",
				account_tag: "00".repeat(32),
				link_tags: [],
				nonce,
				signature,
			},
		});

		expect(res.statusCode).toBe(400);
		await server.close();
	});

	it("refuses registration with 400 when identity_pub is not a valid P-256 point", async () => {
		const server = buildServer({ joinToken: "secret-token" });
		const chalRes = await server.inject({
			method: "POST",
			url: "/v1/challenge",
		});
		const { nonce } = chalRes.json() as { nonce: string };

		// Point starting with 04 and 65 bytes, but not on curve P-256
		const invalidPoint = `04${"00".repeat(64)}`;
		const fakeDeviceId = Buffer.from(
			blake3(Buffer.from(invalidPoint, "hex")).subarray(0, 16),
		).toString("hex");

		const res = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: fakeDeviceId,
				identity_pub: invalidPoint,
				join_token: "secret-token",
				account_tag: "00".repeat(32),
				link_tags: [],
				nonce,
				signature: "00".repeat(64),
			},
		});

		expect(res.statusCode).toBe(400);
		await server.close();
	});

	it("refuses registration with 400 when fields are malformed or missing", async () => {
		const server = buildServer({ joinToken: "secret-token" });

		const missingFieldRes = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: "00".repeat(16),
				identity_pub: `04${"00".repeat(64)}`,
			},
		});
		expect(missingFieldRes.statusCode).toBe(400);

		const nonHexRes = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: "not-a-valid-hex-device-id-at-all",
				identity_pub: `04${"00".repeat(64)}`,
				join_token: "secret-token",
				account_tag: "1234",
				link_tags: ["not-hex!"],
				nonce: "00".repeat(32),
				signature: "00".repeat(64),
			},
		});
		expect(nonHexRes.statusCode).toBe(400);

		await server.close();
	});

	it("replaces link_tags and updates last_seen on device re-registration", async () => {
		const db = new DatabaseSync(":memory:");
		let time = 1_000_000;
		const server = buildServer({
			db,
			joinToken: "secret-token",
			clock: () => time,
		});

		const device = generateTestDevice();

		// First registration
		const chal1 = await server.inject({ method: "POST", url: "/v1/challenge" });
		const nonce1 = (chal1.json() as { nonce: string }).nonce;
		const sig1 = signChallenge(device.privateKey, nonce1);

		const reg1 = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device.deviceIdHex,
				identity_pub: device.publicKeyHex,
				join_token: "secret-token",
				account_tag: "aa".repeat(32),
				link_tags: ["11".repeat(32), "22".repeat(32)],
				nonce: nonce1,
				signature: sig1,
			},
		});
		expect(reg1.statusCode).toBe(200);

		// Advance time
		time += 10_000;

		// Re-registration with new account tag and replaced link tags
		const chal2 = await server.inject({ method: "POST", url: "/v1/challenge" });
		const nonce2 = (chal2.json() as { nonce: string }).nonce;
		const sig2 = signChallenge(device.privateKey, nonce2);

		const reg2 = await server.inject({
			method: "POST",
			url: "/v1/register",
			payload: {
				device_id: device.deviceIdHex,
				identity_pub: device.publicKeyHex,
				join_token: "secret-token",
				account_tag: "bb".repeat(32),
				link_tags: ["33".repeat(32)],
				nonce: nonce2,
				signature: sig2,
			},
		});
		expect(reg2.statusCode).toBe(200);

		// Verify database state
		const deviceRow = db
			.prepare("SELECT * FROM devices WHERE device_id = ?")
			.get(device.deviceIdHex) as {
			account_tag: string;
			registered_at: number;
			last_seen: number;
		};
		expect(deviceRow.account_tag).toBe("bb".repeat(32));
		expect(deviceRow.last_seen).toBe(time);

		const links = db
			.prepare(
				"SELECT link_tag FROM device_link_tags WHERE device_id = ? ORDER BY link_tag",
			)
			.all(device.deviceIdHex) as Array<{ link_tag: string }>;
		expect(links).toEqual([{ link_tag: "33".repeat(32) }]);

		await server.close();
		db.close();
	});

	it("reports delivery TTL and byte limits on GET /v1/info", async () => {
		const server = buildServer({
			joinToken: "test-token",
			deliveryTtlDays: 14,
			deliveryMaxBytes: 50 * 1024 * 1024,
			storageMaxBytes: 500 * 1024 * 1024,
		});
		const res = await server.inject({
			method: "GET",
			url: "/v1/info",
		});
		expect(res.statusCode).toBe(200);
		const body = res.json() as {
			version: number;
			account_salt: string;
			delivery_ttl_days: number;
			delivery_max_bytes: number;
			storage_max_bytes: number;
		};
		expect(body.version).toBe(1);
		expect(body.delivery_ttl_days).toBe(14);
		expect(body.delivery_max_bytes).toBe(50 * 1024 * 1024);
		expect(body.storage_max_bytes).toBe(500 * 1024 * 1024);
		await server.close();
	});

	it("validates environment variables in loadConfigFromEnv", () => {
		const origEnv = { ...process.env };
		try {
			delete process.env.BROKR_DELIVERY_MAX_BYTES;
			delete process.env.BROKR_STORAGE_MAX_BYTES;
			process.env.BROKR_JOIN_TOKEN = "token";

			expect(() => loadConfigFromEnv()).toThrow(
				"BROKR_DELIVERY_MAX_BYTES is required",
			);

			process.env.BROKR_DELIVERY_MAX_BYTES = "10485760";
			expect(() => loadConfigFromEnv()).toThrow(
				"BROKR_STORAGE_MAX_BYTES is required",
			);

			process.env.BROKR_STORAGE_MAX_BYTES = "104857600";
			const cfg = loadConfigFromEnv();
			expect(cfg.deliveryMaxBytes).toBe(10485760);
			expect(cfg.storageMaxBytes).toBe(104857600);
			expect(cfg.deliveryTtlDays).toBe(30);
			expect(cfg.maxPendingPerSender).toBe(100);
		} finally {
			process.env = origEnv;
		}
	});

	it("refuses unauthenticated requests with 401 across all delivery endpoints", async () => {
		const server = buildServer({ joinToken: "test-token" });

		const putRes = await server.inject({
			method: "PUT",
			url: "/v1/deliveries",
			headers: { "content-type": "application/octet-stream" },
			payload: Buffer.alloc(106, 0),
		});
		expect(putRes.statusCode).toBe(401);

		const inboxRes = await server.inject({
			method: "GET",
			url: "/v1/deliveries/inbox",
		});
		expect(inboxRes.statusCode).toBe(401);

		const getRes = await server.inject({
			method: "GET",
			url: "/v1/deliveries/some-delivery-id",
		});
		expect(getRes.statusCode).toBe(401);

		const delRes = await server.inject({
			method: "DELETE",
			url: "/v1/deliveries/some-delivery-id",
		});
		expect(delRes.statusCode).toBe(401);

		const outboxRes = await server.inject({
			method: "GET",
			url: "/v1/deliveries/outbox",
		});
		expect(outboxRes.statusCode).toBe(401);

		await server.close();
	});

	it("allows same-account upload, byte-for-byte collection, acknowledgement, and outbox delivery tracking", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "brokr-deliv-"));
		const db = new DatabaseSync(":memory:");
		let time = 1_700_000_000_000;
		const server = buildServer({
			db,
			dataDir: tmpDir,
			joinToken: "test-token",
			clock: () => time,
		});

		try {
			const sender = generateTestDevice();
			const recipient = generateTestDevice();
			const sharedAccount = "aa".repeat(32);

			const senderSession = await registerTestDevice(server, sender, {
				accountTag: sharedAccount,
			});
			const recipientSession = await registerTestDevice(server, recipient, {
				accountTag: sharedAccount,
			});

			const payload = Buffer.from(
				"arbitrary encrypted payload for deferred delivery",
			);
			const envelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				payload,
			);

			const uploadRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			expect(uploadRes.statusCode).toBe(200);
			const { id: deliveryId } = uploadRes.json() as { id: string };
			expect(deliveryId).toHaveLength(32);

			const savedFilePath = path.join(tmpDir, "deliveries", deliveryId);
			expect(fs.existsSync(savedFilePath)).toBe(true);

			const inboxRes = await server.inject({
				method: "GET",
				url: "/v1/deliveries/inbox",
				headers: { authorization: `Bearer ${recipientSession}` },
			});
			expect(inboxRes.statusCode).toBe(200);
			const inboxList = inboxRes.json() as Array<{
				id: string;
				sender_device_id: string;
				size: number;
				uploaded_at: number;
			}>;
			expect(inboxList).toHaveLength(1);
			const firstInbox = inboxList[0];
			if (!firstInbox) {
				throw new Error("Missing inbox item");
			}
			expect(firstInbox).toEqual({
				id: deliveryId,
				sender_device_id: sender.deviceIdHex,
				size: envelope.length,
				uploaded_at: time,
			});

			const downloadRes = await server.inject({
				method: "GET",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${recipientSession}` },
			});
			expect(downloadRes.statusCode).toBe(200);
			expect(downloadRes.headers["content-type"]).toBe(
				"application/octet-stream",
			);
			expect(downloadRes.rawPayload.equals(envelope)).toBe(true);

			time += 5_000;
			const ackRes = await server.inject({
				method: "DELETE",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${recipientSession}` },
			});
			expect(ackRes.statusCode).toBe(200);
			expect(fs.existsSync(savedFilePath)).toBe(false);

			const outboxRes = await server.inject({
				method: "GET",
				url: "/v1/deliveries/outbox",
				headers: { authorization: `Bearer ${senderSession}` },
			});
			expect(outboxRes.statusCode).toBe(200);
			const outboxList = outboxRes.json() as Array<{
				id: string;
				recipient_device_id: string;
				size: number;
				uploaded_at: number;
				state: string;
				collected_at: number;
			}>;
			expect(outboxList).toHaveLength(1);
			const firstOutbox = outboxList[0];
			if (!firstOutbox) {
				throw new Error("Missing outbox item");
			}
			expect(firstOutbox).toEqual({
				id: deliveryId,
				recipient_device_id: recipient.deviceIdHex,
				size: envelope.length,
				uploaded_at: 1_700_000_000_000,
				state: "delivered",
				collected_at: time,
			});

			const secondDownload = await server.inject({
				method: "GET",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${recipientSession}` },
			});
			expect(secondDownload.statusCode).toBe(404);

			const secondInbox = await server.inject({
				method: "GET",
				url: "/v1/deliveries/inbox",
				headers: { authorization: `Bearer ${recipientSession}` },
			});
			expect(secondInbox.statusCode).toBe(200);
			expect(secondInbox.json()).toEqual([]);
		} finally {
			await server.close();
			db.close();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("allows linked pair sharing a link_tag and refuses unrelated pair with 403", async () => {
		const server = buildServer({ joinToken: "test-token" });
		try {
			const sender = generateTestDevice();
			const linkedRecipient = generateTestDevice();
			const unrelatedRecipient = generateTestDevice();

			const linkTag = "cc".repeat(32);
			const senderSession = await registerTestDevice(server, sender, {
				accountTag: "11".repeat(32),
				linkTags: [linkTag],
			});
			await registerTestDevice(server, linkedRecipient, {
				accountTag: "22".repeat(32),
				linkTags: [linkTag],
			});
			await registerTestDevice(server, unrelatedRecipient, {
				accountTag: "33".repeat(32),
				linkTags: ["44".repeat(32)],
			});

			const payload = Buffer.from("linked transfer payload");
			const linkedEnvelope = buildEnvelope(
				sender.deviceIdHex,
				linkedRecipient.deviceIdHex,
				payload,
			);
			const linkedRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: linkedEnvelope,
			});
			expect(linkedRes.statusCode).toBe(200);

			const unrelatedEnvelope = buildEnvelope(
				sender.deviceIdHex,
				unrelatedRecipient.deviceIdHex,
				payload,
			);
			const unrelatedRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: unrelatedEnvelope,
			});
			expect(unrelatedRes.statusCode).toBe(403);

			const unregisteredDeviceId = "99".repeat(16);
			const unregEnvelope = buildEnvelope(
				sender.deviceIdHex,
				unregisteredDeviceId,
				payload,
			);
			const unregRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: unregEnvelope,
			});
			expect(unregRes.statusCode).toBe(403);
		} finally {
			await server.close();
		}
	});

	it("refuses upload with 400 when sender_device_id is forged or version is invalid", async () => {
		const server = buildServer({ joinToken: "test-token" });
		try {
			const sender = generateTestDevice();
			const recipient = generateTestDevice();
			const otherDevice = generateTestDevice();

			const senderSession = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			await registerTestDevice(server, recipient, {
				accountTag: "aa".repeat(32),
			});

			const payload = Buffer.from("payload");
			const forgedEnvelope = buildEnvelope(
				otherDevice.deviceIdHex,
				recipient.deviceIdHex,
				payload,
			);
			const forgedRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: forgedEnvelope,
			});
			expect(forgedRes.statusCode).toBe(400);

			const badVersionEnvelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				payload,
				2,
			);
			const badVersionRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: badVersionEnvelope,
			});
			expect(badVersionRes.statusCode).toBe(400);
		} finally {
			await server.close();
		}
	});

	it("enforces delivery size, storage limits, and body length matches with no file left behind", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "brokr-limits-"));
		const server = buildServer({
			dataDir: tmpDir,
			joinToken: "test-token",
			deliveryMaxBytes: 200,
			storageMaxBytes: 300,
		});

		try {
			const sender = generateTestDevice();
			const recipient = generateTestDevice();
			const session = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			const recipientSession = await registerTestDevice(server, recipient, {
				accountTag: "aa".repeat(32),
			});

			const overDeliveryEnvelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				Buffer.alloc(100),
				1,
				201n,
			);
			const overDeliveryRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${session}`,
					"content-type": "application/octet-stream",
				},
				payload: overDeliveryEnvelope,
			});
			expect(overDeliveryRes.statusCode).toBe(400);

			const validPayload = Buffer.alloc(50);
			const validEnvelope1 = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				validPayload,
			);
			const upload1 = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${session}`,
					"content-type": "application/octet-stream",
				},
				payload: validEnvelope1,
			});
			expect(upload1.statusCode).toBe(200);
			const { id: upload1Id } = upload1.json() as { id: string };

			const validEnvelope2 = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				validPayload,
			);
			const upload2 = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${session}`,
					"content-type": "application/octet-stream",
				},
				payload: validEnvelope2,
			});
			expect(upload2.statusCode).toBe(413);

			await server.inject({
				method: "DELETE",
				url: `/v1/deliveries/${upload1Id}`,
				headers: { authorization: `Bearer ${recipientSession}` },
			});

			const deliveriesDir = path.join(tmpDir, "deliveries");
			const filesBefore = fs.readdirSync(deliveriesDir);

			const underLengthPayload = Buffer.alloc(20);
			const underEnvelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				underLengthPayload,
				1,
				150n,
			);
			const underRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${session}`,
					"content-type": "application/octet-stream",
				},
				payload: underEnvelope,
			});
			expect(underRes.statusCode).toBe(400);
			expect(fs.readdirSync(deliveriesDir)).toEqual(filesBefore);

			const overLengthEnvelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				Buffer.alloc(50),
				1,
				120n,
			);
			const overRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${session}`,
					"content-type": "application/octet-stream",
				},
				payload: overLengthEnvelope,
			});
			expect(overRes.statusCode).toBe(400);
			expect(fs.readdirSync(deliveriesDir)).toEqual(filesBefore);
		} finally {
			await server.close();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it("enforces the per-sender waiting deliveries cap with 429", async () => {
		const server = buildServer({
			joinToken: "test-token",
			maxPendingPerSender: 2,
		});

		try {
			const sender = generateTestDevice();
			const recipient = generateTestDevice();
			const senderSession = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			const recipientSession = await registerTestDevice(server, recipient, {
				accountTag: "aa".repeat(32),
			});

			const envelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				Buffer.from("chunk"),
			);

			const up1 = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			expect(up1.statusCode).toBe(200);
			const { id: id1 } = up1.json() as { id: string };

			const up2 = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			expect(up2.statusCode).toBe(200);

			const up3 = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			expect(up3.statusCode).toBe(429);

			await server.inject({
				method: "DELETE",
				url: `/v1/deliveries/${id1}`,
				headers: { authorization: `Bearer ${recipientSession}` },
			});

			const up3Retry = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			expect(up3Retry.statusCode).toBe(200);
		} finally {
			await server.close();
		}
	});

	it("refuses GET and DELETE with 404 from non-recipient devices", async () => {
		const server = buildServer({ joinToken: "test-token" });
		try {
			const sender = generateTestDevice();
			const recipient = generateTestDevice();
			const bystander = generateTestDevice();

			const senderSession = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			await registerTestDevice(server, recipient, {
				accountTag: "aa".repeat(32),
			});
			const bystanderSession = await registerTestDevice(server, bystander, {
				accountTag: "aa".repeat(32),
			});

			const envelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				Buffer.from("private"),
			);
			const upRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			const { id: deliveryId } = upRes.json() as { id: string };

			const bystanderGet = await server.inject({
				method: "GET",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${bystanderSession}` },
			});
			expect(bystanderGet.statusCode).toBe(404);

			const bystanderDel = await server.inject({
				method: "DELETE",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${bystanderSession}` },
			});
			expect(bystanderDel.statusCode).toBe(404);

			const senderGet = await server.inject({
				method: "GET",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${senderSession}` },
			});
			expect(senderGet.statusCode).toBe(404);

			const senderDel = await server.inject({
				method: "DELETE",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${senderSession}` },
			});
			expect(senderDel.statusCode).toBe(404);
		} finally {
			await server.close();
		}
	});

	it("sweeps expired deliveries, deletes files, reflects in outbox, and purges rows after 30 days", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "brokr-expiry-"));
		const db = new DatabaseSync(":memory:");
		let time = 1_700_000_000_000;
		const server = buildServer({
			db,
			dataDir: tmpDir,
			joinToken: "test-token",
			deliveryTtlDays: 30,
			clock: () => time,
		});

		try {
			const sender = generateTestDevice();
			const recipient = generateTestDevice();
			const senderSession = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			await registerTestDevice(server, recipient, {
				accountTag: "aa".repeat(32),
			});

			const envelope = buildEnvelope(
				sender.deviceIdHex,
				recipient.deviceIdHex,
				Buffer.from("expires soon"),
			);
			const upRes = await server.inject({
				method: "PUT",
				url: "/v1/deliveries",
				headers: {
					authorization: `Bearer ${senderSession}`,
					"content-type": "application/octet-stream",
				},
				payload: envelope,
			});
			const { id: deliveryId } = upRes.json() as { id: string };
			const filePath = path.join(tmpDir, "deliveries", deliveryId);
			expect(fs.existsSync(filePath)).toBe(true);

			time += 31 * 24 * 60 * 60 * 1000;
			sweepDeliveries(db, tmpDir, time);

			expect(fs.existsSync(filePath)).toBe(false);

			const activeSenderSession = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			const activeRecipientSession = await registerTestDevice(
				server,
				recipient,
				{
					accountTag: "aa".repeat(32),
				},
			);

			const outboxRes = await server.inject({
				method: "GET",
				url: "/v1/deliveries/outbox",
				headers: { authorization: `Bearer ${activeSenderSession}` },
			});
			const outbox = outboxRes.json() as Array<{
				state: string;
				collected_at: number | null;
			}>;
			expect(outbox).toHaveLength(1);
			const firstOutbox = outbox[0];
			if (!firstOutbox) {
				throw new Error("Missing outbox item");
			}
			expect(firstOutbox.state).toBe("expired");
			expect(firstOutbox.collected_at).toBeNull();

			const inboxRes = await server.inject({
				method: "GET",
				url: "/v1/deliveries/inbox",
				headers: { authorization: `Bearer ${activeRecipientSession}` },
			});
			expect(inboxRes.json()).toEqual([]);

			const getRes = await server.inject({
				method: "GET",
				url: `/v1/deliveries/${deliveryId}`,
				headers: { authorization: `Bearer ${activeRecipientSession}` },
			});
			expect(getRes.statusCode).toBe(404);

			time += 30 * 24 * 60 * 60 * 1000 + 1000;
			sweepDeliveries(db, tmpDir, time);

			const purgedSenderSession = await registerTestDevice(server, sender, {
				accountTag: "aa".repeat(32),
			});
			const purgedOutbox = await server.inject({
				method: "GET",
				url: "/v1/deliveries/outbox",
				headers: { authorization: `Bearer ${purgedSenderSession}` },
			});
			expect(purgedOutbox.json()).toEqual([]);
		} finally {
			await server.close();
			db.close();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});

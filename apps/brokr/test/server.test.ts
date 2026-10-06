import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { blake3 } from "@noble/hashes/blake3.js";
import { describe, expect, it } from "vitest";
import { buildServer, resolveSession } from "../src/index.js";

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
});

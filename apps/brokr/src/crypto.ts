import crypto from "node:crypto";
import { blake3 } from "@noble/hashes/blake3.js";

const SPKI_P256_PREFIX = Buffer.from(
	"3059301306072a8648ce3d020106082a8648ce3d030107034200",
	"hex",
);

export function isHex(
	str: unknown,
	expectedByteLength?: number,
): str is string {
	if (typeof str !== "string") {
		return false;
	}
	if (expectedByteLength !== undefined) {
		if (str.length !== expectedByteLength * 2) {
			return false;
		}
	} else {
		if (str.length === 0 || str.length % 2 !== 0) {
			return false;
		}
	}
	return /^[0-9a-fA-F]+$/.test(str);
}

export function constantTimeEqual(a: string, b: string): boolean {
	const hashA = crypto.createHash("sha256").update(a).digest();
	const hashB = crypto.createHash("sha256").update(b).digest();
	return crypto.timingSafeEqual(hashA, hashB);
}

export function parseP256PublicKey(pubKeyHex: string): crypto.KeyObject | null {
	if (pubKeyHex.length !== 130 || !pubKeyHex.startsWith("04")) {
		return null;
	}
	try {
		const rawBytes = Buffer.from(pubKeyHex, "hex");
		if (rawBytes.length !== 65) {
			return null;
		}
		const der = Buffer.concat([SPKI_P256_PREFIX, rawBytes]);
		return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
	} catch {
		return null;
	}
}

export function deriveDeviceId(pubKeyHex: string): string {
	const rawBytes = Buffer.from(pubKeyHex, "hex");
	const hash = blake3(rawBytes);
	return Buffer.from(hash.subarray(0, 16)).toString("hex");
}

export function verifyChallengeSignature(
	keyObject: crypto.KeyObject,
	nonceHex: string,
	signatureHex: string,
): boolean {
	if (signatureHex.length !== 128) {
		return false;
	}
	try {
		const nonceBytes = Buffer.from(nonceHex, "hex");
		const prefix = Buffer.from("tradr-brokr-v1", "utf-8");
		const data = Buffer.concat([prefix, nonceBytes]);
		const sigBytes = Buffer.from(signatureHex, "hex");
		return crypto.verify(
			"sha256",
			data,
			{ key: keyObject, dsaEncoding: "ieee-p1363" },
			sigBytes,
		);
	} catch {
		return false;
	}
}

export function hashSessionToken(token: string): string {
	return crypto.createHash("sha256").update(token).digest("hex");
}

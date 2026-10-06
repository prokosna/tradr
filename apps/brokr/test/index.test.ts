import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfigFromEnv, reportStartupError } from "../src/index.js";

describe("startup error reporting", () => {
	const origEnv = { ...process.env };

	beforeEach(() => {
		process.env = { ...origEnv };
	});

	afterEach(() => {
		process.env = origEnv;
	});

	it("reports missing BROKR_STORAGE_MAX_BYTES to stderr without leaking join token", () => {
		process.env.BROKR_JOIN_TOKEN = "secret-token-123";
		process.env.BROKR_DELIVERY_MAX_BYTES = "1";
		delete process.env.BROKR_STORAGE_MAX_BYTES;

		let captured = "";
		const writer = {
			write(chunk: string) {
				captured += chunk;
			},
		};

		let startupErr: unknown;
		try {
			loadConfigFromEnv();
		} catch (err) {
			startupErr = err;
		}

		expect(startupErr).toBeInstanceOf(Error);
		const exitCode = reportStartupError(startupErr, writer);

		expect(exitCode).toBe(1);
		expect(captured).toBe(
			"brokr: BROKR_STORAGE_MAX_BYTES is required but not set\n",
		);
		expect(captured).toContain("BROKR_STORAGE_MAX_BYTES");
		expect(captured).not.toContain("secret-token-123");
	});

	it("supports function writers and preserves exit code", () => {
		let captured = "";
		const exitCode = reportStartupError(
			new Error("listen EADDRINUSE: address already in use 0.0.0.0:8780"),
			(chunk: string) => {
				captured += chunk;
			},
		);

		expect(exitCode).toBe(1);
		expect(captured).toBe(
			"brokr: listen EADDRINUSE: address already in use 0.0.0.0:8780\n",
		);
	});

	it("sanitizes join token if present in error message", () => {
		process.env.BROKR_JOIN_TOKEN = "secret-token-123";
		let captured = "";
		const exitCode = reportStartupError(
			new Error("failed with secret-token-123"),
			(chunk: string) => {
				captured += chunk;
			},
		);

		expect(exitCode).toBe(1);
		expect(captured).not.toContain("secret-token-123");
		expect(captured).toContain("[REDACTED]");
	});

	it("handles non-Error thrown values", () => {
		let captured = "";
		const exitCode = reportStartupError("unexpected string error", {
			write(chunk: string) {
				captured += chunk;
			},
		});

		expect(exitCode).toBe(1);
		expect(captured).toBe("brokr: unexpected string error\n");
	});
});

import type { UnlistenFn } from "@tauri-apps/api/event";
import { describe, expect, it, vi } from "vitest";
import { subscribe } from "./subscribe.js";

describe("subscribe", () => {
	it("calls unlisten once the promise resolves when cleanup is called before resolution", async () => {
		let resolveSubscription!: (fn: UnlistenFn) => void;
		const subscribePromise = new Promise<UnlistenFn>((resolve) => {
			resolveSubscription = resolve;
		});
		const unlisten = vi.fn();
		const cleanup = subscribe(subscribePromise);

		cleanup();
		expect(unlisten).not.toHaveBeenCalled();

		resolveSubscription(unlisten);
		await Promise.resolve();

		expect(unlisten).toHaveBeenCalledTimes(1);
	});

	it("calls unlisten immediately when cleanup is called after resolution", async () => {
		const unlisten = vi.fn();
		const subscribePromise = Promise.resolve(unlisten);
		const cleanup = subscribe(subscribePromise);

		await subscribePromise;
		expect(unlisten).not.toHaveBeenCalled();

		cleanup();
		expect(unlisten).toHaveBeenCalledTimes(1);
	});

	it("never calls unlisten twice when cleanup is triggered before and after resolution", async () => {
		let resolveSubscription!: (fn: UnlistenFn) => void;
		const subscribePromise = new Promise<UnlistenFn>((resolve) => {
			resolveSubscription = resolve;
		});
		const unlisten = vi.fn();
		const cleanup = subscribe(subscribePromise);

		cleanup();
		resolveSubscription(unlisten);
		await Promise.resolve();
		cleanup();

		expect(unlisten).toHaveBeenCalledTimes(1);
	});
});

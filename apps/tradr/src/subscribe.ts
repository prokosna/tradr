import type { UnlistenFn } from "@tauri-apps/api/event";

export function subscribe(subscribePromise: Promise<UnlistenFn>): () => void {
	let cancelled = false;
	let unlisten: UnlistenFn | undefined;
	subscribePromise.then((fn) => {
		if (cancelled) {
			fn();
		} else {
			unlisten = fn;
		}
	});
	return () => {
		cancelled = true;
		if (unlisten) {
			unlisten();
		}
	};
}

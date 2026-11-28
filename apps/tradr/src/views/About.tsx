import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { ReceiveServiceStatus } from "../types.js";

// "unknown" when the build had no git checkout to read.
const BUILD_COMMIT: string = __TRADR_COMMIT__;

export function About() {
	const [version, setVersion] = useState<string | null>(null);
	// undefined: still loading; null: desktop, which has no receive service.
	const [service, setService] = useState<
		ReceiveServiceStatus | null | undefined
	>(undefined);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		getVersion()
			.then(setVersion)
			.catch((e) => setError(String(e)));
		invoke<ReceiveServiceStatus | null>("plugin:tradr|receive_service_status")
			.then(setService)
			.catch((e) => setError(String(e)));
	}, []);

	return (
		<div className="stack">
			<p>
				Version {version ?? "…"} ({BUILD_COMMIT})
			</p>
			{service?.running === true && <p>Receiving in the background.</p>}
			{service?.running === false && (
				<p>
					Not receiving in the background. Files arrive only while Tradr is
					open.
				</p>
			)}
			{service?.running === false && service.error && (
				<p className="error-text">{service.error}</p>
			)}
			{error && <p className="error-text">{error}</p>}
		</div>
	);
}

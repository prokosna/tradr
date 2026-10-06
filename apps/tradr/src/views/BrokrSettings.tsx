import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";
import type { BrokrStatusDto } from "../types.js";

export interface BrokrSettingsProps {
	onStatusChange?: ((status: BrokrStatusDto) => void) | undefined;
}

export function BrokrSettings({ onStatusChange }: BrokrSettingsProps) {
	const [status, setStatus] = useState<BrokrStatusDto | null>(null);
	const [url, setUrl] = useState("");
	const [joinToken, setJoinToken] = useState("");
	const [actionError, setActionError] = useState<string | null>(null);
	const [isBusy, setIsBusy] = useState(false);

	const loadStatus = useCallback(() => {
		invoke<BrokrStatusDto>("plugin:tradr|brokr_status")
			.then((s) => {
				setStatus(s);
				onStatusChange?.(s);
			})
			.catch((e) => {
				setActionError(String(e));
			});
	}, [onStatusChange]);

	useEffect(() => {
		loadStatus();
	}, [loadStatus]);

	const handleConnect = async () => {
		if (!url.trim() || !joinToken.trim()) return;
		setIsBusy(true);
		setActionError(null);
		try {
			const updated = await invoke<BrokrStatusDto>("plugin:tradr|set_brokr", {
				url: url.trim(),
				joinToken: joinToken.trim(),
			});
			setStatus(updated);
			onStatusChange?.(updated);
			setJoinToken("");
		} catch (e) {
			setActionError(String(e));
		} finally {
			setIsBusy(false);
		}
	};

	const handleCheckNow = async () => {
		setIsBusy(true);
		setActionError(null);
		try {
			await invoke<void>("plugin:tradr|collect_brokr_now");
			const updated = await invoke<BrokrStatusDto>("plugin:tradr|brokr_status");
			setStatus(updated);
			onStatusChange?.(updated);
		} catch (e) {
			setActionError(String(e));
		} finally {
			setIsBusy(false);
		}
	};

	const handleDisconnect = async () => {
		setIsBusy(true);
		setActionError(null);
		try {
			await invoke<void>("plugin:tradr|clear_brokr");
			const updated: BrokrStatusDto = {
				configured: false,
				url: null,
				last_pass: null,
				delivered: 0,
				last_error: null,
			};
			setStatus(updated);
			onStatusChange?.(updated);
		} catch (e) {
			setActionError(String(e));
		} finally {
			setIsBusy(false);
		}
	};

	const lastCheckedText =
		status?.last_pass !== null && status?.last_pass !== undefined
			? `Last checked ${new Date(status.last_pass * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`
			: "Not checked yet";

	return (
		<div className="stack">
			<p className="muted">
				If you run a Tradr Brokr on your own network, Tradr can hold a file for
				a device that is switched off and deliver it when it's back.
			</p>

			{!status?.configured ? (
				<div className="stack">
					<label className="field">
						<span className="small">Brokr address</span>
						<input
							type="text"
							className="input"
							value={url}
							onChange={(e) => setUrl(e.target.value)}
							placeholder="http://192.168.1.50:8080"
						/>
					</label>
					<label className="field">
						<span className="small">Join token</span>
						<input
							type="password"
							className="input"
							value={joinToken}
							onChange={(e) => setJoinToken(e.target.value)}
						/>
					</label>
					<div>
						<button
							type="button"
							className="btn btn--primary"
							onClick={handleConnect}
							disabled={isBusy}
						>
							Connect
						</button>
					</div>
				</div>
			) : (
				<div className="stack">
					<div className="row brokr-settings-row">
						<div className="stack">
							<strong>{status.url}</strong>
							<span className="muted small">{lastCheckedText}</span>
						</div>
						<div className="row">
							<button
								type="button"
								className="btn"
								onClick={handleCheckNow}
								disabled={isBusy}
							>
								Check now
							</button>
							<button
								type="button"
								className="btn"
								onClick={handleDisconnect}
								disabled={isBusy}
							>
								Disconnect
							</button>
						</div>
					</div>

					{status.last_error && (
						<div className="stack">
							<p className="error-text">Couldn't reach the Brokr.</p>
							<p className="small muted">{status.last_error}</p>
						</div>
					)}
				</div>
			)}

			{actionError && <p className="error-text">{actionError}</p>}
		</div>
	);
}

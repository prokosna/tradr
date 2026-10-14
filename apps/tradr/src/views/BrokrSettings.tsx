import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useRef, useState } from "react";
import type { BrokrStatusDto } from "../types.js";

export interface BrokrSettingsProps {
	onStatusChange?: ((status: BrokrStatusDto) => void) | undefined;
}

export function BrokrSettings({ onStatusChange }: BrokrSettingsProps) {
	const [status, setStatus] = useState<BrokrStatusDto | null>(null);
	const [link, setLink] = useState("");
	const [url, setUrl] = useState("");
	const [joinToken, setJoinToken] = useState("");
	const [shownLink, setShownLink] = useState<string | null>(null);
	const [copyState, setCopyState] = useState<"idle" | "copied">("idle");
	const [copyError, setCopyError] = useState<string | null>(null);
	const [actionError, setActionError] = useState<string | null>(null);
	const [isBusy, setIsBusy] = useState(false);
	const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	useEffect(() => {
		return () => {
			if (copyTimerRef.current) {
				clearTimeout(copyTimerRef.current);
			}
		};
	}, []);

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
		const trimmedLink = link.trim();
		if (trimmedLink) {
			setIsBusy(true);
			setActionError(null);
			try {
				const updated = await invoke<BrokrStatusDto>(
					"plugin:tradr|connect_brokr_link",
					{ link: trimmedLink },
				);
				setStatus(updated);
				onStatusChange?.(updated);
				setLink("");
			} catch (e) {
				setActionError(String(e));
			} finally {
				setIsBusy(false);
			}
			return;
		}

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

	const handleToggleLink = async () => {
		if (shownLink !== null) {
			setShownLink(null);
			setCopyState("idle");
			setCopyError(null);
			if (copyTimerRef.current) {
				clearTimeout(copyTimerRef.current);
			}
			return;
		}
		setIsBusy(true);
		setActionError(null);
		try {
			const fetched = await invoke<string>("plugin:tradr|brokr_link");
			setShownLink(fetched);
			setCopyState("idle");
			setCopyError(null);
		} catch (e) {
			setActionError(String(e));
			setShownLink(null);
		} finally {
			setIsBusy(false);
		}
	};

	const handleCopyLink = () => {
		if (!shownLink) return;
		setCopyError(null);
		if (!navigator.clipboard?.writeText) {
			setCopyError("Couldn't copy. Select the link and copy it.");
			return;
		}
		try {
			navigator.clipboard
				.writeText(shownLink)
				.then(() => {
					setCopyState("copied");
					if (copyTimerRef.current) {
						clearTimeout(copyTimerRef.current);
					}
					copyTimerRef.current = setTimeout(() => {
						setCopyState("idle");
					}, 2000);
				})
				.catch(() => {
					setCopyError("Couldn't copy. Select the link and copy it.");
				});
		} catch {
			setCopyError("Couldn't copy. Select the link and copy it.");
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
			setShownLink(null);
			setCopyState("idle");
			setCopyError(null);
			if (copyTimerRef.current) {
				clearTimeout(copyTimerRef.current);
			}
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
						<span className="small">Brokr link</span>
						<input
							type="password"
							className="input"
							value={link}
							onChange={(e) => setLink(e.target.value)}
							placeholder="tradr://brokr?url=...&token=..."
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
					<details className="brokr-manual">
						<summary>Enter the address and token instead</summary>
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
						</div>
					</details>
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
							<button
								type="button"
								className="btn"
								onClick={handleToggleLink}
								disabled={isBusy}
							>
								{shownLink !== null ? "Hide link" : "Show link"}
							</button>
						</div>
					</div>

					{shownLink !== null && (
						<div className="stack">
							<div className="brokr-link-row">
								<input
									type="text"
									readOnly
									className="input"
									aria-label="Brokr link"
									value={shownLink}
								/>
								<button type="button" className="btn" onClick={handleCopyLink}>
									{copyState === "copied" ? "Copied" : "Copy"}
								</button>
							</div>
							{copyError && <p className="error-text">{copyError}</p>}
							<p className="small muted">
								Anyone with this link can add a device to your Brokr.
							</p>
						</div>
					)}

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

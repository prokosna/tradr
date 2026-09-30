import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";
import type { StaticPeerInfo } from "../types.js";

type StaticPeerListState =
	| { status: "loading" }
	| { status: "loaded"; entries: StaticPeerInfo[] }
	| { status: "error"; message: string };

type StaticPeerActionState =
	| { status: "idle" }
	| { status: "adding" }
	| { status: "removing"; id: string }
	| { status: "error"; message: string };

export function StaticPeers() {
	const [list, setList] = useState<StaticPeerListState>({ status: "loading" });
	const [name, setName] = useState("");
	const [address, setAddress] = useState("");
	const [action, setAction] = useState<StaticPeerActionState>({
		status: "idle",
	});

	const loadStaticPeers = useCallback(() => {
		invoke<StaticPeerInfo[]>("plugin:tradr|list_static_peers")
			.then((entries) => setList({ status: "loaded", entries }))
			.catch((error) => setList({ status: "error", message: String(error) }));
	}, []);

	useEffect(() => {
		loadStaticPeers();
	}, [loadStaticPeers]);

	const handleAdd = () => {
		const endpoints = address
			.split(",")
			.map((endpoint) => endpoint.trim())
			.filter((endpoint) => endpoint.length > 0);
		if (endpoints.length === 0) {
			setAction({
				status: "error",
				message: "Enter at least one endpoint.",
			});
			return;
		}
		const label = name.trim();
		setAction({ status: "adding" });
		invoke<string>("plugin:tradr|add_static_peer", {
			label: label.length > 0 ? label : null,
			endpoints,
		}).then(
			() => {
				setAction({ status: "idle" });
				setName("");
				setAddress("");
				loadStaticPeers();
			},
			(error) => {
				setAction({ status: "error", message: String(error) });
			},
		);
	};

	const handleRemove = (id: string) => {
		setAction({ status: "removing", id });
		invoke<void>("plugin:tradr|remove_static_peer", { id }).then(
			() => {
				setAction({ status: "idle" });
				loadStaticPeers();
			},
			(error) => {
				setAction({ status: "error", message: String(error) });
			},
		);
	};

	return (
		<div className="stack">
			<p className="muted">
				Use this for a device that isn't on the same network, such as one on
				your Tailscale network. Enter its name or address; add a port after a
				colon if it isn't 21820.
			</p>
			<div className="row">
				<label className="field">
					<span className="small">Name (optional)</span>
					<input
						type="text"
						className="input"
						value={name}
						onChange={(e) => setName(e.target.value)}
						placeholder="Home desktop"
					/>
				</label>
				<label className="field">
					<span className="small">Address</span>
					<input
						type="text"
						className="input"
						value={address}
						onChange={(e) => setAddress(e.target.value)}
						placeholder="desktop.tail9f3c.ts.net, 192.168.10.5:21820"
					/>
				</label>
				<button
					type="button"
					className="btn btn--primary"
					onClick={handleAdd}
					disabled={action.status === "adding"}
				>
					{action.status === "adding" ? "Adding…" : "Add device"}
				</button>
			</div>

			{action.status === "error" && (
				<p className="error-text">{action.message}</p>
			)}

			{list.status === "loading" && <p className="muted">Loading devices…</p>}
			{list.status === "error" && (
				<p className="error-text">Could not load devices: {list.message}</p>
			)}
			{list.status === "loaded" &&
				(list.entries.length === 0 ? (
					<p className="muted">No devices registered yet.</p>
				) : (
					<ul className="list">
						{list.entries.map((entry) => {
							const isRemoving =
								action.status === "removing" && action.id === entry.id;
							const displayName = entry.label || entry.endpoints[0] || entry.id;
							return (
								<li key={entry.id} className="list-item">
									<div className="row">
										<div className="stack">
											<strong>{displayName}</strong>
											<span className="muted small">
												Addresses: {entry.endpoints.join(", ")}
											</span>
										</div>
										<button
											type="button"
											className="btn"
											onClick={() => handleRemove(entry.id)}
											disabled={isRemoving}
										>
											{isRemoving ? "Removing…" : "Remove"}
										</button>
									</div>
								</li>
							);
						})}
					</ul>
				))}
		</div>
	);
}

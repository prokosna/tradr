import type { PeerInfo } from "../types.js";

export interface ReceivedItem {
	id: string;
	deviceId: string;
	fileName: string;
	receivedAt: Date;
}

export interface ReceivedCardProps {
	items: ReceivedItem[];
	peers: PeerInfo[];
}

export function ReceivedCard({ items, peers }: ReceivedCardProps) {
	return (
		<section className="card stack home-received">
			<h2 className="card-title">Received</h2>
			{items.length === 0 ? (
				<p className="muted">Files sent to this device appear here.</p>
			) : (
				<ul className="list">
					{items.map((item) => {
						const peer = peers.find((p) => p.device_id === item.deviceId);
						const deviceName = peer?.display_name || "another device";
						const timeStr = item.receivedAt.toLocaleTimeString([], {
							hour: "numeric",
							minute: "2-digit",
						});
						const name = item.fileName.split(/[/\\]/).pop() || item.fileName;

						return (
							<li key={item.id} className="file-row">
								<div className="file-row-content">
									<span className="file-icon">📄</span>
									<div className="file-details">
										<span className="file-name">{name}</span>
										<span className="file-meta muted">
											from {deviceName} · {timeStr}
										</span>
									</div>
								</div>
							</li>
						);
					})}
				</ul>
			)}
		</section>
	);
}

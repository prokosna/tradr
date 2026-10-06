import type { DeliveryDto } from "../types.js";

export interface DeliveriesCardProps {
	deliveries: DeliveryDto[];
}

function formatDeliveryState(delivery: DeliveryDto): string {
	if (delivery.state === "waiting") {
		return "Waiting";
	}
	if (delivery.state === "expired") {
		return "Expired";
	}
	if (delivery.state === "delivered") {
		const timestamp = delivery.collected_at ?? delivery.sent_at * 1000;
		const dateStr = new Date(timestamp).toLocaleDateString();
		return `Delivered ${dateStr}`;
	}
	return delivery.state;
}

function formatFileNames(names: string[]): string {
	if (names.length === 0) return "file";
	const firstName = names[0]?.split(/[/\\]/).pop() || names[0] || "file";
	const extra = names.length - 1;
	return extra > 0 ? `${firstName} +${extra} more` : firstName;
}

export function DeliveriesCard({ deliveries }: DeliveriesCardProps) {
	if (deliveries.length === 0) {
		return null;
	}

	const sorted = [...deliveries].sort((a, b) => b.sent_at - a.sent_at);

	return (
		<section className="card stack home-deliveries">
			<h2 className="card-title">Waiting to deliver</h2>
			<ul className="list">
				{sorted.map((delivery) => {
					const fileName = formatFileNames(delivery.names);
					const recipient = delivery.recipient_name
						? `to ${delivery.recipient_name}`
						: "to a device";
					const stateText = formatDeliveryState(delivery);

					return (
						<li key={delivery.id} className="file-row">
							<div className="file-row-content">
								<span className="file-icon">📦</span>
								<div className="file-details">
									<span className="file-name">{fileName}</span>
									<span className="file-meta muted">
										{recipient} · {stateText}
									</span>
								</div>
							</div>
						</li>
					);
				})}
			</ul>
		</section>
	);
}

import type { SignInUiState } from "../App.js";

export type SwitchPending = Extract<
	SignInUiState,
	{ status: "confirm_switch" }
>;

export interface SwitchConfirmProps {
	pending: SwitchPending;
	onConfirm: () => void;
	onCancel: () => void;
}

function plural(count: number, one: string, many: string): string {
	return `${count} ${count === 1 ? one : many}`;
}

export function SwitchConfirm({
	pending,
	onConfirm,
	onCancel,
}: SwitchConfirmProps) {
	const items: string[] = [];
	if (pending.links > 0) {
		items.push(plural(pending.links, "linked account", "linked accounts"));
	}
	if (pending.brokr) {
		items.push("the offline delivery connection");
	}
	if (pending.knownDevices > 0) {
		items.push(plural(pending.knownDevices, "known device", "known devices"));
	}
	return (
		<div className="stack">
			{items.length > 0 ? (
				<div>
					<p>
						This is a different Google account. Switching removes what this
						device set up with the previous one:
					</p>
					<ul>
						{items.map((item) => (
							<li key={item}>{item}</li>
						))}
					</ul>
				</div>
			) : (
				<p>This is a different Google account.</p>
			)}
			<div className="inline-form">
				<button type="button" className="btn btn--danger" onClick={onConfirm}>
					Switch account
				</button>
				<button type="button" className="btn btn--ghost" onClick={onCancel}>
					Keep current account
				</button>
			</div>
		</div>
	);
}

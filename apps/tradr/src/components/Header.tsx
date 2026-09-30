export interface HeaderProps {
	status: string;
	onOpenSettings: () => void;
}

function formatStatus(status: string): string {
	if (status === "signed_in") {
		return "Signed in";
	}
	if (status === "signing_in") {
		return "Signing in…";
	}
	return "Not signed in";
}

export function Header({ status, onOpenSettings }: HeaderProps) {
	return (
		<header className="app-header">
			<div className="row">
				<h1 className="app-title">Tradr</h1>
				<span className="app-status">{formatStatus(status)}</span>
			</div>
			<button
				type="button"
				className="btn btn--icon"
				aria-label="Settings"
				onClick={onOpenSettings}
			>
				⚙
			</button>
		</header>
	);
}

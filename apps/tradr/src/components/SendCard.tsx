import type { TransferProgressPayload } from "../types.js";

export interface StagedFile {
	name: string;
	size?: number;
	cachePath: string | null;
	adoptedId: string | null;
}

export interface ActiveSendInfo {
	peerKey: string;
	targetName: string;
	files: StagedFile[];
}

export interface SendCardProps {
	files: StagedFile[];
	isSending: boolean;
	activeSend: ActiveSendInfo | null;
	progress: TransferProgressPayload | null;
	error: string | null;
	onSelectFiles: () => void;
	onClear: () => void;
}

function formatBytes(bytes: number): string {
	if (bytes === 0) return "0 B";
	const k = 1024;
	const sizes = ["B", "KiB", "MiB", "GiB"];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	const formatted = (bytes / k ** i).toFixed(1);
	return `${formatted} ${sizes[i]}`;
}

export function SendCard({
	files,
	isSending,
	activeSend,
	progress,
	error,
	onSelectFiles,
	onClear,
}: SendCardProps) {
	const hasWaiting = files.length > 0;

	return (
		<section className="card stack home-send">
			<h2 className="card-title">Send files</h2>

			{!hasWaiting && !isSending ? (
				<div className="dropzone">
					<p className="muted">Drop files here, or</p>
					<button
						type="button"
						className="btn btn--primary"
						onClick={onSelectFiles}
					>
						Select files
					</button>
				</div>
			) : (
				<div className="stack">
					<div className="chips">
						{files.map((file) => {
							const key =
								file.adoptedId !== null
									? `adopted-${file.adoptedId}`
									: (file.cachePath ?? file.name);
							return (
								<span key={key} className="chip">
									<span className="chip-name">{file.name}</span>
									{file.size !== undefined && file.size > 0 && (
										<span className="chip-size muted">
											{formatBytes(file.size)}
										</span>
									)}
								</span>
							);
						})}
					</div>

					<div className="row">
						<span>
							{files.length} {files.length === 1 ? "file" : "files"}
						</span>
						<button
							type="button"
							className="btn btn--ghost"
							onClick={onClear}
							disabled={isSending}
						>
							Clear
						</button>
					</div>

					{isSending && activeSend ? (
						<div className="stack">
							<p>Sending to {activeSend.targetName}…</p>
							{progress && (
								<div className="stack">
									<span className="small muted">
										{progress.rel_path} ·{" "}
										{progress.total_bytes > 0
											? Math.round(
													(progress.bytes_transferred / progress.total_bytes) *
														100,
												)
											: 0}
										%
									</span>
									<div className="progress">
										<progress
											className="progress-bar"
											value={progress.bytes_transferred}
											max={progress.total_bytes || 1}
										/>
									</div>
								</div>
							)}
						</div>
					) : (
						<p className="muted">Choose a device to send to.</p>
					)}
				</div>
			)}

			{error && (
				<div className="stack">
					<p className="error-text">Couldn't send.</p>
					<p className="small muted">{error}</p>
				</div>
			)}
		</section>
	);
}

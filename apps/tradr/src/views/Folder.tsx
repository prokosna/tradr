import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import type {
	DirListingDto,
	FileEntryDto,
	ShareInfo,
	SharedFilePayload,
} from "../types.js";

export interface FolderProps {
	peerKey: string;
	peerName: string;
	onBack: () => void;
}

interface StagedAdoptedFile {
	id: string;
	name: string;
}

type BrowseState =
	| { status: "loading" }
	| { status: "loaded"; listing: DirListingDto }
	| { status: "error"; message: string };

function stagePayloads(files: SharedFilePayload[]): {
	paths: string[];
	adoptedIds: StagedAdoptedFile[];
	refused: string[];
} {
	const paths: string[] = [];
	const adoptedIds: StagedAdoptedFile[] = [];
	const refused: string[] = [];
	for (const file of files) {
		if (file.adoptedId !== null) {
			adoptedIds.push({ id: file.adoptedId, name: file.name });
		} else if (file.cachePath !== null) {
			paths.push(file.cachePath);
		} else {
			refused.push(file.name);
		}
	}
	return { paths, adoptedIds, refused };
}

function formatBytes(bytes: number): string {
	if (bytes === 0) return "0 B";
	const k = 1000;
	const sizes = ["B", "KB", "MB", "GB", "TB"];
	const i = Math.min(
		Math.floor(Math.log(bytes) / Math.log(k)),
		sizes.length - 1,
	);
	const formatted = (bytes / k ** i).toFixed(1);
	return `${formatted} ${sizes[i]}`;
}

export function Folder({ peerKey, peerName, onBack }: FolderProps) {
	const [shareId, setShareId] = useState<string | null>(null);
	const [sharesLoaded, setSharesLoaded] = useState(false);
	const [browsePath, setBrowsePath] = useState("");
	const [browseState, setBrowseState] = useState<BrowseState>({
		status: "loading",
	});
	const [browseOpRunning, setBrowseOpRunning] = useState(false);
	const [browseError, setBrowseError] = useState<string | null>(null);
	const [downloadSuccess, setDownloadSuccess] = useState<
		Record<string, string>
	>({});
	const [showNewFolder, setShowNewFolder] = useState(false);
	const [newFolderName, setNewFolderName] = useState("");
	const [renamingEntry, setRenamingEntry] = useState<string | null>(null);
	const [renameValue, setRenameValue] = useState("");
	const [deletingEntry, setDeletingEntry] = useState<string | null>(null);
	const [openMenuEntry, setOpenMenuEntry] = useState<string | null>(null);

	const downloadTimersRef = useRef<ReturnType<typeof setTimeout>[]>([]);

	const isBusy = browseOpRunning || browseState.status === "loading";

	const buildEntryPath = useCallback(
		(name: string) => (browsePath ? `${browsePath}/${name}` : name),
		[browsePath],
	);

	const fetchDirectory = useCallback(
		(currentShareId: string, path: string, cursor = "") => {
			setBrowseError(null);
			setBrowseState({ status: "loading" });
			invoke<DirListingDto>("plugin:tradr|list_peer_directory", {
				peerId: peerKey,
				shareId: currentShareId,
				path: path,
				cursor: cursor,
				limit: 200,
			})
				.then((listing) => {
					setBrowseState({ status: "loaded", listing });
				})
				.catch((error) => {
					const msg = String(error);
					setBrowseState({ status: "error", message: msg });
					setBrowseError(msg);
				});
		},
		[peerKey],
	);

	useEffect(() => {
		let cancelled = false;
		setBrowseError(null);
		setBrowseState({ status: "loading" });
		invoke<ShareInfo[]>("plugin:tradr|get_visible_shares", { peerId: peerKey })
			.then((fetchedShares) => {
				if (cancelled) return;
				setSharesLoaded(true);
				if (fetchedShares.length > 0 && fetchedShares[0]) {
					const sid = fetchedShares[0].shareId;
					setShareId(sid);
					fetchDirectory(sid, "");
				} else {
					setShareId(null);
					setBrowseState({
						status: "loaded",
						listing: { entries: [], nextCursor: "", totalEstimate: 0 },
					});
				}
			})
			.catch((e) => {
				if (cancelled) return;
				setSharesLoaded(true);
				setShareId(null);
				const msg = String(e);
				setBrowseError(msg);
				setBrowseState({ status: "error", message: msg });
			});

		return () => {
			cancelled = true;
		};
	}, [peerKey, fetchDirectory]);

	useEffect(() => {
		const timers = downloadTimersRef.current;
		return () => {
			for (const t of timers) {
				clearTimeout(t);
			}
		};
	}, []);

	const handleNavigate = (newPath: string) => {
		if (!shareId) return;
		setBrowseError(null);
		setRenamingEntry(null);
		setDeletingEntry(null);
		setOpenMenuEntry(null);
		setBrowsePath(newPath);
		fetchDirectory(shareId, newPath);
	};

	const handleBreadcrumbClick = (index: number) => {
		if (index === -1) {
			handleNavigate("");
		} else {
			const parts = browsePath.split("/").filter(Boolean);
			const newPath = parts.slice(0, index + 1).join("/");
			handleNavigate(newPath);
		}
	};

	const handleDownloadFile = async (entryName: string) => {
		if (!shareId) return;
		setBrowseError(null);
		setBrowseOpRunning(true);
		const entryPath = buildEntryPath(entryName);
		try {
			const placedAt = await invoke<string>("plugin:tradr|download_file", {
				peerId: peerKey,
				shareId: shareId,
				path: entryPath,
			});
			const placedName = placedAt.split(/[/\\]/).pop() || placedAt;
			setDownloadSuccess((prev) => ({
				...prev,
				[entryName]: placedName,
			}));
			const timerId = setTimeout(() => {
				setDownloadSuccess((prev) => {
					const next = { ...prev };
					delete next[entryName];
					return next;
				});
			}, 4000);
			downloadTimersRef.current.push(timerId);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleStartRename = (name: string) => {
		setBrowseError(null);
		setDeletingEntry(null);
		setRenamingEntry(name);
		setRenameValue(name);
		setOpenMenuEntry(null);
	};

	const handleCancelRename = () => {
		setRenamingEntry(null);
		setRenameValue("");
	};

	const handleSaveRename = async (oldName: string) => {
		if (!shareId) return;
		const trimmed = renameValue.trim();
		if (!trimmed) return;
		if (trimmed === oldName) {
			setRenamingEntry(null);
			setRenameValue("");
			return;
		}
		setBrowseError(null);
		setBrowseOpRunning(true);
		const from = buildEntryPath(oldName);
		const to = buildEntryPath(trimmed);
		try {
			await invoke<void>("plugin:tradr|rename_peer_entry", {
				peerId: peerKey,
				shareId: shareId,
				from,
				to,
			});
			setRenamingEntry(null);
			setRenameValue("");
			fetchDirectory(shareId, browsePath);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleStartDelete = (name: string) => {
		setBrowseError(null);
		setRenamingEntry(null);
		setDeletingEntry(name);
	};

	const handleCancelDelete = () => {
		setDeletingEntry(null);
	};

	const handleConfirmDelete = async (entry: FileEntryDto) => {
		if (!shareId) return;
		setBrowseError(null);
		setBrowseOpRunning(true);
		const targetPath = buildEntryPath(entry.name);
		try {
			await invoke<void>("plugin:tradr|delete_peer_entry", {
				peerId: peerKey,
				shareId: shareId,
				path: targetPath,
				recursive: entry.kind === "directory",
			});
			setDeletingEntry(null);
			setOpenMenuEntry(null);
			fetchDirectory(shareId, browsePath);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleCancelNewFolder = () => {
		setShowNewFolder(false);
		setNewFolderName("");
	};

	const handleMakeDirectory = async () => {
		if (!shareId) return;
		const trimmed = newFolderName.trim();
		if (!trimmed) return;
		setBrowseError(null);
		setBrowseOpRunning(true);
		const targetPath = buildEntryPath(trimmed);
		try {
			await invoke<void>("plugin:tradr|make_peer_directory", {
				peerId: peerKey,
				shareId: shareId,
				path: targetPath,
			});
			setNewFolderName("");
			setShowNewFolder(false);
			fetchDirectory(shareId, browsePath);
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleUploadFiles = async () => {
		if (!shareId) return;
		setBrowseError(null);
		setBrowseOpRunning(true);
		try {
			let uploadFiles: string[] = [];
			let uploadAdoptedIds: string[] = [];

			const picked = await invoke<SharedFilePayload[] | null>(
				"plugin:tradr|pick_files_to_send",
			);
			if (picked === null) {
				const selected = await open({
					multiple: true,
				});
				if (Array.isArray(selected) && selected.length > 0) {
					uploadFiles = selected;
				} else if (typeof selected === "string") {
					uploadFiles = [selected];
				}
			} else if (picked.length > 0) {
				const { paths, adoptedIds, refused } = stagePayloads(picked);
				if (refused.length > 0) {
					setBrowseError(`Could not read files: ${refused.join(", ")}`);
				}
				uploadFiles = paths;
				uploadAdoptedIds = adoptedIds.map((a) => a.id);
			}

			if (uploadFiles.length > 0 || uploadAdoptedIds.length > 0) {
				await invoke<string[]>("plugin:tradr|upload_to_peer", {
					peerId: peerKey,
					shareId: shareId,
					destDir: browsePath,
					files: uploadFiles,
					adoptedIds: uploadAdoptedIds,
				});
				fetchDirectory(shareId, browsePath);
			}
		} catch (error) {
			setBrowseError(String(error));
		} finally {
			setBrowseOpRunning(false);
		}
	};

	const handleRowClick = (
		e: React.MouseEvent<HTMLLIElement>,
		entry: FileEntryDto,
	) => {
		if (
			entry.kind !== "directory" ||
			renamingEntry === entry.name ||
			deletingEntry === entry.name
		) {
			return;
		}
		const target = e.target as HTMLElement | null;
		if (target?.closest("button, input")) {
			return;
		}
		handleNavigate(buildEntryPath(entry.name));
	};

	const handleRowKeyDown = (
		e: React.KeyboardEvent<HTMLLIElement>,
		entry: FileEntryDto,
	) => {
		if (
			entry.kind !== "directory" ||
			renamingEntry === entry.name ||
			deletingEntry === entry.name
		) {
			return;
		}
		if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) {
			e.preventDefault();
			handleNavigate(buildEntryPath(entry.name));
		}
	};

	const pathSegments = browsePath.split("/").filter(Boolean);

	return (
		<div className="card stack">
			<div className="page-header">
				<button type="button" className="btn" onClick={onBack}>
					Back
				</button>
				<h2>{peerName}</h2>
			</div>

			{shareId && (
				<nav className="breadcrumb" aria-label="Breadcrumb">
					{pathSegments.length === 0 ? (
						<span className="crumb crumb--current">{peerName}</span>
					) : (
						<>
							<button
								type="button"
								className="crumb crumb--link"
								onClick={() => handleBreadcrumbClick(-1)}
								disabled={isBusy}
							>
								{peerName}
							</button>
							<span className="crumb-separator">/</span>
							{pathSegments.map((seg, idx) => {
								const isLast = idx === pathSegments.length - 1;
								return (
									<span
										key={pathSegments.slice(0, idx + 1).join("/")}
										className="crumb"
									>
										{isLast ? (
											<span className="crumb--current">{seg}</span>
										) : (
											<>
												<button
													type="button"
													className="crumb crumb--link"
													onClick={() => handleBreadcrumbClick(idx)}
													disabled={isBusy}
												>
													{seg}
												</button>
												<span className="crumb-separator">/</span>
											</>
										)}
									</span>
								);
							})}
						</>
					)}
				</nav>
			)}

			{shareId && (
				<div className="toolbar">
					<button
						type="button"
						className="btn btn--primary"
						onClick={handleUploadFiles}
						disabled={isBusy}
					>
						Upload
					</button>
					{!showNewFolder ? (
						<button
							type="button"
							className="btn btn--ghost"
							onClick={() => {
								setBrowseError(null);
								setShowNewFolder(true);
							}}
							disabled={isBusy}
						>
							New folder
						</button>
					) : (
						<div className="inline-form">
							<input
								type="text"
								className="input"
								placeholder="Folder name"
								value={newFolderName}
								onChange={(e) => setNewFolderName(e.target.value)}
								disabled={isBusy}
								onKeyDown={(e) => {
									if (e.key === "Enter") {
										handleMakeDirectory();
									} else if (e.key === "Escape") {
										handleCancelNewFolder();
									}
								}}
							/>
							<button
								type="button"
								className="btn btn--primary"
								onClick={handleMakeDirectory}
								disabled={isBusy || !newFolderName.trim()}
							>
								Create
							</button>
							<button
								type="button"
								className="btn btn--ghost"
								onClick={handleCancelNewFolder}
								disabled={isBusy}
							>
								Cancel
							</button>
						</div>
					)}
				</div>
			)}

			{browseError && <div className="notice notice--error">{browseError}</div>}

			{!sharesLoaded || browseState.status === "loading" ? (
				<p className="muted">Loading…</p>
			) : !shareId ? (
				!browseError && (
					<p className="muted">This device isn't sharing a folder.</p>
				)
			) : browseState.status === "loaded" ? (
				browseState.listing.entries.length === 0 ? (
					<p className="muted">This folder is empty.</p>
				) : (
					<ul className="list">
						{browseState.listing.entries.map((entry) => (
							<li
								key={entry.name}
								className={`file-row ${
									entry.kind === "directory" ? "file-row--folder" : ""
								}`}
								role={entry.kind === "directory" ? "button" : undefined}
								tabIndex={entry.kind === "directory" ? 0 : undefined}
								onClick={(e) => handleRowClick(e, entry)}
								onKeyDown={(e) => handleRowKeyDown(e, entry)}
							>
								<div className="file-row-content">
									<span className="file-icon">
										{entry.kind === "directory" ? "📁" : "📄"}
									</span>

									{renamingEntry === entry.name ? (
										<div className="inline-form file-rename-form">
											<input
												type="text"
												className="input"
												value={renameValue}
												onChange={(e) => setRenameValue(e.target.value)}
												disabled={isBusy}
												onKeyDown={(e) => {
													if (e.key === "Enter") {
														handleSaveRename(entry.name);
													} else if (e.key === "Escape") {
														handleCancelRename();
													}
												}}
											/>
											<button
												type="button"
												className="btn btn--primary"
												onClick={() => handleSaveRename(entry.name)}
												disabled={isBusy || !renameValue.trim()}
											>
												Save
											</button>
											<button
												type="button"
												className="btn btn--ghost"
												onClick={handleCancelRename}
												disabled={isBusy}
											>
												Cancel
											</button>
										</div>
									) : (
										<>
											<div className="file-details">
												<span className="file-name">{entry.name}</span>
												{entry.kind === "file" && (
													<span className="file-meta">
														{formatBytes(entry.sizeBytes)} ·{" "}
														{new Date(
															entry.modified * 1000,
														).toLocaleDateString()}
													</span>
												)}
											</div>

											<div className="file-actions">
												{deletingEntry === entry.name ? (
													<div className="inline-form file-delete-confirm">
														<span className="file-delete-prompt">Delete?</span>
														<button
															type="button"
															className="btn btn--danger"
															onClick={() => handleConfirmDelete(entry)}
															disabled={isBusy}
														>
															Delete
														</button>
														<button
															type="button"
															className="btn btn--ghost"
															onClick={handleCancelDelete}
															disabled={isBusy}
														>
															Cancel
														</button>
													</div>
												) : (
													<>
														<button
															type="button"
															className="btn btn--ghost file-actions-menu-btn"
															onClick={() =>
																setOpenMenuEntry(
																	openMenuEntry === entry.name
																		? null
																		: entry.name,
																)
															}
															disabled={isBusy}
															aria-label="Actions"
														>
															⋯
														</button>
														<div
															className={`file-actions-group ${
																openMenuEntry === entry.name ? "is-open" : ""
															}`}
														>
															{entry.kind === "file" && (
																<button
																	type="button"
																	className="btn btn--ghost"
																	onClick={() => handleDownloadFile(entry.name)}
																	disabled={isBusy}
																>
																	Download
																</button>
															)}
															<button
																type="button"
																className="btn btn--ghost"
																onClick={() => handleStartRename(entry.name)}
																disabled={isBusy}
															>
																Rename
															</button>
															<button
																type="button"
																className="btn btn--ghost"
																onClick={() => handleStartDelete(entry.name)}
																disabled={isBusy}
															>
																Delete
															</button>
														</div>
													</>
												)}
											</div>
										</>
									)}
								</div>

								{downloadSuccess[entry.name] && (
									<div className="notice notice--success file-notice">
										Saved to Downloads as {downloadSuccess[entry.name]}.
									</div>
								)}
							</li>
						))}
					</ul>
				)
			) : null}
		</div>
	);
}

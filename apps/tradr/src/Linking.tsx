import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { QRCodeSVG } from "qrcode.react";
import { type ChangeEvent, useCallback, useEffect, useState } from "react";

interface LinkInviteDto {
	blob: string;
	fingerprint: string[];
}

interface LinkProposalDto {
	peer_iss: string;
	peer_sub: string;
	peer_fingerprint: string[];
	peer_label: string | null;
	link_id: string;
}

interface LinkDto {
	link_id: string;
	peer_iss: string;
	peer_sub: string;
	peer_label: string | null;
	created_at: number;
}

interface LinkInvitePreviewDto {
	peer_fingerprint: string[];
	expired: boolean;
}

interface LinkReplyDto {
	linked: boolean;
	link_id: string | null;
	decline_reason: string | null;
	// Read at the pause already; showing it again after the exchange would
	// be the comparison DCR-077 moved consent away from (docs/11).
	peer_fingerprint: string[];
}

type InviteState =
	| { status: "idle" }
	| { status: "loading" }
	| { status: "loaded"; invite: LinkInviteDto }
	| { status: "error"; message: string };

type ProposalState =
	| { status: "idle" }
	| { status: "loading" }
	| { status: "loaded"; proposal: LinkProposalDto }
	| { status: "answering"; proposal: LinkProposalDto }
	| { status: "error"; message: string };

type LinksState =
	| { status: "loading" }
	| { status: "loaded"; links: LinkDto[] }
	| { status: "error"; message: string };

type RemoveState =
	| { status: "idle" }
	| { status: "removing"; linkId: string }
	| { status: "error"; message: string };

type ReplyState =
	| { status: "idle" }
	| { status: "previewing" }
	| { status: "previewed"; blob: string; preview: LinkInvitePreviewDto }
	| { status: "replying"; blob: string; preview: LinkInvitePreviewDto }
	| { status: "done"; outcome: LinkReplyDto }
	| { status: "error"; message: string };

function declineReasonText(reason: string | null): string {
	switch (reason) {
		case "user-declined":
			return "The other device's holder declined.";
		case "invite-expired":
			return "The invite expired before the other device's holder answered.";
		case "verification-failed":
			return "The other device could not verify this device's Attestation.";
		case null:
			return "The other device declined and gave no reason.";
		default:
			// docs/11: an unrecognised reason is dropped and the decline still stands.
			return reason;
	}
}

function formatTimestamp(timestampSecs: number): string {
	if (!timestampSecs) return "-";
	const date = new Date(timestampSecs * 1000);
	return date.toLocaleString();
}

function chunkFingerprint(words: string[]) {
	const rows = [];
	for (let r = 0; r < 3; r++) {
		const rowWords = [];
		for (let c = 0; c < 4; c++) {
			const pos = r * 4 + c;
			const word = words[pos] || "";
			rowWords.push({ id: `w-${pos}-${word}`, word });
		}
		rows.push({ id: `r-${r}`, words: rowWords });
	}
	return rows;
}

function LinkReplier({ onLinked }: { onLinked: () => void }) {
	const [state, setState] = useState<ReplyState>({ status: "idle" });
	const [blobText, setBlobText] = useState("");

	const handleBlobChange = useCallback(
		(e: ChangeEvent<HTMLTextAreaElement>) => {
			setBlobText(e.target.value);
			// The preview must never stand beside changed text (docs/11, DCR-078).
			setState((prev) => (prev.status === "idle" ? prev : { status: "idle" }));
		},
		[],
	);

	const handleCheckInvite = useCallback(() => {
		const blob = blobText;
		setState({ status: "previewing" });
		invoke<LinkInvitePreviewDto>("plugin:tradr|preview_link_invite", {
			blob,
		})
			.then((preview) => {
				setState({ status: "previewed", blob, preview });
			})
			.catch((e) => {
				setState({ status: "error", message: String(e) });
			});
	}, [blobText]);

	const handleSendReply = useCallback(() => {
		if (state.status !== "previewed") return;
		const { blob, preview } = state;
		setState({ status: "replying", blob, preview });
		// The reply must carry the blob the pause previewed, never the
		// textarea's current value -- that is the whole of DCR-078 (docs/11).
		invoke<LinkReplyDto>("plugin:tradr|reply_to_link_invite", { blob })
			.then((outcome) => {
				setState({ status: "done", outcome });
				if (outcome.linked) {
					onLinked();
				}
			})
			.catch((e) => {
				setState({ status: "error", message: String(e) });
			});
	}, [state, onLinked]);

	const pause =
		state.status === "previewed" || state.status === "replying"
			? state.preview
			: null;

	return (
		<div style={{ marginTop: "1.5rem" }}>
			<h3>Reply to an invite</h3>
			<textarea
				rows={6}
				cols={80}
				placeholder="Paste an invite blob here"
				value={blobText}
				onChange={handleBlobChange}
				disabled={state.status === "previewing" || state.status === "replying"}
			/>
			<div style={{ marginTop: "0.5rem" }}>
				<button
					type="button"
					onClick={handleCheckInvite}
					disabled={
						blobText.trim().length === 0 ||
						state.status === "previewing" ||
						state.status === "replying"
					}
				>
					{state.status === "previewing" ? "Checking..." : "Check invite"}
				</button>
			</div>
			{pause && (
				<div style={{ marginTop: "1rem" }}>
					<div style={{ fontFamily: "monospace" }}>
						{chunkFingerprint(pause.peer_fingerprint).map((row) => (
							<div key={row.id} style={{ display: "flex", gap: "1rem" }}>
								{row.words.map((item) => (
									<span key={item.id}>{item.word}</span>
								))}
							</div>
						))}
					</div>
					<p style={{ fontSize: "0.9em", color: "#444" }}>
						Read these words against the other device's screen and continue only
						if all twelve match.
					</p>
					{pause.expired && (
						<p style={{ color: "red" }}>
							This device's clock reads the invite as already expired; the
							inviter will probably refuse the reply.
						</p>
					)}
					{state.status === "previewed" && (
						<button type="button" onClick={handleSendReply}>
							Send reply
						</button>
					)}
					{state.status === "replying" && <p>Sending reply...</p>}
				</div>
			)}
			{state.status === "done" && (
				<div style={{ marginTop: "1rem" }}>
					{state.outcome.linked ? (
						<p>
							This link is now held by both sides:{" "}
							<span style={{ fontFamily: "monospace" }}>
								{state.outcome.link_id}
							</span>
						</p>
					) : (
						<p>{declineReasonText(state.outcome.decline_reason)}</p>
					)}
				</div>
			)}
			{state.status === "error" && (
				<p style={{ color: "red" }}>{state.message}</p>
			)}
		</div>
	);
}

export function Linking() {
	const [inviteState, setInviteState] = useState<InviteState>({
		status: "idle",
	});
	const [proposalState, setProposalState] = useState<ProposalState>({
		status: "idle",
	});
	const [linksState, setLinksState] = useState<LinksState>({
		status: "loading",
	});
	const [removeState, setRemoveState] = useState<RemoveState>({
		status: "idle",
	});

	const fetchLinks = useCallback(() => {
		invoke<LinkDto[]>("plugin:tradr|list_links")
			.then((links) => {
				setLinksState({ status: "loaded", links });
			})
			.catch((e) => {
				setLinksState({ status: "error", message: String(e) });
			});
	}, []);

	useEffect(() => {
		let unlistenProposal: UnlistenFn | undefined;
		let disposed = false;

		listen<LinkProposalDto>("link-proposal", (event) => {
			// The exchange already took the invite out of the window.
			setInviteState({ status: "idle" });
			setProposalState({ status: "loaded", proposal: event.payload });
		}).then((unlisten) => {
			if (disposed) {
				unlisten();
			} else {
				unlistenProposal = unlisten;
			}
		});

		invoke<LinkProposalDto | null>("plugin:tradr|pending_link_proposal")
			.then((pending) => {
				if (disposed) return;
				if (pending) {
					// The exchange already took the invite out of the window.
					setInviteState({ status: "idle" });
					setProposalState({ status: "loaded", proposal: pending });
				}
			})
			.catch((e) => {
				if (disposed) return;
				setProposalState({ status: "error", message: String(e) });
			});

		fetchLinks();

		return () => {
			disposed = true;
			if (unlistenProposal) {
				unlistenProposal();
			}
		};
	}, [fetchLinks]);

	const handleOpenInvite = useCallback(() => {
		setInviteState({ status: "loading" });
		invoke<LinkInviteDto>("plugin:tradr|open_link_invite")
			.then((invite) => {
				setInviteState({ status: "loaded", invite });
			})
			.catch((e) => {
				setInviteState({ status: "error", message: String(e) });
			});
	}, []);

	const handleApprove = useCallback(() => {
		setProposalState((prev) =>
			prev.status === "loaded"
				? { status: "answering", proposal: prev.proposal }
				: prev,
		);
		invoke("plugin:tradr|approve_link")
			.then(() => {
				setProposalState({ status: "idle" });
				fetchLinks();
			})
			.catch((e) => {
				setProposalState({ status: "error", message: String(e) });
			});
	}, [fetchLinks]);

	const handleDecline = useCallback(() => {
		setProposalState((prev) =>
			prev.status === "loaded"
				? { status: "answering", proposal: prev.proposal }
				: prev,
		);
		invoke("plugin:tradr|decline_link")
			.then(() => {
				setProposalState({ status: "idle" });
			})
			.catch((e) => {
				setProposalState({ status: "error", message: String(e) });
			});
	}, []);

	const handleRemove = useCallback(
		(linkId: string) => {
			setRemoveState({ status: "removing", linkId });
			invoke("plugin:tradr|remove_link", { linkId })
				.then(() => {
					setRemoveState({ status: "idle" });
					fetchLinks();
				})
				.catch((e) => {
					setRemoveState({ status: "error", message: String(e) });
				});
		},
		[fetchLinks],
	);

	return (
		<div>
			<div>
				<button
					type="button"
					onClick={handleOpenInvite}
					disabled={inviteState.status === "loading"}
				>
					{inviteState.status === "loading"
						? "Opening invite..."
						: "Show link invite"}
				</button>
				{inviteState.status === "error" && (
					<p style={{ color: "red" }}>{inviteState.message}</p>
				)}
				{inviteState.status === "loaded" && (
					<div style={{ marginTop: "1rem" }}>
						<p>
							This invite is single-use and short-lived; show a fresh one if a
							link does not complete.
						</p>
						{inviteState.invite.blob.length <= 2953 ? (
							// docs/11: QR byte mode holds 2953 bytes at error-correction level L.
							<QRCodeSVG value={inviteState.invite.blob} level="L" size={320} />
						) : (
							<p>
								This invite is too large for a QR code and must be handed over
								by pasting the blob below.
							</p>
						)}
						<div
							style={{
								display: "flex",
								gap: "1.5rem",
								alignItems: "center",
								marginTop: "1rem",
								flexWrap: "wrap",
							}}
						>
							<div style={{ fontFamily: "monospace" }}>
								{chunkFingerprint(inviteState.invite.fingerprint).map((row) => (
									<div key={row.id} style={{ display: "flex", gap: "1rem" }}>
										{row.words.map((item) => (
											<span key={item.id}>{item.word}</span>
										))}
									</div>
								))}
							</div>
							<p>
								These are the words the other device's holder must read back.
							</p>
						</div>
						<div style={{ marginTop: "1rem" }}>
							<textarea
								readOnly
								rows={6}
								cols={80}
								value={inviteState.invite.blob}
							/>
						</div>
					</div>
				)}
			</div>

			{(proposalState.status === "loaded" ||
				proposalState.status === "answering") && (
				<div
					style={{
						marginTop: "1.5rem",
						padding: "1rem",
						border: "1px solid #ddd",
						borderRadius: "4px",
					}}
				>
					<h3>Pending Link Proposal</h3>
					<p>
						<strong>Account:</strong> {proposalState.proposal.peer_sub} (
						{proposalState.proposal.peer_iss})
					</p>
					{proposalState.proposal.peer_label && (
						<p>
							<strong>Label:</strong> {proposalState.proposal.peer_label}
						</p>
					)}
					<p>
						<strong>Link ID:</strong> {proposalState.proposal.link_id}
					</p>
					<div>
						<strong>Replier Fingerprint:</strong>
						<div
							style={{
								fontFamily: "monospace",
								marginTop: "0.25rem",
								marginBottom: "0.5rem",
							}}
						>
							{chunkFingerprint(proposalState.proposal.peer_fingerprint).map(
								(row) => (
									<div key={row.id} style={{ display: "flex", gap: "1rem" }}>
										{row.words.map((item) => (
											<span key={item.id}>{item.word}</span>
										))}
									</div>
								),
							)}
						</div>
						<p style={{ fontSize: "0.9em", color: "#444" }}>
							Read these words aloud against the other device's screen and
							approve only if all twelve match.
						</p>
					</div>
					<div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}>
						<button
							type="button"
							onClick={handleApprove}
							disabled={proposalState.status === "answering"}
						>
							{proposalState.status === "answering"
								? "Approving..."
								: "Approve"}
						</button>
						<button
							type="button"
							onClick={handleDecline}
							disabled={proposalState.status === "answering"}
						>
							{proposalState.status === "answering"
								? "Declining..."
								: "Decline"}
						</button>
					</div>
				</div>
			)}
			{proposalState.status === "error" && (
				<p style={{ color: "red" }}>{proposalState.message}</p>
			)}

			<LinkReplier onLinked={fetchLinks} />

			<div style={{ marginTop: "1.5rem" }}>
				<h3>Links</h3>
				{removeState.status === "error" && (
					<p style={{ color: "red" }}>{removeState.message}</p>
				)}
				{linksState.status === "loading" && <p>Loading links...</p>}
				{linksState.status === "error" && (
					<p style={{ color: "red" }}>{linksState.message}</p>
				)}
				{linksState.status === "loaded" &&
					(linksState.links.length === 0 ? (
						<p>No links held.</p>
					) : (
						<table
							style={{
								width: "100%",
								borderCollapse: "collapse",
								marginTop: "0.5rem",
							}}
						>
							<thead>
								<tr
									style={{
										borderBottom: "2px solid #ddd",
										textAlign: "left",
									}}
								>
									<th style={{ padding: "0.5rem" }}>Account</th>
									<th style={{ padding: "0.5rem" }}>Label</th>
									<th style={{ padding: "0.5rem" }}>Link ID</th>
									<th style={{ padding: "0.5rem" }}>Created</th>
									<th style={{ padding: "0.5rem" }}>Actions</th>
								</tr>
							</thead>
							<tbody>
								{linksState.links.map((link) => {
									const isRemoving =
										removeState.status === "removing" &&
										removeState.linkId === link.link_id;
									return (
										<tr
											key={link.link_id}
											style={{
												borderBottom: "1px solid #eee",
											}}
										>
											<td style={{ padding: "0.5rem" }}>
												{link.peer_sub} ({link.peer_iss})
											</td>
											<td style={{ padding: "0.5rem" }}>
												{link.peer_label || "-"}
											</td>
											<td
												style={{
													padding: "0.5rem",
													fontFamily: "monospace",
												}}
											>
												{link.link_id}
											</td>
											<td style={{ padding: "0.5rem" }}>
												{formatTimestamp(link.created_at)}
											</td>
											<td style={{ padding: "0.5rem" }}>
												<button
													type="button"
													onClick={() => handleRemove(link.link_id)}
													disabled={isRemoving}
												>
													{isRemoving ? "Removing..." : "Remove"}
												</button>
												<span
													style={{
														marginLeft: "0.5rem",
														fontSize: "0.85em",
														color: "#666",
													}}
												>
													Files already handed over cannot be recalled.
												</span>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					))}
			</div>
		</div>
	);
}

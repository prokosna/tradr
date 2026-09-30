import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { QRCodeSVG } from "qrcode.react";
import {
	type ChangeEvent,
	useCallback,
	useEffect,
	useRef,
	useState,
} from "react";
import type {
	LinkDto,
	LinkInviteDto,
	LinkInvitePreviewDto,
	LinkProposalDto,
	LinkReplyDto,
} from "./types.js";

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
			return "They declined.";
		case "invite-expired":
			return "The code expired before they answered.";
		case "verification-failed":
			return "Their device couldn't confirm this device's sign-in.";
		default:
			return "They declined.";
	}
}

const WORD_SLOTS = [
	"w0",
	"w1",
	"w2",
	"w3",
	"w4",
	"w5",
	"w6",
	"w7",
	"w8",
	"w9",
	"w10",
	"w11",
];

function TwelveWords({ words }: { words: string[] }) {
	return (
		<div className="words">
			{WORD_SLOTS.map((slot, i) => (
				<span key={slot}>{words[i] || ""}</span>
			))}
		</div>
	);
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
		<div className="stack">
			<h3>Join with a code</h3>
			<label className="field">
				<span className="small">Paste a code from another account</span>
				<textarea
					rows={4}
					className="input"
					placeholder="Paste a code from another account"
					value={blobText}
					onChange={handleBlobChange}
					disabled={
						state.status === "previewing" || state.status === "replying"
					}
				/>
			</label>
			<div>
				<button
					type="button"
					className="btn"
					onClick={handleCheckInvite}
					disabled={
						blobText.trim().length === 0 ||
						state.status === "previewing" ||
						state.status === "replying"
					}
				>
					{state.status === "previewing" ? "Checking…" : "Check code"}
				</button>
			</div>
			{pause && (
				<div className="stack">
					<p className="small muted">
						Check these words match the other device's screen
					</p>
					<TwelveWords words={pause.peer_fingerprint} />
					{pause.expired && (
						<p className="error-text">
							This code looks expired by this device's clock; the other side
							will probably refuse it.
						</p>
					)}
					{state.status === "previewed" && (
						<div>
							<button
								type="button"
								className="btn btn--primary"
								onClick={handleSendReply}
							>
								Link accounts
							</button>
						</div>
					)}
					{state.status === "replying" && <p className="muted">Linking…</p>}
				</div>
			)}
			{state.status === "done" && (
				<div className="stack">
					{state.outcome.linked ? (
						<p className="success-text">Linked.</p>
					) : (
						<p className="error-text">
							{declineReasonText(state.outcome.decline_reason)}
						</p>
					)}
				</div>
			)}
			{state.status === "error" && (
				<p className="error-text">{state.message}</p>
			)}
		</div>
	);
}

export function Linking() {
	const [inviteState, setInviteState] = useState<InviteState>({
		status: "idle",
	});
	const [copyStatus, setCopyStatus] = useState<"idle" | "copied">("idle");
	const [copyError, setCopyError] = useState<string | null>(null);
	const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	const [proposalState, setProposalState] = useState<ProposalState>({
		status: "idle",
	});
	const [linksState, setLinksState] = useState<LinksState>({
		status: "loading",
	});
	const [removeState, setRemoveState] = useState<RemoveState>({
		status: "idle",
	});
	const [toggleErrors, setToggleErrors] = useState<Record<string, string>>({});

	useEffect(() => {
		return () => {
			if (copyTimerRef.current) {
				clearTimeout(copyTimerRef.current);
			}
		};
	}, []);

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
		let cancelled = false;

		listen<LinkProposalDto>("link-proposal", (event) => {
			// The exchange already took the invite out of the window.
			setInviteState({ status: "idle" });
			setProposalState({ status: "loaded", proposal: event.payload });
		}).then((unlisten) => {
			if (cancelled) {
				unlisten();
			} else {
				unlistenProposal = unlisten;
			}
		});

		invoke<LinkProposalDto | null>("plugin:tradr|pending_link_proposal")
			.then((pending) => {
				if (cancelled) return;
				if (pending) {
					// The exchange already took the invite out of the window.
					setInviteState({ status: "idle" });
					setProposalState({ status: "loaded", proposal: pending });
				}
			})
			.catch((e) => {
				if (cancelled) return;
				setProposalState({ status: "error", message: String(e) });
			});

		fetchLinks();

		return () => {
			cancelled = true;
			if (unlistenProposal) {
				unlistenProposal();
			}
		};
	}, [fetchLinks]);

	const handleOpenInvite = useCallback(() => {
		setInviteState({ status: "loading" });
		setCopyStatus("idle");
		setCopyError(null);
		invoke<LinkInviteDto>("plugin:tradr|open_link_invite")
			.then((invite) => {
				setInviteState({ status: "loaded", invite });
			})
			.catch((e) => {
				setInviteState({ status: "error", message: String(e) });
			});
	}, []);

	const handleCopyCode = useCallback(() => {
		if (inviteState.status !== "loaded") return;
		setCopyError(null);
		navigator.clipboard
			.writeText(inviteState.invite.blob)
			.then(() => {
				setCopyStatus("copied");
				if (copyTimerRef.current) {
					clearTimeout(copyTimerRef.current);
				}
				copyTimerRef.current = setTimeout(() => {
					setCopyStatus("idle");
				}, 2000);
			})
			.catch((e) => {
				setCopyError(String(e));
			});
	}, [inviteState]);

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

	const handleFullAccessToggle = useCallback(
		(linkId: string, allowed: boolean) => {
			setToggleErrors((prev) => {
				const next = { ...prev };
				delete next[linkId];
				return next;
			});
			invoke("plugin:tradr|set_link_full_access", { linkId, allowed })
				.then(() => {
					fetchLinks();
				})
				.catch((e) => {
					setToggleErrors((prev) => ({
						...prev,
						[linkId]: String(e),
					}));
				});
		},
		[fetchLinks],
	);

	return (
		<div className="stack">
			<div className="stack">
				<div>
					<button
						type="button"
						className="btn btn--primary"
						onClick={handleOpenInvite}
						disabled={inviteState.status === "loading"}
					>
						{inviteState.status === "loading"
							? "Inviting…"
							: "Invite another account"}
					</button>
				</div>
				{inviteState.status === "error" && (
					<p className="error-text">{inviteState.message}</p>
				)}
				{inviteState.status === "loaded" && (
					<div className="stack">
						<div className="qr">
							{inviteState.invite.blob.length <= 2953 ? (
								// docs/11: QR byte mode holds 2953 bytes at error-correction level L.
								<QRCodeSVG
									value={inviteState.invite.blob}
									level="L"
									size={320}
								/>
							) : (
								<p className="muted">
									This invite is too large for a QR code and must be handed over
									by pasting the code below.
								</p>
							)}
						</div>
						<p className="muted">
							Scan this on the other device, or copy the code and send it.
						</p>
						<div className="code-box">
							<textarea
								readOnly
								rows={4}
								className="input"
								value={inviteState.invite.blob}
							/>
							<div>
								<button type="button" className="btn" onClick={handleCopyCode}>
									{copyStatus === "copied" ? "Copied" : "Copy code"}
								</button>
							</div>
							{copyError && <p className="error-text">{copyError}</p>}
						</div>
						<div className="stack">
							<p className="small muted">
								Check these words match on the other device
							</p>
							<TwelveWords words={inviteState.invite.fingerprint} />
						</div>
						<p className="small muted">
							This invite works once and expires in five minutes.
						</p>
					</div>
				)}
			</div>

			<LinkReplier onLinked={fetchLinks} />

			{(proposalState.status === "loaded" ||
				proposalState.status === "answering") && (
				<div className="card stack">
					<h3 className="card-title">
						{proposalState.proposal.peer_label || "Another account"} wants to
						link
					</h3>
					<div className="stack">
						<p className="small muted">
							Check these words match on their screen
						</p>
						<TwelveWords words={proposalState.proposal.peer_fingerprint} />
					</div>
					<div className="row">
						<button
							type="button"
							className="btn btn--primary"
							onClick={handleApprove}
							disabled={proposalState.status === "answering"}
						>
							{proposalState.status === "answering" ? "Linking…" : "Link"}
						</button>
						<button
							type="button"
							className="btn btn--ghost"
							onClick={handleDecline}
							disabled={proposalState.status === "answering"}
						>
							{proposalState.status === "answering" ? "Declining…" : "Decline"}
						</button>
					</div>
				</div>
			)}
			{proposalState.status === "error" && (
				<p className="error-text">{proposalState.message}</p>
			)}

			<div className="stack">
				{removeState.status === "error" && (
					<p className="error-text">{removeState.message}</p>
				)}
				{linksState.status === "loading" && (
					<p className="muted">Loading links…</p>
				)}
				{linksState.status === "error" && (
					<p className="error-text">{linksState.message}</p>
				)}
				{linksState.status === "loaded" &&
					(linksState.links.length === 0 ? (
						<p className="muted">No accounts linked.</p>
					) : (
						<div className="list">
							{linksState.links.map((link) => {
								const isRemoving =
									removeState.status === "removing" &&
									removeState.linkId === link.link_id;
								const toggleError = toggleErrors[link.link_id];
								return (
									<div key={link.link_id} className="link-item">
										<div className="row">
											<strong>{link.peer_label || "Linked account"}</strong>
											<span className="small muted">
												linked on{" "}
												{link.created_at
													? new Date(
															link.created_at * 1000,
														).toLocaleDateString()
													: "-"}
											</span>
										</div>
										<div>
											<label className="row small">
												<input
													type="checkbox"
													checked={link.full_access}
													onChange={(e) =>
														handleFullAccessToggle(
															link.link_id,
															e.target.checked,
														)
													}
												/>
												Let this account's devices open and change my folder
											</label>
											{toggleError && (
												<p className="error-text small">{toggleError}</p>
											)}
										</div>
										<div className="row">
											<button
												type="button"
												className="btn btn--ghost btn--danger"
												onClick={() => handleRemove(link.link_id)}
												disabled={isRemoving}
											>
												{isRemoving ? "Removing…" : "Remove"}
											</button>
											<span className="small muted">
												Files already handed over cannot be recalled.
											</span>
										</div>
									</div>
								);
							})}
						</div>
					))}
			</div>
		</div>
	);
}

import type { SignInUiState } from "../App.js";
import { DeliveriesCard } from "../components/DeliveriesCard.js";
import { DeviceTile, type PeerSendStatus } from "../components/DeviceTile.js";
import { ReceivedCard, type ReceivedItem } from "../components/ReceivedCard.js";
import {
	type ActiveSendInfo,
	SendCard,
	type StagedFile,
} from "../components/SendCard.js";
import { SignInCard } from "../components/SignInCard.js";
import type {
	DeliveryDto,
	KnownDeviceDto,
	PeerInfo,
	TransferProgressPayload,
} from "../types.js";

export interface HomeProps {
	signIn: SignInUiState;
	onSignIn: () => void;
	peers: PeerInfo[];
	offlineDevices: KnownDeviceDto[];
	brokrConfigured: boolean;
	deliveries: DeliveryDto[];
	hasLoadedPeersOnce: boolean;
	waitingFiles: StagedFile[];
	isSending: boolean;
	activeSend: ActiveSendInfo | null;
	progress: TransferProgressPayload | null;
	sendError: string | null;
	peerSendStates: Record<string, PeerSendStatus>;
	receivedFiles: ReceivedItem[];
	onSelectFiles: () => void;
	onClearWaitingFiles: () => void;
	onTileTap: (peer: PeerInfo) => void;
	onOpenFolder: (peerKey: string) => void;
}

export function Home({
	signIn,
	onSignIn,
	peers,
	offlineDevices,
	brokrConfigured,
	deliveries,
	hasLoadedPeersOnce,
	waitingFiles,
	isSending,
	activeSend,
	progress,
	sendError,
	peerSendStates,
	receivedFiles,
	onSelectFiles,
	onClearWaitingFiles,
	onTileTap,
	onOpenFolder,
}: HomeProps) {
	const showSignIn = signIn.status !== "signed_in";
	const devicesTitle = waitingFiles.length > 0 ? "Send to" : "Devices";
	const hasNoDevices = peers.length === 0 && offlineDevices.length === 0;

	return (
		<div className="app-main--split">
			{showSignIn && <SignInCard signIn={signIn} onSignIn={onSignIn} />}

			<section
				className={`card stack home-devices ${showSignIn ? "dimmed" : ""}`}
			>
				<h2 className="card-title">{devicesTitle}</h2>

				{showSignIn ? (
					<p className="muted">
						Your devices appear here once you're signed in.
					</p>
				) : hasNoDevices ? (
					!hasLoadedPeersOnce ? (
						<p className="muted">Looking for your devices…</p>
					) : (
						<div className="stack">
							<p className="muted">
								Devices signed in to your Google account appear here when
								they're on the same network.
							</p>
							<div>
								<button
									type="button"
									className="btn btn--ghost"
									onClick={() => {
										window.location.hash = "#/settings";
									}}
								>
									Add a device by address
								</button>
							</div>
						</div>
					)
				) : (
					<div className="list">
						{peers.map((peer) => (
							<DeviceTile
								key={peer.key}
								peer={peer}
								hasWaitingFiles={waitingFiles.length > 0}
								sendState={peerSendStates[peer.key]}
								onTap={onTileTap}
								onOpenFolder={onOpenFolder}
							/>
						))}
						{offlineDevices.map((device) => {
							const offlinePeer: PeerInfo = {
								device_id: device.device_id,
								key: device.device_id,
								display_name: device.display_name,
								addresses: [],
								capabilities: 0,
								sources: [],
							};
							return (
								<DeviceTile
									key={device.device_id}
									peer={offlinePeer}
									isOffline={true}
									brokrConfigured={brokrConfigured}
									hasWaitingFiles={waitingFiles.length > 0}
									sendState={peerSendStates[device.device_id]}
									onTap={onTileTap}
									onOpenFolder={onOpenFolder}
								/>
							);
						})}
					</div>
				)}
			</section>

			<div className="column">
				<SendCard
					files={waitingFiles}
					isSending={isSending}
					activeSend={activeSend}
					progress={progress}
					error={sendError}
					onSelectFiles={onSelectFiles}
					onClear={onClearWaitingFiles}
				/>

				<ReceivedCard items={receivedFiles} peers={peers} />

				<DeliveriesCard deliveries={deliveries} />
			</div>
		</div>
	);
}

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::State;

use tradr_app::brokr::{
    ArrivalHook, BrokrApi, BrokrError, BrokrSettings, Collector, CollectorParts, DeliveryDto,
    DeliveryStatus, HttpBrokrApi, JoinToken, KnownDeviceDto, LinksFn, OutboxEntry, OutboxState,
    OwnAccountFn, PlacedDeliveries, SendDeferredContext, SentDeliveries, clear_join_token,
    clear_session, clear_settings, delivery_dtos, ensure_session, known_device_dtos, load_settings,
    save_join_token, save_settings,
};
use tradr_app::known_store::KnownDevicesStore;
use tradr_app::peer_trust::PeerTrust;
use tradr_app::sign_in::SignInState;
use tradr_core::{Clock, DeviceId, KeyStore, PublicIdentity, SecretStore};
use tradr_identity::OsRng;
use tradr_vfs::NativeVfs;

use crate::identity::IdentityState;
use crate::lifecycle::downloads_root_id;

/// Status snapshot of the Brokr connection and delivery collector.
#[derive(Debug, Clone, Serialize)]
pub struct BrokrStatusDto {
    /// True when a Brokr URL is saved and configured.
    pub configured: bool,
    /// The Brokr base URL, if configured.
    pub url: Option<String>,
    /// Unix timestamp in seconds of the last pass, if one has run.
    pub last_pass: Option<i64>,
    /// Number of deliveries successfully placed on the last pass.
    pub delivered: usize,
    /// Short error description if the last pass failed.
    pub last_error: Option<String>,
}

struct BrokrInner {
    url: Option<String>,
    api: Option<Arc<HttpBrokrApi>>,
    collector: Option<Collector<NativeVfs>>,
}

/// Produces the device's peer trust engine, or explains why it is unavailable.
pub type PeerTrustFn = Arc<dyn Fn() -> Result<Arc<PeerTrust>, String> + Send + Sync>;

/// Grouped dependencies and callbacks required to initialize [`BrokrState`].
pub struct BrokrDeps {
    /// Directory where brokr settings are persisted.
    pub app_data_dir: PathBuf,
    /// Store for persisting the brokr join token and session.
    pub secrets: Arc<dyn SecretStore + Send + Sync>,
    /// Device key store for signing registrations.
    pub key_store: Arc<dyn KeyStore>,
    /// Device public identity advertised to the brokr.
    pub identity: PublicIdentity,
    /// Local filesystem for placing deferred deliveries.
    pub vfs: Arc<NativeVfs>,
    /// Clock for timestamping collector passes.
    pub clock: Arc<dyn Clock + Send + Sync>,
    /// Produces the device's peer trust engine.
    pub peer_trust_fn: PeerTrustFn,
    /// Yields the device's signed-in account if present.
    pub own_account_fn: OwnAccountFn,
    /// Yields the device's links and link secrets.
    pub links_fn: LinksFn,
    /// Hook called when files arrive via deferred delivery.
    pub on_arrival: ArrivalHook,
}

/// Shared state managing the Brokr collector background loop.
pub struct BrokrState {
    deps: BrokrDeps,
    inner: Mutex<BrokrInner>,
}

impl BrokrState {
    /// Builds and initializes the Brokr state, launching the collector if settings exist.
    pub fn new(deps: BrokrDeps) -> Self {
        let (url, api, collector) = match load_settings(&deps.app_data_dir) {
            Ok(Some(settings)) => match HttpBrokrApi::new(&settings.url) {
                Ok(api) => {
                    let api_arc = Arc::new(api);
                    let api_dyn: Arc<dyn BrokrApi> = api_arc.clone();
                    match (deps.peer_trust_fn)() {
                        Ok(trust) => {
                            let parts = CollectorParts {
                                api: api_dyn,
                                secrets: Arc::clone(&deps.secrets),
                                key_store: Arc::clone(&deps.key_store),
                                identity: deps.identity.clone(),
                                vfs: Arc::clone(&deps.vfs),
                                root: downloads_root_id(),
                                clock: Arc::clone(&deps.clock),
                                trust,
                                own_account: Arc::clone(&deps.own_account_fn),
                                links: Arc::clone(&deps.links_fn),
                                on_arrival: Arc::clone(&deps.on_arrival),
                                placed: Arc::new(PlacedDeliveries::new(&deps.app_data_dir)),
                            };
                            let collector = Collector::new(parts);
                            let runner = collector.clone();
                            tauri::async_runtime::spawn(async move {
                                runner.run().await;
                            });
                            (Some(settings.url), Some(api_arc), Some(collector))
                        }
                        Err(e) => {
                            eprintln!("brokr: peer trust not available at startup: {e}");
                            (Some(settings.url), Some(api_arc), None)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("brokr: invalid stored url {}: {e}", settings.url);
                    (None, None, None)
                }
            },
            Ok(None) => (None, None, None),
            Err(e) => {
                eprintln!("brokr: could not load stored settings: {e}");
                (None, None, None)
            }
        };

        Self {
            deps,
            inner: Mutex::new(BrokrInner {
                url,
                api,
                collector,
            }),
        }
    }

    /// Sets or replaces the Brokr URL and join token, restarting the collector.
    pub fn set_brokr(&self, url: String, join_token: String) -> Result<BrokrStatusDto, String> {
        let api = HttpBrokrApi::new(&url).map_err(|e| e.to_string())?;
        let api_arc = Arc::new(api);
        let api_dyn: Arc<dyn BrokrApi> = api_arc.clone();
        save_settings(&self.deps.app_data_dir, &BrokrSettings { url: url.clone() })
            .map_err(|e| e.to_string())?;
        save_join_token(self.deps.secrets.as_ref(), &JoinToken::new(join_token))
            .map_err(|e| e.to_string())?;
        clear_session(self.deps.secrets.as_ref()).map_err(|e| e.to_string())?;

        let trust =
            (self.deps.peer_trust_fn)().map_err(|e| format!("peer trust unavailable: {e}"))?;

        let parts = CollectorParts {
            api: api_dyn,
            secrets: Arc::clone(&self.deps.secrets),
            key_store: Arc::clone(&self.deps.key_store),
            identity: self.deps.identity.clone(),
            vfs: Arc::clone(&self.deps.vfs),
            root: downloads_root_id(),
            clock: Arc::clone(&self.deps.clock),
            trust,
            own_account: Arc::clone(&self.deps.own_account_fn),
            links: Arc::clone(&self.deps.links_fn),
            on_arrival: Arc::clone(&self.deps.on_arrival),
            placed: Arc::new(PlacedDeliveries::new(&self.deps.app_data_dir)),
        };
        let collector = Collector::new(parts);
        let runner = collector.clone();
        tauri::async_runtime::spawn(async move {
            runner.run().await;
        });

        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(old) = inner.collector.take() {
            old.stop();
        }
        let status = collector.status();
        inner.url = Some(url.clone());
        inner.api = Some(api_arc);
        inner.collector = Some(collector);

        Ok(BrokrStatusDto {
            configured: true,
            url: Some(url),
            last_pass: status.last_pass.map(|t| t.as_secs()),
            delivered: status.delivered,
            last_error: status.last_error,
        })
    }

    /// Current snapshot of collector status.
    pub fn status(&self) -> BrokrStatusDto {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(ref url) = inner.url {
            let (last_pass, delivered, last_error) = match &inner.collector {
                Some(collector) => {
                    let s = collector.status();
                    (s.last_pass.map(|t| t.as_secs()), s.delivered, s.last_error)
                }
                None => (None, 0, None),
            };
            BrokrStatusDto {
                configured: true,
                url: Some(url.clone()),
                last_pass,
                delivered,
                last_error,
            }
        } else {
            BrokrStatusDto {
                configured: false,
                url: None,
                last_pass: None,
                delivered: 0,
                last_error: None,
            }
        }
    }

    /// Wakes the collector for an immediate pass if running.
    pub fn wake(&self) {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(collector) = &inner.collector {
            collector.wake();
        }
    }

    /// Stops the collector and clears settings, join token and session.
    pub fn clear(&self) -> Result<(), String> {
        {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(old) = inner.collector.take() {
                old.stop();
            }
            inner.url = None;
            inner.api = None;
        }
        clear_settings(&self.deps.app_data_dir).map_err(|e| e.to_string())?;
        clear_join_token(self.deps.secrets.as_ref()).map_err(|e| e.to_string())?;
        clear_session(self.deps.secrets.as_ref()).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Returns the active Brokr HTTP API adapter if configured.
    pub fn api(&self) -> Option<Arc<HttpBrokrApi>> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.api.clone()
    }
}

/// Configures the Brokr address and join token, and starts or restarts collecting.
#[tauri::command]
pub async fn set_brokr(
    url: String,
    join_token: String,
    state: State<'_, Arc<BrokrState>>,
) -> Result<BrokrStatusDto, String> {
    state.set_brokr(url, join_token)
}

/// Returns the current configuration and delivery status of the Brokr collector.
#[tauri::command]
pub async fn brokr_status(state: State<'_, Arc<BrokrState>>) -> Result<BrokrStatusDto, String> {
    Ok(state.status())
}

/// Triggers an immediate collecting pass without waiting for the 5-minute interval.
#[tauri::command]
pub async fn collect_brokr_now(state: State<'_, Arc<BrokrState>>) -> Result<(), String> {
    state.wake();
    Ok(())
}

/// Disables the Brokr, stops collecting, and removes stored tokens and settings.
#[tauri::command]
pub async fn clear_brokr(state: State<'_, Arc<BrokrState>>) -> Result<(), String> {
    state.clear()
}

/// Lists known devices met through verified direct handshakes, excluding this device.
#[tauri::command]
pub async fn list_known_devices(
    identity_state: State<'_, IdentityState>,
    known_devices: State<'_, Arc<KnownDevicesStore>>,
) -> Result<Vec<KnownDeviceDto>, String> {
    let self_id = identity_state.public_identity()?.device_id();
    let snapshot = known_devices.snapshot();
    Ok(known_device_dtos(&snapshot, self_id))
}

/// Uploads an end-to-end encrypted envelope to the Brokr for an offline recipient.
#[tauri::command]
pub async fn send_deferred<R: tauri::Runtime>(
    _app: tauri::AppHandle<R>,
    device_id: String,
    files: Vec<String>,
    adopted_ids: Option<Vec<String>>,
    state: State<'_, Arc<BrokrState>>,
    sign_in_state: State<'_, Arc<SignInState>>,
    known_devices: State<'_, Arc<KnownDevicesStore>>,
) -> Result<DeliveryDto, String> {
    let api = state
        .api()
        .ok_or_else(|| "no Brokr is configured".to_string())?;

    let target_id = device_id
        .parse::<DeviceId>()
        .map_err(|e| format!("invalid device id: {e}"))?;

    let recipient = known_devices
        .snapshot()
        .into_iter()
        .find(|d| d.device_id() == target_id)
        .ok_or_else(|| "device is not a known device".to_string())?;

    let attestation_token = sign_in_state
        .id_token()
        .ok_or_else(|| "not signed in".to_string())?;

    let own_account = sign_in_state
        .own_account()
        .ok_or_else(|| "not signed in".to_string())?;

    #[cfg(not(target_os = "android"))]
    if let Some(ref ids) = adopted_ids
        && !ids.is_empty()
    {
        return Err("adopted files exist only on Android".to_string());
    }

    let items =
        tradr_app::send::resolve_send_items(state.deps.vfs.as_ref(), downloads_root_id(), &files)
            .await?;

    #[cfg(target_os = "android")]
    let (items, staged_count, adopted_ctx) = {
        use tauri::Manager;
        let mut items = items;
        let ids = adopted_ids.unwrap_or_default();
        if !ids.is_empty() {
            let adopted = _app
                .try_state::<Arc<tradr_app::adopted::AdoptedFiles>>()
                .ok_or_else(|| "adopted files not found".to_string())?;
            let staged = adopted.send_items(state.deps.vfs.as_ref(), &ids).await?;
            let count = staged.len();
            items.extend(staged);
            (items, count, Some((adopted, ids)))
        } else {
            (items, 0, None)
        }
    };

    let link_view = (state.deps.links_fn)().map_err(|e| format!("links unavailable: {e}"))?;

    let session = ensure_session(
        api.as_ref(),
        state.deps.secrets.as_ref(),
        state.deps.key_store.as_ref(),
        &state.deps.identity,
        &own_account,
        &link_view.secrets,
    )
    .await
    .map_err(map_brokr_error)?;

    let ctx = SendDeferredContext {
        vfs: state.deps.vfs.as_ref(),
        identity: &state.deps.identity,
        key_store: state.deps.key_store.as_ref(),
        attestation_token,
        rng: &OsRng,
        clock: state.deps.clock.as_ref(),
    };

    let send_result = async {
        let sent_res =
            tradr_app::brokr::send_deferred(api.as_ref(), &session, &ctx, &recipient, &items).await;

        let sent = match sent_res {
            Err(BrokrError::Unauthorized) => {
                if let Err(e) = clear_session(state.deps.secrets.as_ref()) {
                    eprintln!("failed to clear session: {e}");
                }
                let refreshed_session = ensure_session(
                    api.as_ref(),
                    state.deps.secrets.as_ref(),
                    state.deps.key_store.as_ref(),
                    &state.deps.identity,
                    &own_account,
                    &link_view.secrets,
                )
                .await
                .map_err(map_brokr_error)?;
                tradr_app::brokr::send_deferred(
                    api.as_ref(),
                    &refreshed_session,
                    &ctx,
                    &recipient,
                    &items,
                )
                .await
                .map_err(map_brokr_error)?
            }
            Err(e) => return Err(map_brokr_error(e)),
            Ok(s) => s,
        };

        let now = state.deps.clock.now();
        let mut outbox = SentDeliveries::load(&state.deps.app_data_dir)
            .map_err(|e| format!("failed to load sent deliveries: {e}"))?;
        outbox
            .record_delivery(&sent, now)
            .map_err(|e| format!("failed to record delivery: {e}"))?;

        let recipient_name = recipient.display_name().map(|n| n.as_str().to_string());
        Ok(DeliveryDto {
            id: sent.id,
            recipient_device_id: sent.recipient.to_string(),
            recipient_name,
            names: sent.names,
            sent_at: now.as_secs(),
            state: "waiting".to_string(),
            collected_at: None,
        })
    }
    .await;

    #[cfg(target_os = "android")]
    if let Some((adopted, ids)) = adopted_ctx {
        let staged = &items[items.len() - staged_count..];
        if let Err(e) = adopted.unstage(state.deps.vfs.as_ref(), staged) {
            eprintln!("failed to unstage adopted files: {e}");
        }
        if send_result.is_ok() {
            for id in &ids {
                if let Err(e) = adopted.release(id) {
                    eprintln!("failed to release adopted file {id}: {e}");
                }
            }
        }
    }

    send_result
}

/// Lists sent deliveries merged with the Brokr outbox when reachable, or from local records.
#[tauri::command]
pub async fn list_deliveries(
    state: State<'_, Arc<BrokrState>>,
    known_devices: State<'_, Arc<KnownDevicesStore>>,
) -> Result<Vec<DeliveryDto>, String> {
    let outbox_journal = match SentDeliveries::load(&state.deps.app_data_dir) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("failed to load sent deliveries: {e}");
            return Ok(Vec::new());
        }
    };
    let known = known_devices.snapshot();

    let brokr_outbox = if let Some(api) = state.api() {
        query_brokr_outbox(api.as_ref(), state.inner()).await
    } else {
        None
    };

    if let Some(entries) = brokr_outbox {
        let statuses = outbox_journal.merge_with(&entries);
        Ok(delivery_dtos(&statuses, &known))
    } else {
        let now = state.deps.clock.now();
        const THIRTY_DAYS_SECS: i64 = 30 * 24 * 3600;
        let statuses: Vec<DeliveryStatus> = outbox_journal
            .all()
            .iter()
            .map(|r| {
                let state = match r.state {
                    Some(s) => s,
                    None => {
                        let elapsed = now.as_secs().saturating_sub(r.sent_at.as_secs());
                        if elapsed > THIRTY_DAYS_SECS {
                            OutboxState::Expired
                        } else {
                            OutboxState::Waiting
                        }
                    }
                };
                DeliveryStatus {
                    id: r.id.clone(),
                    recipient_device_id: r.recipient_device_id,
                    names: r.names.clone(),
                    sent_at: r.sent_at,
                    state,
                    collected_at: r.collected_at,
                }
            })
            .collect();
        Ok(delivery_dtos(&statuses, &known))
    }
}

async fn query_brokr_outbox(api: &dyn BrokrApi, state: &BrokrState) -> Option<Vec<OutboxEntry>> {
    let own_account = (state.deps.own_account_fn)()?;
    let link_view = (state.deps.links_fn)().ok()?;
    let session = ensure_session(
        api,
        state.deps.secrets.as_ref(),
        state.deps.key_store.as_ref(),
        &state.deps.identity,
        &own_account,
        &link_view.secrets,
    )
    .await
    .ok()?;
    match api.outbox(&session).await {
        Ok(entries) => Some(entries),
        Err(BrokrError::Unauthorized) => {
            if let Err(e) = clear_session(state.deps.secrets.as_ref()) {
                eprintln!("failed to clear session: {e}");
            }
            let refreshed = ensure_session(
                api,
                state.deps.secrets.as_ref(),
                state.deps.key_store.as_ref(),
                &state.deps.identity,
                &own_account,
                &link_view.secrets,
            )
            .await
            .ok()?;
            api.outbox(&refreshed).await.ok()
        }
        Err(_) => None,
    }
}

fn map_brokr_error(err: BrokrError) -> String {
    match err {
        BrokrError::NotEligible => {
            "that device isn't one of yours or a linked account's on this Brokr".to_string()
        }
        BrokrError::StorageFull => "storage full".to_string(),
        BrokrError::TooManyWaiting => "too many waiting".to_string(),
        BrokrError::Rejected(ref msg) if msg.contains("not eligible") => {
            "that device isn't one of yours or a linked account's on this Brokr".to_string()
        }
        other => other.to_string(),
    }
}

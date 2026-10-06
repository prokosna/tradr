//! Tauri commands and state management for the background Brokr collector.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::State;

use tradr_app::brokr::{
    ArrivalHook, BrokrSettings, Collector, CollectorParts, HttpBrokrApi, JoinToken, LinksFn,
    OwnAccountFn, clear_join_token, clear_session, clear_settings, load_settings, save_join_token,
    save_settings,
};
use tradr_app::peer_trust::PeerTrust;
use tradr_core::{Clock, KeyStore, PublicIdentity, SecretStore};
use tradr_vfs::NativeVfs;

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
        let (url, collector) = match load_settings(&deps.app_data_dir) {
            Ok(Some(settings)) => match HttpBrokrApi::new(&settings.url) {
                Ok(api) => match (deps.peer_trust_fn)() {
                    Ok(trust) => {
                        let parts = CollectorParts {
                            api: Arc::new(api),
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
                        };
                        let collector = Collector::new(parts);
                        let runner = collector.clone();
                        tauri::async_runtime::spawn(async move {
                            runner.run().await;
                        });
                        (Some(settings.url), Some(collector))
                    }
                    Err(e) => {
                        eprintln!("brokr: peer trust not available at startup: {e}");
                        (Some(settings.url), None)
                    }
                },
                Err(e) => {
                    eprintln!("brokr: invalid stored url {}: {e}", settings.url);
                    (None, None)
                }
            },
            Ok(None) => (None, None),
            Err(e) => {
                eprintln!("brokr: could not load stored settings: {e}");
                (None, None)
            }
        };

        Self {
            deps,
            inner: Mutex::new(BrokrInner { url, collector }),
        }
    }

    /// Sets or replaces the Brokr URL and join token, restarting the collector.
    pub fn set_brokr(&self, url: String, join_token: String) -> Result<BrokrStatusDto, String> {
        let api = HttpBrokrApi::new(&url).map_err(|e| e.to_string())?;
        save_settings(&self.deps.app_data_dir, &BrokrSettings { url: url.clone() })
            .map_err(|e| e.to_string())?;
        save_join_token(self.deps.secrets.as_ref(), &JoinToken::new(join_token))
            .map_err(|e| e.to_string())?;
        clear_session(self.deps.secrets.as_ref()).map_err(|e| e.to_string())?;

        let trust =
            (self.deps.peer_trust_fn)().map_err(|e| format!("peer trust unavailable: {e}"))?;

        let parts = CollectorParts {
            api: Arc::new(api),
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
        }
        clear_settings(&self.deps.app_data_dir).map_err(|e| e.to_string())?;
        clear_join_token(self.deps.secrets.as_ref()).map_err(|e| e.to_string())?;
        clear_session(self.deps.secrets.as_ref()).map_err(|e| e.to_string())?;
        Ok(())
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

//! BLE advertising rotation across broadcast secrets (docs/03, DCR-109).

use std::sync::Arc;
use std::time::Duration;

use tradr_core::{BoxFuture, Clock};

use crate::advertisement::{Advertisement, PlatformCode, SERVICE_DATA_LEN};
use crate::ble::{
    BLE_OBSERVATION_TTL_SECS, BleAdvertiser, BleError, BroadcastSecrets, DeclaredCapabilities,
};
use crate::eid::EidWindow;

/// The duration of one advertising slot, sized so a scanning peer expects multiple reports per slot.
pub const BLE_ADVERTISEMENT_SLOT_SECS: u64 = 4;

/// The largest cycle that leaves one slot of margin before the observation age-out.
pub const BLE_ADVERTISED_SET_MAX: usize =
    (BLE_OBSERVATION_TTL_SECS / BLE_ADVERTISEMENT_SLOT_SECS - 1) as usize;

const _: () = assert!(
    (BLE_ADVERTISED_SET_MAX as u64 + 1) * BLE_ADVERTISEMENT_SLOT_SECS <= BLE_OBSERVATION_TTL_SECS,
    "full advertising cycle plus one slot must fit within the observation TTL",
);

const OVERBOUND_REPORT: &str = "ble rotation: advertised set exceeds maximum cycle bound";
const OVERBOUND_CLEARED_REPORT: &str =
    "ble rotation: advertised set returned within maximum cycle bound";

/// The outcome of one slot's advertising rotation tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationTick {
    wait: Duration,
    report: Option<&'static str>,
}

impl RotationTick {
    /// The time before the next tick.
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// A line to print when the advertised set size condition changes.
    pub fn report(&self) -> Option<&str> {
        self.report
    }
}

/// Drives the BLE advertising rotation across the currently held advertised secrets.
pub struct BleRotation {
    advertiser: Box<dyn BleAdvertiser>,
    secrets: Box<dyn BroadcastSecrets>,
    clock: Box<dyn Clock + Send + Sync>,
    capabilities: Arc<dyn DeclaredCapabilities>,
    platform: PlatformCode,
    cycle_index: usize,
    on_air: Option<[u8; SERVICE_DATA_LEN]>,
    overbound_reported: bool,
}

impl BleRotation {
    /// Creates a new BLE advertising rotation runner.
    pub fn new(
        advertiser: Box<dyn BleAdvertiser>,
        secrets: Box<dyn BroadcastSecrets>,
        clock: Box<dyn Clock + Send + Sync>,
        capabilities: Arc<dyn DeclaredCapabilities>,
        platform: PlatformCode,
    ) -> Self {
        Self {
            advertiser,
            secrets,
            clock,
            capabilities,
            platform,
            cycle_index: 0,
            on_air: None,
            overbound_reported: false,
        }
    }

    /// Performs one slot's worth of advertising work.
    pub fn tick(&mut self) -> BoxFuture<'_, Result<RotationTick, BleError>> {
        Box::pin(async move {
            let advertised = self.secrets.advertised();
            let capabilities = self.capabilities.capabilities();
            let now = self.clock.now();

            let (next_overbound, report) = if advertised.len() > BLE_ADVERTISED_SET_MAX {
                if !self.overbound_reported {
                    (true, Some(OVERBOUND_REPORT))
                } else {
                    (true, None)
                }
            } else if self.overbound_reported {
                (false, Some(OVERBOUND_CLEARED_REPORT))
            } else {
                (false, None)
            };

            if advertised.is_empty() {
                self.cycle_index = 0;
                if self.on_air.is_some() {
                    self.advertiser.stop().await?;
                    self.on_air = None;
                }
            } else {
                let index = self.cycle_index % advertised.len();
                let secret = &advertised[index];
                let window = EidWindow::containing(now);
                let eid = secret.eid(window);
                let payload = Advertisement::new(eid, self.platform, capabilities).service_data();

                if self.on_air != Some(payload) {
                    if let Err(e) = self.advertiser.start(payload).await {
                        self.on_air = None;
                        return Err(e);
                    }
                    self.on_air = Some(payload);
                }
                self.cycle_index = self.cycle_index.wrapping_add(1);
            }

            self.overbound_reported = next_overbound;

            Ok(RotationTick {
                wait: Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS),
                report,
            })
        })
    }
}

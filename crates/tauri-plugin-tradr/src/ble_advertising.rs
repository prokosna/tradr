#![forbid(unsafe_code)]
//! Background BLE advertising runner driving slot rotation across broadcast secrets (docs/03, WI-M7-011, DCR-109).

use std::sync::Arc;
use std::time::Duration;

use tradr_core::{BoxFuture, Clock};
use tradr_discovery::{
    BLE_ADVERTISEMENT_SLOT_SECS, BleAdvertiser, BleError, BleRotation, BroadcastSecrets,
    DeclaredCapabilities, PlatformCode, RotationTick,
};

/// The 4-bit platform code this build advertises (ADR-0019).
pub fn local_platform_code() -> PlatformCode {
    #[cfg(target_os = "linux")]
    {
        PlatformCode::LINUX
    }
    #[cfg(target_os = "windows")]
    {
        PlatformCode::WINDOWS
    }
    #[cfg(target_os = "macos")]
    {
        PlatformCode::MAC
    }
    #[cfg(target_os = "android")]
    {
        PlatformCode::ANDROID
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "android"
    )))]
    {
        PlatformCode::UNKNOWN
    }
}

/// What one rotation tick's outcome tells the advertising task to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotOutcome {
    reports: Vec<String>,
    wait: Duration,
    retreat: bool,
}

impl SlotOutcome {
    /// The lines to report before the next slot, empty when nothing changed.
    pub fn reports(&self) -> &[String] {
        &self.reports
    }

    /// How long to wait before the next tick.
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// Whether the task ends, which is Change Drill D4's retreat.
    pub fn retreat(&self) -> bool {
        self.retreat
    }
}

/// Decides what one tick's outcome reports and whether the task goes on.
pub fn slot_outcome(
    outcome: &Result<RotationTick, BleError>,
    previous: Option<BleError>,
) -> SlotOutcome {
    match outcome {
        Err(BleError::Unsupported) => SlotOutcome {
            reports: vec![
                "ble advertising: unsupported on this platform, scanning only from now on"
                    .to_string(),
            ],
            wait: Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS),
            retreat: true,
        },
        Err(e) => {
            let reports = if previous != Some(*e) {
                vec![format!("ble advertising: {e}")]
            } else {
                Vec::new()
            };
            SlotOutcome {
                reports,
                wait: Duration::from_secs(BLE_ADVERTISEMENT_SLOT_SECS),
                retreat: false,
            }
        }
        Ok(tick) => {
            let mut reports = Vec::new();
            if previous.is_some() {
                reports.push("ble advertising: advertising resumed".to_string());
            }
            if let Some(report) = tick.report() {
                reports.push(report.to_string());
            }
            SlotOutcome {
                reports,
                wait: tick.wait(),
                retreat: false,
            }
        }
    }
}

/// Remembers the error the previous slot answered, so a cause is reported when it changes.
#[derive(Debug, Default)]
pub struct AdvertisingReporter {
    previous: Option<BleError>,
}

impl AdvertisingReporter {
    /// Decides one slot's outcome and remembers this slot's error for the next.
    pub fn slot(&mut self, outcome: &Result<RotationTick, BleError>) -> SlotOutcome {
        let decided = slot_outcome(outcome, self.previous);
        self.previous = outcome.as_ref().err().copied();
        decided
    }
}

/// Owns everything the advertising rotation needs except the radio itself.
pub struct BleAdvertising {
    secrets: Box<dyn BroadcastSecrets>,
    clock: Box<dyn Clock + Send + Sync>,
    capabilities: Arc<dyn DeclaredCapabilities>,
    platform: PlatformCode,
}

impl BleAdvertising {
    /// Creates a new BLE advertising runner.
    pub fn new(
        secrets: Box<dyn BroadcastSecrets>,
        clock: Box<dyn Clock + Send + Sync>,
        capabilities: Arc<dyn DeclaredCapabilities>,
        platform: PlatformCode,
    ) -> Self {
        Self {
            secrets,
            clock,
            capabilities,
            platform,
        }
    }

    /// Drives the rotation one slot at a time until the platform cannot advertise.
    pub async fn run(self, advertiser: Result<Box<dyn BleAdvertiser>, BleError>) {
        let advertiser = match advertiser {
            Ok(a) => a,
            Err(cause) => {
                eprintln!("ble advertising: advertiser unavailable: {cause}");
                return;
            }
        };

        let mut rotation = BleRotation::new(
            advertiser,
            self.secrets,
            self.clock,
            self.capabilities,
            self.platform,
        );

        let mut reporter = AdvertisingReporter::default();
        loop {
            let result = rotation.tick().await;
            let outcome = reporter.slot(&result);
            for line in outcome.reports() {
                eprintln!("{line}");
            }
            if outcome.retreat() {
                return;
            }
            tokio::time::sleep(outcome.wait()).await;
        }
    }
}

/// Spawns the background BLE advertising task on Tauri's async runtime.
pub fn spawn_ble_advertising(
    advertising: BleAdvertising,
    open: BoxFuture<'static, Result<Box<dyn BleAdvertiser>, BleError>>,
) {
    tauri::async_runtime::spawn(async move {
        let advertiser = open.await;
        advertising.run(advertiser).await;
    });
}

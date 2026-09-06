#![forbid(unsafe_code)]
#![cfg(target_os = "android")]
//! Diagnostic probe making Android BLE advertise and scan observable (WI-M7-005b).
//!
//! Kept in a separate module rather than ble_android.rs so it can be deleted
//! in one step when WI-M7-006 and WI-M7-007 wire real BLE lifecycle.

use std::collections::HashSet;
use std::time::Duration;

use tauri::{Runtime, plugin::PluginHandle};
use tokio::time::timeout;
use tradr_core::{Capabilities, Clock};
use tradr_discovery::{
    Advertisement, BleAdvertiser, BleScanner, BroadcastSecret, EidWindow, PlatformCode,
};
use tradr_identity::SystemClock;

use crate::ble_android::{
    AndroidBleAdvertiser, AndroidBleScanner, SELF_TEST_HANDLE, SELF_TEST_SERVICE_DATA,
};

const PROBE_ACCOUNT_ID: &[u8] = b"tradr-m7-probe";
const PROBE_DURATION_SECS: u64 = 60;

fn to_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Spawns the background BLE verification probe without blocking the setup hook.
pub fn spawn_ble_probe<R: Runtime>(handle: PluginHandle<R>) {
    tauri::async_runtime::spawn(async move {
        run_probe(handle).await;
    });
}

async fn run_probe<R: Runtime>(handle: PluginHandle<R>) {
    let clock = SystemClock;
    let window = EidWindow::containing(clock.now());
    let secret = BroadcastSecret::bootstrap(PROBE_ACCOUNT_ID);
    let eid = secret.eid(window);
    let advertisement = Advertisement::new(eid, PlatformCode::ANDROID, Capabilities::BLE_GATT);
    let service_data = advertisement.service_data();

    println!(
        "WI-M7-005b probe-start: seed=tradr-m7-probe window={} eid={} service_data={}",
        window.index(),
        to_hex(eid.as_bytes()),
        to_hex(&service_data),
    );

    let mut advertiser = AndroidBleAdvertiser::new(handle.clone());
    let mut advertising_started = false;
    match advertiser.start(service_data).await {
        Ok(()) => {
            println!("WI-M7-005b advertise: ok");
            advertising_started = true;
        }
        Err(err) => {
            println!("WI-M7-005b advertise: error={err}");
        }
    }

    let mut scanner = match AndroidBleScanner::new(handle, true).await {
        Ok(scanner) => {
            println!("WI-M7-005b scan-start: ok");
            scanner
        }
        Err(err) => {
            println!("WI-M7-005b scan-start: error={err}");
            if advertising_started && let Err(stop_err) = advertiser.stop().await {
                eprintln!("WI-M7-005b stop advertising failed: {stop_err}");
            }
            return;
        }
    };

    let mut reports_count: usize = 0;
    let mut distinct_handles = HashSet::new();
    let mut selftest_received = false;

    let scan_duration = Duration::from_secs(PROBE_DURATION_SECS);
    let scan_loop = async {
        loop {
            match scanner.next_report().await {
                Ok(report) => {
                    reports_count += 1;
                    distinct_handles.insert(report.handle().to_string());
                    let is_probe_payload = report.service_data() == service_data;
                    if report.handle() == SELF_TEST_HANDLE
                        && report.service_data() == SELF_TEST_SERVICE_DATA
                    {
                        selftest_received = true;
                        println!(
                            "WI-M7-005d selftest: handle={} service_data={}",
                            report.handle(),
                            to_hex(report.service_data()),
                        );
                    }
                    println!(
                        "WI-M7-005b report: handle={} service_data={} is_probe_payload={}",
                        report.handle(),
                        to_hex(report.service_data()),
                        is_probe_payload,
                    );
                }
                Err(err) => {
                    println!("WI-M7-005b scan-error: {err}");
                    break;
                }
            }
        }
    };

    if timeout(scan_duration, scan_loop).await.is_err() {
        println!("WI-M7-005b scan-window: closed after {PROBE_DURATION_SECS}s");
    }

    if advertising_started && let Err(err) = advertiser.stop().await {
        eprintln!("WI-M7-005b stop advertising failed: {err}");
    }
    drop(scanner);

    println!(
        "WI-M7-005b probe-end: reports={reports_count} distinct_handles={} selftest_received={selftest_received}",
        distinct_handles.len()
    );
}

//! Received files history recording and retrieval (docs/12, DCR-184).

use std::sync::Arc;

use tauri::State;
use tradr_app::received_history::{
    NewReceived, ReceivedHistory, ReceivedHistoryError, ReceivedHow, ReceivedRow,
};
use tradr_core::{Clock, DeviceId, RelPath};
use tradr_identity::KnownDevice;

/// Returns the display name held for the peer device, if known and named.
pub fn known_name(known: &[KnownDevice], peer: &DeviceId) -> Option<String> {
    known
        .iter()
        .find(|d| d.device_id() == *peer)
        .and_then(|d| d.display_name())
        .map(|n| n.as_str().to_string())
}

/// Records arrivals into the received history journal.
pub fn record_received(
    history: &ReceivedHistory,
    device_name: Option<String>,
    clock: &dyn Clock,
    peer: DeviceId,
    paths: &[RelPath],
    how: ReceivedHow,
) -> Result<(), ReceivedHistoryError> {
    let now_secs = clock.now().as_secs().max(0) as u64;
    let peer_str = peer.to_string();
    let rows: Vec<NewReceived> = paths
        .iter()
        .map(|path| NewReceived {
            path: path.to_string(),
            device_id: peer_str.clone(),
            device_name: device_name.clone(),
            received_at: now_secs,
            how,
        })
        .collect();
    history.record(rows)
}

/// Returns the list of received files ordered newest first.
#[tauri::command]
pub fn received_history(
    history: State<'_, Arc<ReceivedHistory>>,
) -> Result<Vec<ReceivedRow>, String> {
    history.rows().map_err(|e| e.to_string())
}

/// Clears all recorded arrivals from the history journal.
#[tauri::command]
pub fn clear_received_history(history: State<'_, Arc<ReceivedHistory>>) -> Result<(), String> {
    history.clear().map_err(|e| e.to_string())
}

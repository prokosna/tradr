#![forbid(unsafe_code)]
//! Composition root: binds the other crates to tradr-core's traits; hosts the Kotlin glue.
//!
//! WI-M0-005 also lives here: both of ADR-0001's call directions run once, from this
//! plugin's setup hook, so the evidence needs no interaction with the frontend.

use tauri::{
    Runtime,
    plugin::{Builder, TauriPlugin},
};

#[cfg(target_os = "android")]
mod android;

/// Builds the plugin. On Android its setup hook demonstrates both ADR-0001 call
/// directions with Kotlin; on every other target it is a no-op, since there is no
/// Kotlin side to call into or be called from.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("tradr")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            android::demonstrate_bidirectional_calls(_api)?;
            Ok(())
        })
        .build()
}

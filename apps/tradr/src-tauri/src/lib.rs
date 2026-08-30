//! Tauri entry point for the Tradr desktop and Android shell.
//!
//! Registers the `tauri-plugin-tradr` plugin; everything the plugin does happens
//! inside its own setup hook, since this file is only the composition root.

// Empty and absent both mean unconfigured, never distinguished: build.rs
// (DCR-030) emits an empty value when `.tradr-deployment.env` is absent
// so a fresh clone still builds, and omits the secret entirely on Android
// so `option_env!` reads it as absent rather than failing the build.
fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.filter(|v| !v.is_empty())
}

#[cfg(desktop)]
fn show_main_window(app: &tauri::AppHandle) {
    use tauri::Manager;

    if let Some(window) = app.get_webview_window("main") {
        if let Err(err) = window.show() {
            eprintln!("tray: failed to show window: {err}");
        }
        if let Err(err) = window.unminimize() {
            eprintln!("tray: failed to unminimize window: {err}");
        }
        if let Err(err) = window.set_focus() {
            eprintln!("tray: failed to focus window: {err}");
        }
    }
}

#[cfg(desktop)]
fn setup_desktop(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show_item = MenuItem::with_id(app, "show", "Show Tradr", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                show_main_window(app);
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_tradr::init(
            non_empty(option_env!("TRADR_OAUTH_CLIENT_IDS")),
            non_empty(option_env!("TRADR_OAUTH_CLIENT_SECRET")),
        ));

    #[cfg(desktop)]
    {
        builder = builder
            .setup(|app| {
                setup_desktop(app)?;
                Ok(())
            })
            .on_window_event(|window, event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    if let Err(err) = window.hide() {
                        eprintln!("window: failed to hide on close request: {err}");
                    }
                }
            });
    }

    builder.run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    // The only thing that will notice if build.rs stops plumbing
    // TRADR_OAUTH_CLIENT_IDS from the environment into the build (DCR-030).
    // Vacuously passes when the variable is unset, which keeps a fresh
    // clone's `cargo test` green.
    #[test]
    fn oauth_client_ids_reach_the_compiled_app() {
        if let Ok(expected) = std::env::var("TRADR_OAUTH_CLIENT_IDS")
            && !expected.is_empty()
        {
            assert_eq!(env!("TRADR_OAUTH_CLIENT_IDS"), expected);
        }
    }
}

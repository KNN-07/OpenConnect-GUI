// SPDX-License-Identifier: GPL-3.0-only
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::sync::atomic::Ordering;
use tauri::{Emitter, Manager};
mod auth_window;
mod commands;
use commands::*;

fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
pub fn refresh_tray(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let profiles = tauri::async_runtime::spawn_blocking(|| {
            ocvpn_client::profiles::ProfileStore::open()?.list()
        })
        .await;
        let Ok(Ok(profiles)) = profiles else {
            return;
        };
        let _ = install_tray_menu(&app, &profiles.profiles);
    });
}
fn install_tray_menu(
    app: &tauri::AppHandle,
    profiles: &[ocvpn_model::Profile],
) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, Submenu};
    let menu = Menu::new(app)?;
    let status = MenuItem::with_id(
        app,
        "status",
        "Service state: checking",
        false,
        None::<&str>,
    )?;
    menu.append(&status)?;
    if let Ok(mut item) = app.state::<Desktop>().status_item.lock() {
        *item = Some(status);
    }
    menu.append(&MenuItem::with_id(
        app,
        "show",
        "Show OpenConnect GUI",
        true,
        None::<&str>,
    )?)?;
    let submenu = Submenu::new(app, "Connect profile", true)?;
    for profile in profiles {
        submenu.append(&MenuItem::with_id(
            app,
            format!("profile:{}", profile.id),
            &profile.name,
            true,
            None::<&str>,
        )?)?;
    }
    menu.append(&submenu)?;
    for (id, label) in [
        ("disconnect", "Disconnect"),
        ("quit", "Quit UI (keep tunnel)"),
        ("disconnect-quit", "Disconnect and quit"),
    ] {
        menu.append(&MenuItem::with_id(app, id, label, true, None::<&str>)?)?;
    }
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu))?;
    }
    Ok(())
}
async fn tray_host_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Creating an AppIndicator does not prove that the desktop has a tray host.
        // Never hide the only window behind an unregistered indicator.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let Ok(connection) = zbus::Connection::session().await else {
                return false;
            };
            for name in [
                "org.kde.StatusNotifierWatcher",
                "org.freedesktop.StatusNotifierWatcher",
            ] {
                if let Ok(proxy) =
                    zbus::Proxy::new(&connection, name, "/StatusNotifierWatcher", name).await
                {
                    if proxy
                        .get_property::<bool>("IsStatusNotifierHostRegistered")
                        .await
                        .unwrap_or(false)
                    {
                        return true;
                    }
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}
fn main() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--auth-window")
    {
        if auth_window::run().is_err() {
            std::process::exit(3);
        }
        return;
    }
    let app = tauri::Builder::default().manage(Desktop::default())
        .invoke_handler(tauri::generate_handler![profiles,new_profile,save_profile,duplicate_profile,remove_profile,import_profiles,export_profiles,choose_certificate,read_settings,save_settings,forget_credentials,doctor,licenses,manage_service,approval_settings,disconnect,snapshot,observe,begin_connection,cancel_connection,auth_reply,certificate_reply,browser_reply,browser_clipboard,export_diagnostics,quit_ui])
        .setup(|app| {
            let config = app.config().app.windows.first().ok_or("missing main window configuration")?;
            tauri::WebviewWindowBuilder::from_config(app, config)?
                .on_navigation(|url| {
                    let packaged = (url.scheme() == "tauri" && url.host_str() == Some("localhost")) || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"));
                    let development = cfg!(debug_assertions) && url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port() == Some(1420);
                    (packaged || development) && url.username().is_empty() && url.password().is_none()
                }).on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny).build()?;
            let mut tray = tauri::tray::TrayIconBuilder::with_id("main").tooltip("OpenConnect GUI — checking service");
            if let Some(icon) = app.default_window_icon() { tray = tray.icon(icon.clone()); }
            let result = tray.on_menu_event(|app, event| {
                let id = event.id().as_ref();
                if id == "show" { show(app); }
                else if let Some(profile) = id.strip_prefix("profile:") { show(app); let _ = app.emit_to("main", "tray-connect", profile); }
                else if id == "disconnect" { let app = app.clone(); tauri::async_runtime::spawn(async move { if let Err(error) = ocvpn_client::daemon::disconnect().await { show(&app); let _ = app.emit_to("main", "desktop-error", error); } }); }
                else if id == "quit" || id == "disconnect-quit" {
                    let app = app.clone(); let disconnect = id == "disconnect-quit";
                    tauri::async_runtime::spawn(async move { if let Err(error) = quit_ui(app.clone(), disconnect).await { show(&app); let _ = app.emit_to("main", "desktop-error", error); } });
                }
            }).build(app);
            app.state::<Desktop>().tray.store(result.is_ok(), Ordering::SeqCst);
            refresh_tray(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main" { return; }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close(); let app = window.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    stop_pending(&app).await;
                    let connected = ocvpn_client::daemon::snapshot().await.is_ok_and(|s| matches!(s.state, ocvpn_model::ConnectionState::Connected | ocvpn_model::ConnectionState::Reconnecting));
                    if connected && !app.state::<Desktop>().close_explained.swap(true, Ordering::SeqCst) {
                        rfd::AsyncMessageDialog::new().set_title("Your VPN stays connected").set_description("Closing OpenConnect GUI does not disconnect the tunnel. Use Disconnect in the tray, CLI or TUI to stop it. Quit UI keeps the tunnel; Disconnect and quit stops both.").show().await;
                    }
                    let close_to_tray = tauri::async_runtime::spawn_blocking(|| ocvpn_client::profiles::ProfileStore::open()?.settings()).await.ok().and_then(|v| v.ok()).is_some_and(|s| s.settings.close_to_tray);
                    if close_to_tray && app.state::<Desktop>().tray.load(Ordering::SeqCst) && tray_host_available().await { if let Some(window) = app.get_webview_window("main") { let _ = window.hide(); } }
                    else { let _ = quit_ui(app, false).await; }
                });
            }
        }).build(tauri::generate_context!()).expect("could not run OpenConnect GUI");
    app.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            if !app.state::<Desktop>().quitting.load(Ordering::SeqCst) {
                api.prevent_exit();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = quit_ui(app, false).await;
                });
            }
        }
    });
}

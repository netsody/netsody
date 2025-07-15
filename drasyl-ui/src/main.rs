#![windows_subsystem = "windows"]

mod app;
mod glow_tools;
mod user_event;

use app::App;
use arboard::Clipboard;
use drasyl_sdn::rest_api;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::time::{self, Duration};
use tracing::{trace, warn};
use tray_icon::{TrayIconEvent, menu::MenuEvent};
use user_event::UserEvent;
use winit::event_loop::EventLoop;

fn main() {
    tracing_subscriber::fmt::init();

    trace!("Starting drasyl-ui");

    let event_loop = EventLoop::<UserEvent>::with_user_event().build().unwrap();

    #[allow(unused_variables, unused_mut)]
    let (tx, mut rx): (Sender<UserEvent>, Receiver<UserEvent>) = channel(100);

    // start tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let rt = Arc::new(rt);

    let clipboard = Clipboard::new().expect("Failed to create clipboard");
    let proxy = event_loop.create_proxy();
    let mut app = App::new(tx.clone(), proxy, rt.clone(), clipboard);

    // set a tray event handler that forwards the event and wakes up the event loop
    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::TrayIconEvent(event));
    }));
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::MenuEvent(event));
    }));

    // start background job
    #[cfg(target_os = "linux")]
    let tx_clone = tx.clone();
    #[cfg(not(target_os = "linux"))]
    let proxy = event_loop.create_proxy();
    rt.spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;

            let client = rest_api::RestApiClient::new();
            let event = match client.status().await {
                Ok(status) => UserEvent::Status(Ok(status)),
                Err(e) => {
                    warn!("Failed to retrieve status: {}", e);
                    UserEvent::Status(Err(e.to_string()))
                }
            };
            #[cfg(target_os = "linux")]
            let _ = tx_clone.send(event).await;
            #[cfg(not(target_os = "linux"))]
            let _ = proxy.send_event(event);
        }
    });

    // since winit doesn't use gtk on Linux, and we need gtk for
    // the tray icon to show up, we need to spawn a thread
    // where we initialize gtk and create the tray_icon
    #[cfg(target_os = "linux")]
    {
        let status = app.status.clone();
        std::thread::spawn(move || {
            gtk::init().unwrap();
            let (_tray_icon, menu) = App::new_tray_icon();
            trace!("Starting gtk main loop");

            loop {
                // process GUI events
                while gtk::events_pending() {
                    gtk::main_iteration_do(false);
                }

                // process commands from channel
                match rx.try_recv() {
                    Ok(UserEvent::Status(result)) => {
                        App::update_menu_items(&menu, &result);
                        status.lock().expect("Mutex poisoned").replace(result);
                    }
                    Ok(UserEvent::Quit) => {
                        break;
                    }
                    _ => {}
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            trace!("Exiting gtk main loop");
            std::process::exit(0);
        });
    }

    if let Err(err) = event_loop.run_app(&mut app) {
        println!("Error: {err:?}");
    }
}

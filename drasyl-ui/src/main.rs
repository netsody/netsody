use arboard::Clipboard;
use drasyl_sdn::rest_api;
use drasyl_sdn::rest_api::Status;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::time::{self, Duration};
use tracing::{trace, warn};
use tray_icon::menu::MenuId;
use tray_icon::{
    TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use winit::{application::ApplicationHandler, event_loop::EventLoop};

#[allow(clippy::large_enum_variant)]
enum UserEvent {
    TrayIconEvent(TrayIconEvent),
    MenuEvent(MenuEvent),
    Status(Result<Status, String>),
    Quit,
}

struct DrasylUi {
    sender: Sender<UserEvent>,
    tray_icon: Option<TrayIcon>,
    status: Option<Result<Status, String>>,
    address_item: Option<MenuItem>,
}

impl DrasylUi {
    fn new(sender: Sender<UserEvent>) -> Self {
        Self {
            sender,
            tray_icon: None,
            status: None,
            address_item: None,
        }
    }

    fn new_address_item() -> MenuItem {
        MenuItem::with_id(
            "address",
            "Waiting for drasyl service to become available…",
            false,
            None,
        )
    }

    fn new_tray_icon(address_item: &MenuItem) -> TrayIcon {
        // Embed the tray icon directly in the binary
        let icon_bytes = include_bytes!("../resources/tray-icon.png");
        let icon = load_icon_from_bytes(icon_bytes);

        TrayIconBuilder::new()
            .with_menu(Box::new(Self::new_tray_menu(address_item)))
            .with_tooltip("drasyl")
            .with_icon(icon)
            .with_icon_as_template(true)
            .build()
            .unwrap()
    }

    fn new_tray_menu(address_item: &MenuItem) -> Menu {
        trace!("Creating tray menu");
        let menu = Menu::new();

        // address
        trace!("Adding address item");
        if let Err(e) = menu.append(address_item) {
            panic!("{e:?}");
        }

        // separator
        trace!("Adding separator");
        if let Err(e) = menu.append(&PredefinedMenuItem::separator()) {
            panic!("{e:?}");
        }

        // quit
        trace!("Adding quit item");
        #[cfg(target_os = "linux")]
        let quit_item = &MenuItem::with_id("quit", "Quit drasyl UI", true, None);
        #[cfg(not(target_os = "linux"))]
        let quit_item = &PredefinedMenuItem::quit(Some("Quit drasyl UI"));
        if let Err(e) = menu.append(quit_item) {
            panic!("{e:?}");
        }

        menu
    }
}

impl ApplicationHandler<UserEvent> for DrasylUi {
    fn resumed(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {}

    fn window_event(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        _window_id: winit::window::WindowId,
        _event: winit::event::WindowEvent,
    ) {
    }

    fn new_events(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        cause: winit::event::StartCause,
    ) {
        // We create the icon once the event loop is actually running
        // to prevent issues like https://github.com/tauri-apps/tray-icon/issues/90
        if winit::event::StartCause::Init == cause {
            #[cfg(not(target_os = "linux"))]
            {
                self.address_item = Some(DrasylUi::new_address_item());
                self.tray_icon = Some(DrasylUi::new_tray_icon(self.address_item.as_ref().unwrap()));
            }

            // We have to request a redraw here to have the icon actually show up.
            // Winit only exposes a redraw method on the Window so we use core-foundation directly.
            #[cfg(target_os = "macos")]
            {
                use objc2_core_foundation::CFRunLoop;

                let rl = CFRunLoop::main().unwrap();
                rl.wake_up();
            }
        }
    }

    fn user_event(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(menu_event) => match menu_event.id {
                id if id == MenuId::new("address") => {
                    trace!("Address item clicked");
                    if let Some(Ok(status)) = self.status.as_ref() {
                        if let Ok(mut clipboard) = Clipboard::new() {
                            let _ = clipboard.set_text(status.opts.id.pk.to_string());
                        }
                    }
                }
                id if id == MenuId::new("quit") => {
                    trace!("Quit item clicked");
                    let _ = self.sender.try_send(UserEvent::Quit);
                }
                _ => {}
            },
            UserEvent::Status(result) => {
                if let Some(address_item) = self.address_item.as_ref() {
                    match &result {
                        Ok(status) => {
                            let pk = status.opts.id.pk;
                            address_item.set_text(format!("Public key: {}", pk));
                            address_item.set_enabled(true);
                        }
                        Err(e) => {
                            address_item.set_text(e);
                            address_item.set_enabled(false);
                        }
                    }
                }
                self.status = Some(result);
            }
            _ => {}
        }
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    trace!("Starting drasyl-ui");

    #[allow(unused_variables, unused_mut)]
    let (tx, mut rx): (Sender<UserEvent>, Receiver<UserEvent>) = channel(100);
    let mut app = DrasylUi::new(tx.clone());

    let event_loop = EventLoop::<UserEvent>::with_user_event().build().unwrap();

    // set a tray event handler that forwards the event and wakes up the event loop
    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::TrayIconEvent(event));
    }));
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::MenuEvent(event));
    }));

    // Start Tokio Runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Start background job
    #[cfg(target_os = "linux")]
    let tx_clone = tx.clone();
    #[cfg(not(target_os = "linux"))]
    let proxy = event_loop.create_proxy();
    rt.spawn(async move {
        let mut interval = time::interval(Duration::from_secs(10));
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

    // Since winit doesn't use gtk on Linux, and we need gtk for
    // the tray icon to show up, we need to spawn a thread
    // where we initialize gtk and create the tray_icon
    #[cfg(target_os = "linux")]
    {
        std::thread::spawn(move || {
            gtk::init().unwrap();
            let address_item = DrasylUi::new_address_item();
            let _tray_icon = DrasylUi::new_tray_icon(&address_item);
            trace!("Starting gtk main loop");

            loop {
                // Process GUI events
                while gtk::events_pending() {
                    gtk::main_iteration_do(false);
                }

                // Process commands from channel
                match rx.try_recv() {
                    Ok(UserEvent::Status(Ok(status))) => {
                        let pk = status.opts.id.pk;
                        address_item.set_text(format!("Public key: {}", pk));
                        address_item.set_enabled(true);
                    }
                    Ok(UserEvent::Status(Err(e))) => {
                        address_item.set_text(e);
                        address_item.set_enabled(false);
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
        println!("Error: {:?}", err);
    }
}

fn load_icon_from_bytes(icon_bytes: &[u8]) -> tray_icon::Icon {
    let (icon_rgba, icon_width, icon_height) = {
        let image = image::load_from_memory(icon_bytes)
            .expect("Failed to open icon bytes")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };
    tray_icon::Icon::from_rgba(icon_rgba, icon_width, icon_height).expect("Failed to open icon")
}

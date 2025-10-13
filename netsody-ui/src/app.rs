use crate::glow_tools::GlutinWindowContext;
use crate::user_event::UserEvent;
use agent::rest_api;
use agent::rest_api::{NetworkStatus, Status, mask_url};
use arboard::Clipboard;
use ipnet::Ipv4Net;
use rest_api::RestApiClient;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::Sender;
use tracing::{trace, warn};
use tray_icon::menu::accelerator::{Accelerator, CMD_OR_CTRL, Code};
use tray_icon::menu::{
    CheckMenuItem, Menu, MenuId, MenuItem, MenuItemKind, PredefinedMenuItem, Submenu,
};
use tray_icon::{TrayIcon, TrayIconBuilder};
use url::Url;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;

pub struct App {
    sender: Sender<UserEvent>,
    tray_icon: Option<TrayIcon>,
    menu: Option<Menu>,
    pub(crate) status: Arc<Mutex<Option<Result<Status, String>>>>,
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
    rt: Arc<Runtime>,
    clipboard: Clipboard,
    // add network modal
    gl_window: Option<GlutinWindowContext>,
    gl: Option<Arc<glow::Context>>,
    egui_glow: Option<egui_glow::EguiGlow>,
    config_url: String,
    repaint_delay: std::time::Duration,
    token_path: String,
    // confirmation dialog state
    network_to_remove: Option<String>,
}

impl App {
    pub(crate) fn new(
        sender: Sender<UserEvent>,
        proxy: winit::event_loop::EventLoopProxy<UserEvent>,
        rt: Arc<Runtime>,
        clipboard: Clipboard,
        token_path: String,
    ) -> Self {
        Self {
            sender,
            tray_icon: None,
            menu: None,
            status: Arc::new(Mutex::new(None)),
            proxy,
            rt,
            clipboard,
            gl_window: None,
            gl: None,
            egui_glow: None,
            config_url: String::new(),
            repaint_delay: std::time::Duration::MAX,
            token_path,
            network_to_remove: None,
        }
    }

    pub(crate) fn update_menu_items(menu: &Menu, result: &Result<Status, String>) {
        let mut position: usize = 0;
        let mut positions_to_delete = vec![];
        let mut existing_networks = vec![];
        menu.items().iter_mut().for_each(|kind| {
            match kind {
                MenuItemKind::MenuItem(item) => {
                    let id = item.id();
                    match id {
                        id if id == &MenuId::new("address") => match result {
                            Ok(status) => {
                                let pk = status.opts.id.pk;
                                item.set_text(format!("Public Key: {pk}"));
                                item.set_enabled(true);
                            }
                            Err(e) => {
                                item.set_text(e);
                                item.set_enabled(false);
                            }
                        },
                        id if id == &MenuId::new("add_network") => match result {
                            Ok(_) => {
                                item.set_enabled(true);
                            }
                            Err(_) => {
                                item.set_enabled(false);
                            }
                        },
                        _ => {}
                    }
                }
                MenuItemKind::Submenu(submenu) => {
                    let id = submenu.id();
                    match id {
                        id if id.0.starts_with("network ") => match result {
                            Ok(status) => {
                                let config_url_str = id.0.split_once(' ').unwrap().1;

                                if let Ok(config_url) = Url::parse(config_url_str) {
                                    if let Some(network) = status.networks.get(&config_url) {
                                        let new_text =
                                            Self::network_display_text(&config_url, network);

                                        // On Linux, submenu text cannot be changed directly
                                        // If the text has changed, we need to recreate the submenu
                                        // by adding it to the deletion list so it gets rebuilt
                                        if cfg!(target_os = "linux") && submenu.text() != new_text {
                                            positions_to_delete.push(position);
                                        } else {
                                            // we do not add the network to the existing networks
                                            // list on linux when text has changed, because it needs
                                            // to be recreated, so we will add it again below
                                            existing_networks.push(config_url_str.to_string());
                                            submenu.set_text(new_text);
                                        }

                                        submenu.items().iter_mut().for_each(|kind| {
                                            if let MenuItemKind::MenuItem(item) = kind {
                                                let id = item.id();
                                                match id {
                                                    id if id.0.starts_with("network_status ") => {
                                                        let tabs = if cfg!(target_os = "linux") {
                                                            "\t\t"
                                                        } else {
                                                            "\t"
                                                        };
                                                        item.set_text(format!(
                                                            "Status:{tabs}  {0}",
                                                            network.status_text()
                                                        ));
                                                    }
                                                    id if id.0.starts_with("network_ip ") => {
                                                        let tabs = if cfg!(target_os = "linux") {
                                                            "\t\t\t\t"
                                                        } else {
                                                            "\t\t"
                                                        };
                                                        item.set_text(format!(
                                                            "IP:{tabs}  {0}",
                                                            Self::network_ip(network)
                                                                .map_or("None".to_string(), |ip| {
                                                                    ip.to_string()
                                                                })
                                                        ));
                                                    }
                                                    _ => {}
                                                }
                                            } else if let MenuItemKind::Check(item) = kind {
                                                let id = item.id();
                                                match id {
                                                    id if id.0.starts_with("network_enabled ") => {
                                                        item.set_checked(!network.disabled);
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        });
                                    } else {
                                        positions_to_delete.push(position);
                                    }
                                }
                            }
                            Err(_) => {
                                positions_to_delete.push(position);
                            }
                        },
                        id if id == &MenuId::new("about") => {
                            submenu.items().iter_mut().for_each(|kind| {
                                if let MenuItemKind::MenuItem(item) = kind {
                                    let id = item.id();
                                    match id {
                                        id if id == &MenuId::new("version_agent") => match result {
                                            Ok(status) => {
                                                let tabs = if cfg!(target_os = "linux") {
                                                    "\t\t"
                                                } else {
                                                    "\t"
                                                };
                                                item.set_text(format!(
                                                    "Agent:{tabs}  {0} ({1})",
                                                    status.version_info.version,
                                                    status.version_info.full_commit()
                                                ));
                                            }
                                            Err(_) => {
                                                item.set_text("Agent:");
                                            }
                                        },
                                        _ => {}
                                    }
                                }
                            });
                        }
                        _ => {}
                    }
                }
                MenuItemKind::Predefined(_) => {}
                MenuItemKind::Check(_) => {}
                MenuItemKind::Icon(_) => {}
            }

            position += 1;
        });

        // remove items for removed networks
        for position in positions_to_delete.iter().rev() {
            menu.remove_at(*position);
        }

        // add items for new networks
        if let Ok(status) = result {
            // Collect all networks and sort them
            let mut networks_to_add: Vec<_> = status.networks.iter().collect();

            // Sort by URL
            networks_to_add.sort_by(|(url_a, _), (url_b, _)| url_a.as_str().cmp(url_b.as_str()));

            let mut position = 0;
            for (config_url, network) in networks_to_add {
                let config_url_str = config_url.to_string();

                if existing_networks.contains(&config_url_str) {
                    position += 1;
                    continue;
                }

                let display_text = Self::network_display_text(config_url, network);
                let submenu =
                    Submenu::with_id(format!("network {config_url_str}"), display_text, true);

                // copy action
                let item = MenuItem::with_id(
                    format!("copy_network {config_url_str}"),
                    "Copy Network URL",
                    true,
                    None,
                );
                if let Err(e) = submenu.append(&item) {
                    panic!("{e:?}");
                }

                // separator
                trace!("Adding separator");
                if let Err(e) = submenu.append(&PredefinedMenuItem::separator()) {
                    panic!("{e:?}");
                }

                // Status
                let tabs = if cfg!(target_os = "linux") {
                    "\t\t"
                } else {
                    "\t"
                };
                let item = MenuItem::with_id(
                    format!("network_status {config_url_str}"),
                    format!("Status:{tabs}  {0}", network.status_text()),
                    true,
                    None,
                );
                if let Err(e) = submenu.append(&item) {
                    panic!("{e:?}");
                }

                // IP
                let tabs = if cfg!(target_os = "linux") {
                    "\t\t\t\t"
                } else {
                    "\t\t"
                };
                let item = MenuItem::with_id(
                    format!("network_ip {config_url_str}"),
                    format!(
                        "IP:{tabs}  {0}",
                        Self::network_ip(network).map_or("None".to_string(), |ip| ip.to_string())
                    ),
                    true,
                    None,
                );
                if let Err(e) = submenu.append(&item) {
                    panic!("{e:?}");
                }

                // separator
                trace!("Adding separator");
                if let Err(e) = submenu.append(&PredefinedMenuItem::separator()) {
                    panic!("{e:?}");
                }

                // enable/disable action
                let item = CheckMenuItem::with_id(
                    format!("network_enabled {config_url_str}"),
                    "Enabled",
                    true,
                    !network.disabled,
                    None,
                );
                if let Err(e) = submenu.append(&item) {
                    panic!("{e:?}");
                }

                // separator
                trace!("Adding separator");
                if let Err(e) = submenu.append(&PredefinedMenuItem::separator()) {
                    panic!("{e:?}");
                }

                // remove action
                let item = MenuItem::with_id(
                    format!("remove_network {config_url_str}"),
                    "Remove…",
                    true,
                    None,
                );
                if let Err(e) = submenu.append(&item) {
                    panic!("{e:?}");
                }

                if let Err(e) = menu.insert(&submenu, 3 + position) {
                    panic!("{e:?}");
                }
                position += 1;
            }
        }
    }

    fn network_display_text(config_url: &Url, network: &NetworkStatus) -> String {
        let mut display_text = match network.name.as_ref() {
            Some(name) => Self::sanitize_menu_text(name),
            None => mask_url(config_url),
        };

        // Add enabled/disabled indicator at the beginning
        let status_icon = if cfg!(target_os = "windows") {
            // do not use tabs on windows, because they are used for mnemonics
            if network.disabled { "     " } else { "✓  " }
        } else if network.disabled {
            "\t"
        } else {
            "✓\t"
        };
        display_text = format!("{status_icon}{display_text}");

        display_text
    }

    fn network_ip(network: &NetworkStatus) -> Option<Ipv4Net> {
        network.current_state.ip.applied
    }

    /// Sanitizes text for use in menu items by only allowing safe characters
    pub(crate) fn sanitize_menu_text(text: &str) -> String {
        let mut sanitized = String::with_capacity(text.len());

        for ch in text.chars() {
            // Whitelist: Only allow explicitly safe characters
            match ch {
                // Basic Latin letters and numbers
                'a'..='z' | 'A'..='Z' | '0'..='9' => {
                    sanitized.push(ch);
                }
                // Common punctuation and symbols that are safe for menu display
                ' ' | '-' | '_' | '.' | ',' | ':' | '(' | ')' | '[' | ']' | '!' | '?' | '&' => {
                    sanitized.push(ch);
                }
                // German umlauts and special characters (common in German network names)
                'ä' | 'ö' | 'ü' | 'Ä' | 'Ö' | 'Ü' | 'ß' => {
                    sanitized.push(ch);
                }
                // All other characters are ignored/removed
                _ => {
                    // Skip any character not in the whitelist
                }
            }
        }

        // Trim whitespace and limit length
        sanitized = sanitized.trim().to_string();
        if sanitized.len() > 100 {
            sanitized.truncate(97);
            sanitized.push_str("...");
        }

        // If sanitization resulted in empty string, provide a fallback
        if sanitized.is_empty() {
            sanitized = "Unnamed Network".to_string();
        }

        sanitized
    }

    pub(crate) fn new_tray_icon() -> (TrayIcon, Menu) {
        // Embed the tray icon directly in the binary
        let icon_bytes: &[u8] = if !cfg!(target_os = "windows") {
            include_bytes!("../resources/tray-icon.png")
        } else {
            include_bytes!("../resources/tray-icon-windows.png")
        };
        let icon = Self::load_icon_from_bytes(icon_bytes);

        let menu = Self::new_tray_menu();
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip("Netsody")
            .with_icon(icon)
            .with_icon_as_template(true)
            .build()
            .unwrap();
        (tray_icon, menu)
    }

    fn new_tray_menu() -> Menu {
        trace!("Creating tray menu");
        let menu = Menu::new();

        // address
        trace!("Adding address item");
        let item = MenuItem::with_id(
            "address",
            "Waiting for Netsody service to become available…",
            false,
            Some(Accelerator::new(Some(CMD_OR_CTRL), Code::KeyC)),
        );
        if let Err(e) = menu.append(&item) {
            panic!("{e:?}");
        }

        // add network
        trace!("Adding 'add network' item");
        let item = MenuItem::with_id(
            "add_network",
            "Add Network…",
            false,
            Some(Accelerator::new(Some(CMD_OR_CTRL), Code::KeyN)),
        );
        if let Err(e) = menu.append(&item) {
            panic!("{e:?}");
        }

        // separator
        trace!("Adding separator");
        if let Err(e) = menu.append(&PredefinedMenuItem::separator()) {
            panic!("{e:?}");
        }

        // separator
        trace!("Adding separator");
        if let Err(e) = menu.append(&PredefinedMenuItem::separator()) {
            panic!("{e:?}");
        }

        // add about
        let about = Submenu::with_id("about", "About", true);
        if let Err(e) = menu.append(&about) {
            panic!("{e:?}");
        }

        // ui version
        trace!("Adding UI version item");

        let version = Self::version_ui();

        let tabs = if cfg!(target_os = "linux") {
            "\t\t\t"
        } else {
            "\t\t"
        };
        let item = MenuItem::with_id("version_ui", format!("UI:{tabs}  {version}"), true, None);
        if let Err(e) = about.append(&item) {
            panic!("{e:?}");
        }

        let item = MenuItem::with_id("version_agent", "Agent:", true, None);
        if let Err(e) = about.append(&item) {
            panic!("{e:?}");
        }

        // copy agent status (masked by default)
        let item = MenuItem::with_id(
            "copy_agent_status",
            "Copy Agent Status to Clipboard",
            true,
            None,
        );
        if let Err(e) = about.append(&item) {
            panic!("{e:?}");
        }

        // separator
        trace!("Adding separator");
        if let Err(e) = about.append(&PredefinedMenuItem::separator()) {
            panic!("{e:?}");
        }

        // Website
        trace!("Adding Website item");
        let item = MenuItem::with_id("website", "Website", true, None);
        if let Err(e) = about.append(&item) {
            panic!("{e:?}");
        }

        // GitHub
        trace!("Adding GitHub item");
        let item = MenuItem::with_id("github", "GitHub", true, None);
        if let Err(e) = about.append(&item) {
            panic!("{e:?}");
        }

        // separator
        trace!("Adding separator");
        if let Err(e) = menu.append(&PredefinedMenuItem::separator()) {
            panic!("{e:?}");
        }

        // quit
        trace!("Adding quit item");
        if cfg!(target_os = "windows") || cfg!(target_os = "linux") {
            let quit_item = MenuItem::with_id("quit", "Quit Netsody UI", true, None);
            if let Err(e) = menu.append(&quit_item) {
                panic!("{e:?}");
            }
        } else {
            let quit_item = PredefinedMenuItem::quit(Some("Quit Netsody UI"));
            if let Err(e) = menu.append(&quit_item) {
                panic!("{e:?}");
            }
        }

        menu
    }

    fn version_ui() -> String {
        // extract version information from build-time environment variables
        let version = env!("CARGO_PKG_VERSION");
        let git_commit = env!("VERGEN_GIT_SHA");
        let git_dirty = env!("VERGEN_GIT_DIRTY");

        // combine git commit hash with dirty flag
        let full_commit = if git_dirty == "true" {
            format!("{git_commit}-dirty")
        } else {
            git_commit.to_string()
        };
        let version = format!("{version} ({full_commit})");
        version
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
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {}

    fn window_event(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        _window_id: winit::window::WindowId,
        event: WindowEvent,
    ) {
        trace!("Window event: {:?}", event);

        match event {
            WindowEvent::CloseRequested => {
                trace!("Window close requested");
                self.config_url.clear();
                self.network_to_remove = None;
                self.gl_window.take();
                self.gl.take();
                self.egui_glow.take();
            }
            WindowEvent::RedrawRequested => {
                let mut cancel = false;

                self.egui_glow.as_mut().unwrap().run(
                    self.gl_window.as_mut().unwrap().window(),
                    |egui_ctx| {
                        egui::CentralPanel::default().show(egui_ctx, |ui| {
                            if let Some(network_url) = &self.network_to_remove {
                                // Confirmation dialog for removing network
                                // Get network name/URL for display
                                let display_text = if let Some(Ok(status)) =
                                    self.status.lock().expect("Mutex poisoned").as_ref()
                                {
                                    if let Ok(url) = Url::parse(network_url) {
                                        if let Some(network) = status.networks.get(&url) {
                                            match network.name.as_ref() {
                                                Some(name) => Self::sanitize_menu_text(name),
                                                None => mask_url(&url),
                                            }
                                        } else {
                                            network_url.clone()
                                        }
                                    } else {
                                        network_url.clone()
                                    }
                                } else {
                                    network_url.clone()
                                };

                                ui.vertical_centered(|ui| {
                                    ui.label(format!(
                                        "Are you sure you want to remove the network »{}«?",
                                        display_text
                                    ));
                                });
                                ui.add_space(10.0);

                                // Check for Escape key press
                                let input = ui.input(|i| i.clone());
                                if input.key_pressed(egui::Key::Escape) {
                                    trace!("Cancel remove action triggered");
                                    cancel = true;
                                }

                                // buttons - centered
                                ui.horizontal(|ui| {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            // Add flexible space to center the buttons
                                            ui.allocate_space(egui::Vec2::new(
                                                ui.available_width() * 0.5 - 60.0,
                                                0.0,
                                            ));

                                            if ui.button("Remove").clicked() {
                                                let url = network_url.clone();
                                                trace!(
                                                    "Confirmed removing network with URL: {}",
                                                    url
                                                );

                                                self.rt.block_on(async {
                                                    let client =
                                                        RestApiClient::new(self.token_path.clone());
                                                    match client.remove_network(&url).await {
                                                        Ok(_) => {
                                                            trace!("Removed network: {url}");
                                                        }
                                                        Err(e) => {
                                                            trace!(
                                                                "Failed to remove network: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                });
                                                cancel = true;
                                            }

                                            if ui.button("Cancel").clicked() {
                                                trace!("Cancel remove action triggered");
                                                cancel = true;
                                            }
                                        },
                                    );
                                });
                            } else {
                                // Add network dialog
                                // Helper function to add network
                                let add_network = |url: String| {
                                    if Url::parse(url.trim()).is_ok() {
                                        // send event for processing
                                        self.proxy
                                            .send_event(UserEvent::AddNetwork(url))
                                            .expect("Failed to send event");
                                        true // return true to indicate success
                                    } else {
                                        false
                                    }
                                };

                                // URL input field
                                ui.label("Network configuration URL (https:// or file://):");
                                let response = ui.add_sized(
                                    [ui.available_width() * 1.0, 0.0],
                                    egui::TextEdit::singleline(&mut self.config_url)
                                        .hint_text("https://example.com/network-config.toml"),
                                );
                                // automatically set focus on the text field
                                response.request_focus();

                                // Check for Enter key press
                                let input = ui.input(|i| i.clone());
                                if input.key_pressed(egui::Key::Enter) {
                                    let url = self.config_url.clone();
                                    if add_network(url) {
                                        cancel = true;
                                    }
                                }

                                // Check for Escape key press
                                if input.key_pressed(egui::Key::Escape) {
                                    trace!("Cancel action triggered");
                                    cancel = true;
                                }

                                ui.add_space(10.0);

                                // buttons
                                ui.horizontal(|ui| {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.button("Add").clicked() {
                                                let url = self.config_url.clone();
                                                if add_network(url) {
                                                    cancel = true;
                                                }
                                            }

                                            if ui.button("Cancel").clicked() {
                                                trace!("Cancel action triggered");
                                                cancel = true;
                                            }
                                        },
                                    );
                                });
                            }
                        });
                    },
                );

                if cancel {
                    self.config_url.clear();
                    self.network_to_remove = None;
                    self.gl_window.take();
                    self.gl.take();
                    self.egui_glow.take();
                    return;
                } else {
                    // event_loop.set_control_flow(if self.repaint_delay.is_zero() {
                    //     self.gl_window.as_mut().unwrap().window().request_redraw();
                    //     winit::event_loop::ControlFlow::Poll
                    // } else if let Some(repaint_after_instant) =
                    //     std::time::Instant::now().checked_add(self.repaint_delay)
                    // {
                    //     winit::event_loop::ControlFlow::WaitUntil(repaint_after_instant)
                    // } else {
                    //     winit::event_loop::ControlFlow::Wait
                    // });
                }

                {
                    unsafe {
                        use glow::HasContext as _;
                        self.gl.as_mut().unwrap().clear(glow::COLOR_BUFFER_BIT);
                    }

                    if let (Some(egui_glow), Some(gl_window)) =
                        (self.egui_glow.as_mut(), self.gl_window.as_mut())
                    {
                        // draw things behind egui here
                        egui_glow.paint(gl_window.window());

                        // draw things on top of egui here
                        gl_window.swap_buffers().unwrap();
                        if !gl_window.window().is_visible().unwrap_or(true) {
                            gl_window.window().set_visible(true);
                        }
                    }
                }

                return;
            }
            WindowEvent::Resized(physical_size) => {
                self.gl_window.as_mut().unwrap().resize(physical_size);
            }
            _ => {}
        }

        if let Some(egui_glow) = self.egui_glow.as_mut() {
            let event_response =
                egui_glow.on_window_event(self.gl_window.as_mut().unwrap().window(), &event);
            if event_response.repaint {
                self.gl_window.as_mut().unwrap().window().request_redraw();
            }
        }
    }

    fn new_events(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        cause: winit::event::StartCause,
    ) {
        // we create the icon once the event loop is actually running
        // to prevent issues like https://github.com/tauri-apps/tray-icon/issues/90
        if winit::event::StartCause::Init == cause {
            #[cfg(not(target_os = "linux"))]
            {
                let (tray_icon, menu) = App::new_tray_icon();
                self.tray_icon = Some(tray_icon);
                self.menu = Some(menu);
            }

            // we have to request a redraw here to have the icon actually show up.
            // winit only exposes a redraw method on the Window so we use core-foundation directly.
            #[cfg(target_os = "macos")]
            {
                use objc2_core_foundation::CFRunLoop;

                let rl = CFRunLoop::main().unwrap();
                rl.wake_up();
            }
        }
    }

    fn user_event(&mut self, event_loop: &winit::event_loop::ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(menu_event) => {
                trace!("Menu event: {:?}", menu_event);
                match menu_event.id {
                    id if id == MenuId::new("address") => {
                        trace!("Address item clicked");

                        if let Some(Ok(status)) =
                            self.status.lock().expect("Mutex poisoned").as_ref()
                        {
                            let address = status.opts.id.pk.to_string();
                            if let Err(e) = self.clipboard.set_text(address) {
                                warn!("Failed to copy address to clipboard: {}", e);
                            } else {
                                trace!(
                                    "Copied address to clipboard: {}",
                                    status.opts.id.pk.to_string()
                                );
                            }
                        } else {
                            trace!("Status is not yet available");
                        }
                    }
                    id if id == MenuId::new("add_network") => {
                        trace!("Add network item clicked");

                        // Close all existing windows/dialogs first
                        self.config_url.clear();
                        self.network_to_remove = None;
                        self.gl_window.take();
                        self.gl.take();
                        self.egui_glow.take();

                        // create window if it doesn't exist yet
                        if let Some(gl_window) = self.gl_window.as_mut() {
                            gl_window.window().focus_window();
                        } else {
                            let (gl_window, gl) = crate::glow_tools::create_display(
                                event_loop,
                                "Add Network",
                                500.0,
                                100.0,
                            );
                            let gl = Arc::new(gl);
                            gl_window.window().set_visible(true);
                            gl_window.window().focus_window();

                            let egui_glow =
                                egui_glow::EguiGlow::new(event_loop, gl.clone(), None, None, true);

                            let event_loop_proxy = egui::mutex::Mutex::new(self.proxy.clone());
                            egui_glow
                                .egui_ctx
                                .set_request_repaint_callback(move |info| {
                                    event_loop_proxy
                                        .lock()
                                        .send_event(UserEvent::Redraw(info.delay))
                                        .expect("Cannot send event");
                                });
                            self.gl_window = Some(gl_window);
                            self.gl = Some(gl);
                            self.egui_glow = Some(egui_glow);
                        }
                    }
                    id if id == MenuId::new("quit") => {
                        trace!("Quit item clicked");
                        if cfg!(target_os = "linux") {
                            let _ = self.sender.try_send(UserEvent::Quit);
                        } else {
                            std::process::exit(0);
                        }
                    }
                    id if id.0.starts_with("remove_network ") => {
                        let url = id.0.split_once(' ').unwrap().1;

                        trace!("Remove network confirmation dialog for URL: {}", url);

                        // Close all existing windows/dialogs first
                        self.config_url.clear();
                        self.network_to_remove = None;
                        self.gl_window.take();
                        self.gl.take();
                        self.egui_glow.take();

                        // Store the network URL to be removed and show confirmation dialog
                        self.network_to_remove = Some(url.to_string());

                        // Create window if it doesn't exist yet
                        if let Some(gl_window) = self.gl_window.as_mut() {
                            gl_window.window().focus_window();
                        } else {
                            let (gl_window, gl) = crate::glow_tools::create_display(
                                event_loop,
                                "Remove Network",
                                400.0,
                                80.0,
                            );
                            let gl = Arc::new(gl);
                            gl_window.window().set_visible(true);
                            gl_window.window().focus_window();

                            let egui_glow =
                                egui_glow::EguiGlow::new(event_loop, gl.clone(), None, None, true);

                            let event_loop_proxy = egui::mutex::Mutex::new(self.proxy.clone());
                            egui_glow
                                .egui_ctx
                                .set_request_repaint_callback(move |info| {
                                    event_loop_proxy
                                        .lock()
                                        .send_event(UserEvent::Redraw(info.delay))
                                        .expect("Cannot send event");
                                });
                            self.gl_window = Some(gl_window);
                            self.gl = Some(gl);
                            self.egui_glow = Some(egui_glow);
                        }
                    }
                    id if id.0.starts_with("network_enabled ") => {
                        let url = id.0.split_once(' ').unwrap().1;

                        trace!("Enable/Disable network with URL: {}", url);

                        if let Some(Ok(status)) =
                            self.status.lock().expect("Mutex poisoned").as_ref()
                        {
                            if let Some(network) = status.networks.get(&Url::parse(url).unwrap()) {
                                if network.disabled {
                                    self.rt.block_on(async {
                                        let client = RestApiClient::new(self.token_path.clone());
                                        match client.enable_network(url).await {
                                            Ok(_) => {
                                                trace!("Enabled network: {url}");
                                            }
                                            Err(e) => {
                                                trace!("Failed to enable network: {}", e);
                                            }
                                        }
                                    });
                                } else {
                                    self.rt.block_on(async {
                                        let client = RestApiClient::new(self.token_path.clone());
                                        match client.disable_network(url).await {
                                            Ok(_) => {
                                                trace!("Disabled network: {url}");
                                            }
                                            Err(e) => {
                                                trace!("Failed to disable network: {}", e);
                                            }
                                        }
                                    });
                                }
                            } else {
                                trace!("Network not found in status");
                            }
                        } else {
                            trace!("No status available");
                        }
                    }
                    id if id.0.starts_with("copy_network ") => {
                        let url = id.0.split_once(' ').unwrap().1;

                        trace!("Copy network URL: {}", url);

                        if let Err(e) = self.clipboard.set_text(url) {
                            warn!("Failed to copy network URL to clipboard: {}", e);
                        } else {
                            trace!("Copied network URL to clipboard: {}", url);
                        }
                    }
                    id if id.0.starts_with("network_status ") => {
                        let url = id.0.split_once(' ').unwrap().1;
                        trace!("Copy network status for network: {}", url);

                        if let Some(Ok(status)) =
                            self.status.lock().expect("Mutex poisoned").as_ref()
                        {
                            if let Some(network) = status.networks.get(&Url::parse(url).unwrap()) {
                                let network_status_string = network.to_string();

                                if let Err(e) = self.clipboard.set_text(network_status_string) {
                                    warn!("Failed to copy network status to clipboard: {}", e);
                                } else {
                                    trace!("Copied network status to clipboard: {}", url);
                                }
                            } else {
                                trace!("Network not found in status");
                            }
                        } else {
                            trace!("No status available");
                        }
                    }
                    id if id.0.starts_with("network_ip ") => {
                        let url = id.0.split_once(' ').unwrap().1;
                        trace!("Copy network IP for network: {}", url);

                        if let Some(Ok(status)) =
                            self.status.lock().expect("Mutex poisoned").as_ref()
                        {
                            if let Some(network) = status.networks.get(&Url::parse(url).unwrap()) {
                                let ip = Self::network_ip(network);

                                if let Err(e) = self.clipboard.set_text(
                                    ip.map_or("None".to_string(), |ip| ip.addr().to_string()),
                                ) {
                                    warn!("Failed to copy network IP to clipboard: {}", e);
                                } else {
                                    trace!("Copied network IP to clipboard: {}", url);
                                }
                            } else {
                                trace!("Network not found in status");
                            }
                        } else {
                            trace!("No status available");
                        }
                    }
                    id if id == MenuId::new("copy_agent_status") => {
                        trace!("Copy Agent Status item clicked");

                        if let Some(Ok(status)) =
                            self.status.lock().expect("Mutex poisoned").as_ref()
                        {
                            let status_text = status.to_string_with_secrets(false);

                            if let Err(e) = self.clipboard.set_text(status_text) {
                                warn!("Failed to copy agent status to clipboard: {}", e);
                            } else {
                                trace!("Copied agent status to clipboard");
                            }
                        } else {
                            trace!("No status available to copy");
                        }
                    }
                    id if id == MenuId::new("website") => {
                        trace!("Website item clicked");
                        if let Err(e) = webbrowser::open("https://netsody.io") {
                            warn!("Failed to open Website: {}", e);
                        }
                    }
                    id if id == MenuId::new("version_ui") => {
                        let version = Self::version_ui();
                        trace!("Copy UI version: {}", version);

                        if let Err(e) = self.clipboard.set_text(version.clone()) {
                            warn!("Failed to copy UI version to clipboard: {}", e);
                        } else {
                            trace!("Copied UI version to clipboard: {}", version);
                        }
                    }
                    id if id == MenuId::new("version_agent") => {
                        let version = if let Some(Ok(status)) =
                            self.status.lock().expect("Mutex poisoned").as_ref()
                        {
                            format!(
                                "{0} ({1})",
                                status.version_info.version,
                                status.version_info.full_commit()
                            )
                        } else {
                            "None".to_string()
                        };

                        trace!("Copy agent version: {}", version);

                        if let Err(e) = self.clipboard.set_text(version.clone()) {
                            warn!("Failed to copy agent version to clipboard: {}", e);
                        } else {
                            trace!("Copied agent version to clipboard: {}", version);
                        }
                    }
                    id if id == MenuId::new("github") => {
                        trace!("GitHub item clicked");
                        if let Err(e) = webbrowser::open("https://github.com/netsody/netsody/") {
                            warn!("Failed to open GitHub: {}", e);
                        }
                    }
                    _ => {}
                }
            }
            UserEvent::Status(result) => {
                if let Some(menu) = self.menu.as_ref() {
                    App::update_menu_items(menu, &result);
                }
                self.status.lock().expect("Mutex poisoned").replace(result);
            }
            UserEvent::AddNetwork(url) => {
                trace!("Adding network with URL: {}", url);

                self.rt.block_on(async {
                    let client = RestApiClient::new(self.token_path.clone());
                    match client.add_network(&url).await {
                        Ok(_) => {
                            trace!("Added network: {url}");
                        }
                        Err(e) => {
                            trace!("Failed to add network: {}", e);
                        }
                    }
                });
            }
            UserEvent::Redraw(delay) => {
                self.repaint_delay = delay;
            }
            _ => {}
        }
    }
}

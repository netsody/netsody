use agent::rest_api::Status;
use std::fmt::{Debug, Formatter};
use tray_icon::TrayIconEvent;
use tray_icon::menu::MenuEvent;

#[allow(clippy::large_enum_variant)]
pub enum UserEvent {
    TrayIconEvent(TrayIconEvent),
    MenuEvent(MenuEvent),
    Status(Result<Status, String>),
    Quit,
    Redraw(std::time::Duration),
    AddNetwork(String),
}

impl Debug for UserEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UserEvent::TrayIconEvent(_) => write!(f, "TrayIconEvent"),
            UserEvent::MenuEvent(_) => write!(f, "MenuEvent"),
            UserEvent::Status(_) => write!(f, "Status"),
            UserEvent::Quit => write!(f, "Quit"),
            UserEvent::Redraw(_) => write!(f, "Redraw"),
            UserEvent::AddNetwork(_) => write!(f, "AddNetwork"),
        }
    }
}

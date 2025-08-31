use crate::network::{EffectiveRoutingList, Network};
use cfg_if::cfg_if;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tun_rs::AsyncDevice;
use url::Url;

pub trait AgentRoutingInterface {
    #[allow(unused_variables)]
    async fn update_network(
        &self,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
        tun_device: Arc<AsyncDevice>,
    ) -> EffectiveRoutingList {
        // do nothing
        EffectiveRoutingList::default()
    }

    #[allow(unused_variables)]
    async fn remove_network(&self, routes: EffectiveRoutingList, tun_device: Arc<AsyncDevice>) {
        // do nothing
    }

    #[allow(unused_variables)]
    async fn shutdown(
        &self,
        networks: Arc<Mutex<HashMap<Url, Network>>>,
        tun_device: Arc<AsyncDevice>,
    ) {
        // do nothing
    }
}

cfg_if! {
    if #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))] {
        mod net_route;
        pub use net_route::AgentRouting;
    }
    else if #[cfg(any(target_os = "ios"))] {
        mod network_listener;
        pub use network_listener::AgentRouting;
    }
    else {
        // unsupported platform
        pub struct AgentRouting {}

        impl AgentRouting {
            pub(crate) fn new() -> Self {
                Self {}
            }
        }

        impl AgentRoutingInterface for AgentRouting {}
    }
}

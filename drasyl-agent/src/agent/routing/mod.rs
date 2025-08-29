#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
mod net_route;

use crate::network::{EffectiveRoutingList, Network};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::trace;
use tun_rs::AsyncDevice;
use url::Url;

pub struct AgentRouting {
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    pub(crate) net_route_handle: Arc<::net_route::Handle>,
}

impl AgentRouting {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
            net_route_handle: Arc::new(
                ::net_route::Handle::new().expect("Failed to create route handle"),
            ),
        }
    }

    pub(crate) async fn shutdown(
        &self,
        networks: Arc<Mutex<HashMap<Url, Network>>>,
        tun_device: Arc<AsyncDevice>,
    ) {
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            trace!("Shutting down routing using net_route");
            self.shutdown_net_route(networks, tun_device).await;
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            trace!("No supported platform detected for shutting down routes, skipping");
        }
    }

    pub(crate) async fn update_routes(
        &self,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
        tun_device: Arc<AsyncDevice>,
    ) -> EffectiveRoutingList {
        #[allow(unused_mut)]
        let mut applied_routes = EffectiveRoutingList::default();
        trace!(
            "Routes change: current={:?}; desired={:?}",
            current_routes, desired_routes
        );

        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            trace!("Updating routes using net_route");
            self.update_routes_net_route(
                current_routes,
                desired_routes,
                tun_device,
                &mut applied_routes,
            )
            .await;
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            trace!("No supported platform detected for updating routes, skipping");
        }

        applied_routes
    }

    pub(crate) async fn remove_routes(
        &self,
        routes: EffectiveRoutingList,
        tun_device: Arc<AsyncDevice>,
    ) {
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            trace!("Removing routes using net_route");
            self.remove_routes_net_route(routes, tun_device).await;
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            trace!("No supported platform detected for removing routes, skipping");
        }
    }
}

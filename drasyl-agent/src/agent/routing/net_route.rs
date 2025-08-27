use crate::agent::routing::AgentRouting;
use crate::network::{EffectiveRoute, EffectiveRoutingList, Network};
use ::net_route::Handle as NetRouteHandle;
use net_route::Route;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{trace, warn};
use tun_rs::AsyncDevice;
use url::Url;

impl AgentRouting {
    pub(crate) async fn shutdown_net_route(&self, networks: Arc<Mutex<HashMap<Url, Network>>>) {
        // remove physical routes
        trace!("remove physical routes");
        let mut all_physical_routes: Vec<(Option<u32>, EffectiveRoutingList)> = Vec::new();
        {
            trace!("Locking networks for shutdown");
            let networks = networks.lock().await;

            for network in networks.values() {
                if let Some(state) = network.state.as_ref() {
                    all_physical_routes.push((
                        network
                            .tun_state
                            .as_ref()
                            .and_then(|tun| tun.device.if_index().ok()),
                        state.routes.clone(),
                    ));
                }
            }
            trace!("Got networks for shutdown");
        }

        let routes_handle = self.net_route_handle.clone();
        let task = tokio::spawn(async move {
            for (if_index, physical_routes) in all_physical_routes {
                trace!("Remove physical routes: {}", physical_routes);
                Self::remove_routes_net_route_inner(
                    routes_handle.clone(),
                    physical_routes,
                    if_index,
                )
                .await;
            }
        });
        futures::executor::block_on(task).unwrap();
    }

    pub(crate) async fn update_routes_net_route(
        &self,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
        tun_device: Option<Arc<AsyncDevice>>,
        applied_routes: &mut EffectiveRoutingList,
    ) {
        Self::update_or_remove_routes_net_link(
            self.net_route_handle.clone(),
            current_routes,
            desired_routes,
            tun_device.as_ref().and_then(|tun| tun.if_index().ok()),
            applied_routes,
        )
        .await
    }

    async fn update_or_remove_routes_net_link(
        routes_handle: Arc<NetRouteHandle>,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
        if_index: Option<u32>,
        applied_routes: &mut EffectiveRoutingList,
    ) {
        // clean up old routes
        if let Some(current_routes) = current_routes.as_ref() {
            for (dest, route) in current_routes.iter() {
                match desired_routes.as_ref() {
                    Some(desired_routes) if desired_routes.contains(dest) => {
                        applied_routes.add(route.as_applied_route());
                    }
                    _ => {
                        trace!("delete route: {:?}", route);
                        let net_route = Self::net_route(route, if_index);
                        if let Err(e) = routes_handle.delete(&net_route).await {
                            warn!("Failed to delete route {:?}: {}", route, e);
                            applied_routes.add(route.as_removing_route());
                        }
                    }
                }
            }
        }

        if let Some(desired_routes) = desired_routes.as_ref() {
            if let Ok(existing_routes) = routes_handle.list().await {
                for (_, route) in desired_routes.iter() {
                    let net_route = Self::net_route(route, if_index);
                    let existing = existing_routes.iter().any(|route| {
                        net_route.destination == route.destination
                            && net_route.prefix == route.prefix
                            && net_route.gateway == route.gateway
                    });
                    if existing {
                        trace!("route does already exist: {:?}", route);
                        applied_routes.add(route.as_applied_route());
                    } else {
                        trace!("add route: {:?}", route);
                        if let Err(e) = routes_handle.add(&net_route).await {
                            warn!("Failed to add route {:?}: {}", route, e);
                            applied_routes.add(route.as_pending_route());
                        } else {
                            applied_routes.add(route.as_applied_route());
                        }
                    }
                }
            } else {
                warn!("Failed to list existing routes");
            }
        }
    }

    pub(crate) async fn remove_routes_net_route(
        &self,
        routes: EffectiveRoutingList,
        tun_device: Option<Arc<AsyncDevice>>,
    ) {
        Self::remove_routes_net_route_inner(
            self.net_route_handle.clone(),
            routes,
            tun_device.as_ref().and_then(|tun| tun.if_index().ok()),
        )
        .await;
    }

    async fn remove_routes_net_route_inner(
        routes_handle: Arc<NetRouteHandle>,
        routes: EffectiveRoutingList,
        if_index: Option<u32>,
    ) {
        let mut applied_routes = EffectiveRoutingList::default();
        Self::update_or_remove_routes_net_link(
            routes_handle,
            Some(routes),
            None,
            if_index,
            &mut applied_routes,
        )
        .await;
    }

    #[allow(unused_variables)]
    fn net_route(effective_route: &EffectiveRoute, if_index: Option<u32>) -> Route {
        let route = Route::new(
            IpAddr::V4(effective_route.dest.addr()),
            effective_route.dest.prefix_len(),
        )
        .with_gateway(IpAddr::V4(effective_route.gw));
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        let route = route.with_metric(4900);
        #[cfg(target_os = "windows")]
        let route = route.with_ifindex(if_index.expect("Interface index is required"));
        route
    }
}

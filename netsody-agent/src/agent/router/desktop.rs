use crate::agent::AgentInner;
use crate::agent::router::AgentRouterInterface;
use crate::network::{AppliedStatus, EffectiveRoute, EffectiveRoutingList, Network};
use cfg_if::cfg_if;
use net_route::{Handle, Route};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use tun_rs::AsyncDevice;
use url::Url;

pub struct AgentRouter {
    pub(crate) handle: Arc<Handle>,
}

impl AgentRouter {
    pub(crate) fn new() -> Self {
        Self {
            handle: Arc::new(Handle::new().expect("Failed to create route handle")),
        }
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

    async fn update_network_inner(
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

        trace!("Updating routes using net_route");
        let routes_handle = self.handle.clone();
        let if_index = tun_device.if_index().ok();
        if let Some(current_routes) = current_routes.as_ref() {
            for (dest, route) in current_routes.iter() {
                match desired_routes.as_ref() {
                    Some(desired_routes) if desired_routes.contains(dest) => {
                        applied_routes.add(route.clone());
                    }
                    _ => {
                        trace!("delete route: {:?}", route);
                        let net_route = Self::net_route(route, if_index);
                        if let Err(e) = routes_handle.delete(&net_route).await {
                            warn!("Failed to delete route {:?}: {}", route, e);
                            applied_routes.add(route.clone());
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
                        applied_routes.add(route.clone());
                    } else {
                        trace!("add route: {:?}", route);
                        if let Err(e) = routes_handle.add(&net_route).await {
                            warn!("Failed to add route {:?}: {}", route, e);
                        } else {
                            applied_routes.add(route.clone());
                        }
                    }
                }
            } else {
                warn!("Failed to list existing routes");
            }
        }

        applied_routes
    }
}

impl AgentRouterInterface for AgentRouter {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        if let Some(network) = networks.get_mut(config_url) {
            // routing

            // check if routes are still in desired state
            let routes_handle = self.handle.clone();
            if let Some(routes) = network.current_state.routes.applied.clone()
                && let Ok(existing_routes) = routes_handle.list().await
            {
                let result = inner.netif.tun_device.load().as_ref().cloned();
                let tun_device = result.map(|result| result.0.clone());
                if let Some(tun_device) = tun_device {
                    let if_index = tun_device.if_index().ok();
                    for (_, route) in routes.0.iter() {
                        let net_route = Self::net_route(route, if_index);

                        if !existing_routes.contains(&net_route) {
                            warn!("Route {:?} has been removed by externally.", route);
                            network.current_state.routes = AppliedStatus::error(format!(
                                "Route {:?} has been removed by externally.",
                                route
                            ));
                        }
                    }
                } else if network.desired_state.routes.applied.is_some() {
                    network.current_state.routes =
                        AppliedStatus::error("TUN device does not exist1.".to_string());
                    return;
                }
            }

            if network.current_state.routes != network.desired_state.routes {
                trace!("Routes are not in desired state");

                trace!("Try to apply routes '{}'", &network.current_state.routes);
                let tun_device = inner
                    .netif
                    .tun_device
                    .load()
                    .as_ref()
                    .map(|result| result.0.clone());
                if let Some(tun_device) = tun_device {
                    let applied_routes = AppliedStatus::applied(
                        self.update_network_inner(
                            network.current_state.routes.applied.clone(),
                            network.desired_state.routes.applied.clone(),
                            tun_device.clone(),
                        )
                        .await,
                    );

                    trace!("Applied routes {}", &network.current_state.routes);
                    network.current_state.routes = applied_routes;
                } else if network.desired_state.routes.applied.is_some() {
                    network.current_state.routes =
                        AppliedStatus::error("TUN device does not exist2.".to_string());
                } else if network.desired_state.routes.applied.is_none() {
                    network.current_state.routes = network.desired_state.routes.clone();
                }
            }

            // forwarding
            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    use sysctl::Sysctl;

                    match sysctl::Ctl::new("net.ipv4.ip_forward") {
                        Ok(ctl) => match ctl.value_string() {
                            Ok(ref s) if s == "1" && network.desired_state.forwarding.applied == Some(true) => {
                                trace!("IP forwarding is already enabled.");
                                network.current_state.forwarding = network.desired_state.forwarding.clone();
                            }
                            Ok(ref s) if s == "0" && network.desired_state.forwarding.applied == Some(true) => {
                                trace!("IP forwarding is not enabled. Enabling...");
                                match ctl.set_value_string("1") {
                                    Ok(_) => {
                                        trace!("Enabled IP forwarding");
                                        network.current_state.forwarding = network.desired_state.forwarding.clone();
                                    },
                                    Err(e) => {
                                        warn!("Failed to enable IP forwarding: {}", e);
                                        network.current_state.forwarding = AppliedStatus::with_error(false, format!("Failed to enable IP forwarding: {}", e));
                                    }
                                }
                            }
                            Ok(ref s) if s == "0" => {
                                trace!("IP forwarding is already disabled.");
                                network.current_state.forwarding = network.desired_state.forwarding.clone();
                            }
                            Ok(_) => {
                                // ip forwarding is enabled, but we dont need it. We keep it enabled, because we can't know if another application needs it. Therefore, we change the desired state to "enabled".
                                network.current_state.forwarding = AppliedStatus::applied(true);
                                network.desired_state.forwarding = AppliedStatus::applied(true);
                            }
                            Err(e) => {
                                warn!("Failed to get value for Ctl '{}': {}", "net.ipv4.ip_forward", e);
                                network.current_state.forwarding = AppliedStatus::with_error(false, format!("Failed to get value for Ctl '{}': {}", "net.ipv4.ip_forward", e));
                            }
                        },
                        Err(e) => {
                            warn!("Failed to construct Ctl for '{}': {}", "net.ipv4.ip_forward", e);
                            network.current_state.forwarding = AppliedStatus::with_error(false, format!("Failed to construct Ctl for '{}': {}", "net.ipv4.ip_forward", e));
                        }
                    }
                }
                else {
                    match network.desired_state.forwarding.applied {
                        Some(true) => {
                            warn!("We're configured as a gateway. Forwarding is not supported on this platform.");
                            network.current_state.forwarding = AppliedStatus::error("We're configured as a gateway. Forwarding is not supported on this platform.".to_string());
                        }
                        _ => {
                            network.current_state.forwarding = network.desired_state.forwarding.clone();
                        }
                    }
                }
            }
        }
    }
}

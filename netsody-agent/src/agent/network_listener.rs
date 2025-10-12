use crate::agent::AgentInner;
use crate::network::Network;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::trace;
use url::Url;

impl AgentInner {
    pub(crate) async fn notify_on_network_change(
        &self,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
        inner: Arc<AgentInner>,
    ) {
        trace!("Networks change listener set, check if we have a change");

        trace!("Collecting routes from {} networks", networks.len());
        let mut all_routes: Vec<Ipv4Net> = networks
            .iter()
            .filter_map(|(url, network)| {
                trace!(
                    "Processing network {}: routes={:?}",
                    url, network.current_state.routes.applied
                );
                network
                    .current_state
                    .routes
                    .applied
                    .as_ref()
                    .map(|routes| routes.iter().map(|(dest, _)| *dest))
            })
            .flatten()
            .collect();
        all_routes.sort();
        trace!("Collected {} routes: {:?}", all_routes.len(), all_routes);

        let mut all_ips: Vec<Ipv4Net> = networks
            .iter()
            .filter_map(|(url, network)| {
                trace!(
                    "Processing network {}: ip={:?}",
                    url, network.current_state.ip.applied
                );
                network.current_state.ip.applied
            })
            .collect();
        all_ips.sort();
        trace!("Collected {} IPs: {:?}", all_ips.len(), all_ips);

        let networks_change = NetworkChange {
            routes: Some(all_routes),
            ips: Some(all_ips),
            #[cfg(feature = "dns")]
            dns_server: self.dns.server_ip(),
        };

        let mut last_change_guard = inner.last_network_change.lock().await;
        if last_change_guard.as_ref() != Some(&networks_change) {
            trace!(
                "Network change detected, notifying listener: old={:?} new={:?}",
                *last_change_guard, networks_change
            );
            *last_change_guard = Some(networks_change.clone());
            let _ = &(inner.platform_dependent.network_listener)(networks_change.clone());
        } else {
            trace!("Network change is identical to last one, skipping notification");
        }
    }
}

/// Represents a network change event including all current IPs and routes of all networks
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkChange {
    pub ips: Option<Vec<Ipv4Net>>,
    pub routes: Option<Vec<Ipv4Net>>,
    #[cfg(feature = "dns")]
    pub dns_server: Option<std::net::Ipv4Addr>,
}

/// Callback function type for network change notifications
pub type NetworkListener = Box<dyn Fn(NetworkChange) + Send + Sync>;

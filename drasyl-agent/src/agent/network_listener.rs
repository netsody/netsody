use crate::agent::AgentInner;
use crate::network::Network;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::trace;
use url::Url;

impl AgentInner {
    pub(crate) fn notify_on_network_change(
        &self,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
        inner: Arc<AgentInner>,
    ) {
        if let Some(listener) = &inner.network_listener {
            trace!("Networks change listener set, check if we have a change");

            trace!("Collecting routes from {} networks", networks.len());
            let all_routes: Vec<Ipv4Net> = networks
                .iter()
                .filter_map(|(url, network)| {
                    trace!(
                        "Processing network {}: routes={:?}",
                        url,
                        network.state.as_ref().map(|s| &s.routes)
                    );
                    network
                        .state
                        .as_ref()
                        .map(|state| state.routes.iter().map(|(dest, _)| *dest))
                })
                .flatten()
                .collect();
            trace!("Collected {} routes: {:?}", all_routes.len(), all_routes);

            let all_ips: Vec<Ipv4Net> = networks
                .iter()
                .filter_map(|(url, network)| {
                    trace!(
                        "Processing network {}: ip={:?}, subnet={:?}",
                        url,
                        network.state.as_ref().map(|s| s.ip),
                        network.state.as_ref().map(|s| s.subnet)
                    );
                    network
                        .state
                        .as_ref()
                        .map(|state| Ipv4Net::new(state.ip, state.subnet.prefix_len()).unwrap())
                })
                .collect();
            trace!("Collected {} IPs: {:?}", all_ips.len(), all_ips);

            let networks_change = NetworkChange {
                routes: Some(all_routes),
                ips: Some(all_ips),
            };

            if inner.last_network_change.as_ref() != Some(&networks_change) {
                trace!(
                    "Network change detected, notifying listener: {:?}",
                    networks_change
                );
                // store the new networks_change state into last_networks_change
                if let Some(inner_mut) = Arc::get_mut(&mut inner.clone()) {
                    inner_mut.last_network_change = Some(networks_change.clone());
                }
                listener(networks_change.clone());
            } else {
                trace!("Network change is identical to last one, skipping notification");
            }
        } else {
            trace!("No networks change listener set, skipping notification");
        }
    }
}

/// Represents a network change event including all current IPs and routes of all networks
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkChange {
    pub ips: Option<Vec<Ipv4Net>>,
    pub routes: Option<Vec<Ipv4Net>>,
}

/// Callback function type for network change notifications
pub type NetworkListener = Box<dyn Fn(NetworkChange) + Send + Sync>;

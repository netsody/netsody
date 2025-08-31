use crate::agent::Error;
use crate::agent::inner::AgentInner;
use crate::agent::routing::AgentRoutingInterface;
use crate::network::{LocalNodeState, Network, TunState};
use cfg_if::cfg_if;
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::MutexGuard;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument, trace, warn};
use url::Url;

/// Timeout in milliseconds for fetching network config.
/// If a config cannot be received within this time, the fetch is considered failed.
pub(crate) const CONFIG_FETCH_TIMEOUT: u64 = 5_000;

impl AgentInner {
    pub(crate) async fn housekeeping_runner(
        inner: Arc<AgentInner>,
        housekeeping_shutdown: CancellationToken,
    ) -> Result<(), String> {
        let mut interval = tokio::time::interval(Duration::from_millis(10_000));

        loop {
            tokio::select! {
                biased;
                _ = housekeeping_shutdown.cancelled() => {
                    trace!("Housekeeping runner cancelled");
                    break
                },
                _ = interval.tick() => {
                    if let Err(e) = inner.housekeeping(&inner).await {
                        error!("Error in housekeeping: {e}");
                    }
                }
            }
        }

        trace!("Housekeeping runner finished");
        Ok(())
    }

    async fn housekeeping(&self, inner: &Arc<AgentInner>) -> Result<(), Error> {
        trace!("Locking networks to get network keys");
        let urls: Vec<Url> = {
            let networks = inner.networks.lock().await;
            networks.keys().cloned().collect()
        };
        trace!("Got network keys");

        trace!("Locking networks for housekeeping");
        let mut networks = self.networks.lock().await;
        for url in urls {
            self.housekeeping_network(inner.clone(), url, &mut networks)
                .await;
        }
        trace!("Finished housekeeping");

        // ensure network listener is fired on network changes
        self.notify_on_network_change(&networks, inner.clone())
            .await;

        Ok(())
    }

    #[instrument(fields(network = %config_url), skip_all)]
    async fn housekeeping_network(
        &self,
        inner: Arc<AgentInner>,
        config_url: Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        if let Some(network) = networks.get_mut(&config_url) {
            match timeout(
                Duration::from_millis(CONFIG_FETCH_TIMEOUT),
                self.fetch_network_config(network.config_url.as_str()),
            )
            .await
            {
                Ok(Ok(config)) => {
                    trace!("Network config fetched successfully");

                    // Update network name from config
                    if network.name != config.name {
                        trace!(
                            "Network name changed from '{:?}' to '{:?}'",
                            network.name, config.name
                        );
                    }
                    network.name = config.name.clone();

                    let desired = match config.ip(&inner.id.pk) {
                        Some(desired_ip) => {
                            let desired_effective_access_rule_list = config
                                .effective_access_rule_list(&inner.id.pk)
                                .expect("Failed to get effective access rule");
                            let desired_effective_routing_list = config
                                .effective_routing_list(&inner.id.pk)
                                .expect("Failed to get effective routing list");
                            let desired_hostnames = config.hostnames(&inner.id.pk);
                            Some(LocalNodeState {
                                subnet: config.subnet,
                                ip: desired_ip,
                                access_rules: desired_effective_access_rule_list,
                                routes: desired_effective_routing_list,
                                hostnames: desired_hostnames,
                            })
                        }
                        None => None,
                    };

                    let current = network.state.as_ref().cloned();

                    match (current, desired) {
                        (Some(_), _) if network.disabled => {
                            trace!("Network is disabled. We need to teardown everything.");
                            self.teardown_network(inner.clone(), config_url, networks)
                                .await;
                        }
                        (_, _) if network.disabled => {
                            trace!("Network is disabled. Nothing to do.");
                        }
                        (Some(current), Some(desired)) if current == desired => {
                            trace!("Network is already in desired state");
                        }
                        (Some(current), Some(desired))
                            if current.tun_state() == desired.tun_state() =>
                        {
                            trace!("TUN is in desired state");
                            self.update_routes_and_hostnames(
                                inner.clone(),
                                config_url,
                                networks,
                                Some(current),
                                desired,
                            )
                            .await;
                        }
                        (current, Some(desired)) => {
                            if current.is_some() {
                                trace!(
                                    "TUN is not in desired state. We need to teardown everything and then setup everything again."
                                );
                                self.teardown_network(inner.clone(), config_url.clone(), networks)
                                    .await;
                            } else {
                                trace!("TUN device does not exist. We need to setup everything.");
                            }
                            self.setup_network(
                                inner.clone(),
                                config_url,
                                networks,
                                current,
                                desired,
                            )
                            .await;
                        }
                        (_, None) => {
                            trace!("I'm not part of this network.");
                            self.teardown_network(inner.clone(), config_url, networks)
                                .await;
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Failed to fetch network config: {}", e);
                }
                Err(_) => {
                    warn!(
                        "Timeout of {} ms exceeded while attempting to fetch network config hostname",
                        CONFIG_FETCH_TIMEOUT
                    );
                }
            }
        }
    }

    async fn update_routes_and_hostnames(
        &self,
        inner: Arc<AgentInner>,
        config_url: Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
        current: Option<LocalNodeState>,
        desired: LocalNodeState,
    ) {
        if let Some(network) = networks.get_mut(&config_url) {
            // routes
            let applied_routes = match current.as_ref().map(|state| state.routes.clone()) {
                Some(current_routes) if current_routes == desired.routes => current_routes,
                current_routes => {
                    self.routing
                        .update_network(
                            current_routes,
                            Some(desired.routes.clone()),
                            inner.tun_device.clone(),
                        )
                        .await
                }
            };

            network.state = Some(LocalNodeState {
                subnet: desired.subnet,
                ip: desired.ip,
                access_rules: desired.access_rules.clone(),
                routes: applied_routes,
                hostnames: desired.hostnames.clone(),
            });

            // access rules
            match current.as_ref().map(|state| state.access_rules.clone()) {
                Some(current_access_rules) if current_access_rules == desired.access_rules => {}
                current_access_rules => {
                    trace!(
                        "Access rules change: current=\n{}; desired=\n{}",
                        current_access_rules.map_or("None".to_string(), |v| v.to_string()),
                        desired.access_rules
                    );
                    self.update_tx_tries(inner.clone(), networks).await;
                    self.update_rx_tries(inner.clone(), networks).await;
                }
            }

            #[cfg(feature = "dns")]
            {
                use crate::agent::dns::AgentDnsInterface;

                trace!("Update DNS");
                match current.as_ref().map(|state| state.hostnames.clone()) {
                    Some(current_hostnames) if current_hostnames == desired.hostnames => {}
                    _ => {
                        self.dns.update_network_hostnames(networks).await;
                    }
                }
            }
        }
    }

    pub(crate) async fn teardown_network(
        &self,
        inner: Arc<AgentInner>,
        config_url: Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        if let Some(network) = networks.get_mut(&config_url) {
            // routes
            let routes = { network.state.as_ref().map(|state| state.routes.clone()) };
            if let Some(routes) = routes {
                self.routing
                    .remove_network(routes, inner.tun_device.clone())
                    .await;
            }

            network.state = None;

            // tun device
            if let Some(tun_state) = network.tun_state.as_ref() {
                trace!("Remove network from TUN device by removing address");
                cfg_if! {
                    if #[cfg(target_os = "ios")] {
                        trace!(
                            "No supported platform detected for manages TUN device addresses. Assuming we're running on a mobile platform where the network listener handles TUN address updates. Therefore, we just assume everything is fine and hope for the best! 🤞"
                        );
                    } else {
                        self.tun_device
                            .remove_address(IpAddr::V4(tun_state.ip))
                            .expect("Failed to add address");
                    }
                }
                network.tun_state = None;
            }

            // access rules
            self.update_tx_tries(inner.clone(), networks).await;
            self.update_rx_tries(inner.clone(), networks).await;

            #[cfg(feature = "dns")]
            {
                use crate::agent::dns::AgentDnsInterface;

                trace!("Update DNS");
                self.dns.update_all_hostnames(networks).await;
            }
        }
    }

    async fn setup_network(
        &self,
        inner: Arc<AgentInner>,
        config_url: Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
        current: Option<LocalNodeState>,
        desired: LocalNodeState,
    ) {
        if let Some(network) = networks.get_mut(&config_url) {
            // tun device
            trace!("Setup network by adding address to TUN device");
            cfg_if! {
                if #[cfg(target_os = "ios")] {
                    trace!(
                        "No supported platform detected for manages TUN device addresses. Assuming we're running on a mobile platform where the network listener handles TUN address updates. Therefore, we just assume everything is fine and hope for the best! 🤞"
                    );
                } else {
                    inner
                        .tun_device
                        .add_address_v4(desired.ip, desired.subnet.prefix_len())
                        .expect("Failed to add address");
                }
            }
            network.tun_state = Some(TunState { ip: desired.ip });

            self.update_routes_and_hostnames(inner.clone(), config_url, networks, current, desired)
                .await;
        }
    }

    #[instrument(skip_all)]
    pub(crate) async fn update_tx_tries(
        &self,
        inner: Arc<AgentInner>,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        trace!("Rebuild TX tries");
        let mut trie_tx: crate::agent::inner::TrieTx = IpnetTrie::new();

        for (config_url, network) in networks.iter() {
            if let Some(access_rules) = network
                .state
                .as_ref()
                .map(|state| state.access_rules.clone())
            {
                let (network_trie_tx, _) = access_rules.routing_tries();

                trace!(
                    network=?config_url,
                    "Processing access rules for network"
                );

                // tx
                for (source, trie) in network_trie_tx.iter() {
                    let mut source_trie = IpnetTrie::new();
                    trace!(source_net=?source, "Building TX trie for source network");

                    for (dest, pk) in trie.iter() {
                        let send_handle = self
                            .node
                            .send_handle(pk)
                            .expect("Failed to create send handle");
                        source_trie.insert(dest, send_handle);

                        trace!(
                            source_net=?source,
                            dest_net=?dest,
                            peer=?pk,
                            "Added TX route: {} -> {} via peer {}",
                            source,
                            dest,
                            pk
                        );
                    }
                    trie_tx.insert(source, source_trie);
                }
            } else {
                trace!(
                    network=?network.config_url,
                    "No access rules available for network"
                );
            }
        }

        trace!("TX tries rebuilt successfully.",);

        inner.trie_tx.store(Arc::new(trie_tx));
    }

    #[instrument(skip_all)]
    pub(crate) async fn update_rx_tries(
        &self,
        inner: Arc<AgentInner>,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        trace!("Rebuild RX tries");
        let mut trie_rx: crate::agent::inner::TrieRx = IpnetTrie::new();

        for (config_url, network) in networks.iter() {
            if let Some(access_rules) = network
                .state
                .as_ref()
                .map(|state| state.access_rules.clone())
            {
                let (_, network_trie_rx) = access_rules.routing_tries();

                trace!(
                    network=?config_url,
                    "Processing access rules for network"
                );

                // rx
                for (src, trie) in network_trie_rx.iter() {
                    let mut source_trie = IpnetTrie::new();
                    trace!(source_net=?src, "Building RX trie for source network");

                    for (source, pk) in trie.iter() {
                        source_trie.insert(source, *pk);

                        trace!(
                            source_net=?src,
                            dest_net=?source,
                            peer=?pk,
                            "Added RX route: {} -> {} from peer {} to TUN device",
                            src,
                            source,
                            pk
                        );
                    }
                    trie_rx.insert(src, source_trie);
                }
            } else {
                trace!(
                    network=?config_url,
                    "No access rules available for network"
                );
            }
        }

        trace!("RX tries rebuilt successfully.",);

        inner.trie_rx.store(Arc::new(trie_rx));
    }
}

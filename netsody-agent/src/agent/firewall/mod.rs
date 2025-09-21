use crate::agent::AgentInner;
use crate::network::Network;
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::{instrument, trace};
use url::Url;

pub struct AgentFirewall {}

impl AgentFirewall {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        if let Some(network) = networks.get_mut(config_url)
            && network.current_state.access_rules != network.desired_state.access_rules
        {
            trace!(
                "Access rules change: current=\n{}; desired=\n{}",
                network.current_state.access_rules.to_string(),
                network.desired_state.access_rules
            );
            // set applied access rules to desired access rules. This is okay, as this process can not fail.
            network.current_state.access_rules = network.desired_state.access_rules.clone();
            self.update_tries(inner.clone(), networks).await;
        }
    }

    #[instrument(skip_all)]
    async fn update_tries(
        &self,
        inner: Arc<AgentInner>,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        trace!("Rebuild tries");
        let mut trie_tx: crate::agent::inner::TrieTx = IpnetTrie::new();
        let mut trie_rx: crate::agent::inner::TrieRx = IpnetTrie::new();

        for (config_url, network) in networks.iter() {
            if let Some(access_rules) = &network.current_state.access_rules.applied {
                let (network_trie_tx, network_trie_rx) = access_rules.routing_tries();

                trace!(
                    network=?config_url,
                    "Processing access rules for network"
                );

                // tx
                for (dest, trie) in network_trie_tx.iter() {
                    let mut dest_trie = IpnetTrie::new();
                    trace!(dest_net=?dest, "Building TX trie for dest network");

                    for (source, pk) in trie.iter() {
                        let send_handle = inner
                            .node
                            .send_handle(pk)
                            .expect("Failed to create send handle");
                        dest_trie.insert(source, send_handle);

                        trace!(
                            dest_net=?source,
                            source_net=?dest,
                            peer=?pk,
                            "Added TX route: {} -> {} via peer {}",
                            source,
                            dest,
                            pk
                        );
                    }
                    trie_tx.insert(dest, dest_trie);
                }

                // rx
                for (source, trie) in network_trie_rx.iter() {
                    let mut source_trie = IpnetTrie::new();
                    trace!(source_net=?source, "Building RX trie for source network");

                    for (dest, pk) in trie.iter() {
                        source_trie.insert(dest, *pk);

                        trace!(
                            source_net=?source,
                            dest_net=?dest,
                            peer=?pk,
                            "Added RX route: {} -> {} from peer {} to TUN device",
                            source,
                            dest,
                            pk
                        );
                    }
                    trie_rx.insert(source, source_trie);
                }
            } else {
                trace!(
                    network=?network.config_url,
                    "No access rules available for network"
                );
            }
        }

        trace!("Tries rebuilt successfully.",);

        inner.trie_tx.store(Arc::new(trie_tx));
        inner.trie_rx.store(Arc::new(trie_rx));
    }
}

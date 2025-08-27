mod config;
#[cfg(feature = "dns")]
mod dns;
mod error;
mod housekeeping;
mod inner;
mod routing;

use crate::network::Network;
pub use config::*;
pub use error::*;
pub use inner::*;
use p2p::identity::PubKey;
use p2p::node::{MessageSink, Node, SendHandle};
use p2p::util;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::{error, info, trace, warn};
use url::Url;

pub struct Agent {
    pub(crate) inner: Arc<AgentInner>,
}

impl Agent {
    pub async fn start(config: AgentConfig, config_path: String, token_path: String) -> Self {
        info!("Start agent.");

        // start node
        let cancellation_token = CancellationToken::new();
        let (node, recv_buf_rx) = AgentInner::bind_node(&config)
            .await
            .expect("Failed to bind node");

        // options
        let channel_cap = util::get_env("CHANNEL_CAP", 512);

        // tun <-> drasyl packet processing
        let (tun_tx, drasyl_rx) = flume::bounded::<(Vec<u8>, Arc<SendHandle>)>(channel_cap);
        let tun_tx = Arc::new(tun_tx);
        let drasyl_rx = Arc::new(drasyl_rx);

        let inner = Arc::new(AgentInner::new(
            config.id,
            config.networks,
            cancellation_token,
            node,
            recv_buf_rx,
            tun_tx.clone(),
            drasyl_rx.clone(),
            config_path,
            token_path,
            config.mtu.unwrap_or(AgentConfig::default_mtu()),
        ));

        let mut join_set = JoinSet::new();

        // node runner task
        join_set.spawn(AgentInner::node_runner(
            inner.clone(),
            inner.cancellation_token.clone(),
        ));

        // housekeeping task
        join_set.spawn(AgentInner::housekeeping_runner(
            inner.clone(),
            inner.cancellation_token.clone(),
        ));

        let monitoring_token = inner.cancellation_token.clone();
        tokio::spawn(async move {
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    error!("Task failed: {e}");
                    monitoring_token.cancel();
                    break;
                }
            }
        });

        info!("Agent started.");

        Self { inner }
    }

    pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancellation_token.cancelled()
    }

    pub async fn shutdown(&self) {
        info!("Shutdown agent.");
        self.inner.shutdown().await;
        info!("Agent shut down.");
    }

    pub fn node(&self) -> Arc<Node> {
        self.inner.node.clone()
    }

    /// adds a new network
    pub async fn add_network(&self, config_url: &str) -> Result<(), Error> {
        let url = Url::parse(config_url).map_err(|e| Error::ConfigParseError {
            reason: format!("Failed to parse URL: {e}"),
        })?;

        // check if network already exists and add it
        trace!("Locking networks to check if network already exists");
        let mut networks = self.inner.networks.lock().await;
        if networks.contains_key(&url) {
            return Err(Error::NetworkAlreadyExists {
                config_url: config_url.to_string(),
            });
        }

        // add network
        trace!("Adding network");
        let network = Network {
            config_url: config_url.to_string(),
            disabled: false,
            name: None,
            state: None,
            inner: std::sync::Arc::new(crate::network::NetworkInner::default()),
            tun_state: None,
        };
        networks.insert(url, network);

        // persist configuration
        self.save_config(&networks).await?;

        info!("Network '{}' added successfully", config_url);
        Ok(())
    }

    /// removes a network
    pub async fn remove_network(&self, config_url: &str) -> Result<(), Error> {
        let url = Url::parse(config_url).map_err(|e| Error::ConfigParseError {
            reason: format!("Failed to parse URL: {e}"),
        })?;

        // check if network exists and remove it
        trace!("Locking networks to check if network exists");
        let mut networks = self.inner.networks.lock().await;
        if !networks.contains_key(&url) {
            return Err(Error::NetworkNotFound {
                config_url: config_url.to_string(),
            });
        }

        // shutdown network
        trace!("Shutting down network");
        self.inner
            .teardown_network(self.inner.clone(), url.clone(), &mut networks)
            .await;
        let _ = networks.remove(&url);

        // persist configuration
        self.save_config(&networks).await?;

        info!("Network '{}' removed successfully", config_url);
        Ok(())
    }

    /// disables a network
    pub async fn disable_network(&self, config_url: &str) -> Result<(), Error> {
        let url = Url::parse(config_url).map_err(|e| Error::ConfigParseError {
            reason: format!("Failed to parse URL: {e}"),
        })?;

        // check if network exists and disable it
        trace!("Locking networks to check if network exists");
        let mut networks = self.inner.networks.lock().await;
        if !networks.contains_key(&url) {
            return Err(Error::NetworkNotFound {
                config_url: config_url.to_string(),
            });
        }

        // disable network
        trace!("Disabling network");
        if let Some(network) = networks.get_mut(&url) {
            network.disabled = true;
        }

        // persist configuration
        self.save_config(&networks).await?;

        info!("Network '{}' disabled successfully", config_url);
        Ok(())
    }

    /// enables a network
    pub async fn enable_network(&self, config_url: &str) -> Result<(), Error> {
        let url = Url::parse(config_url).map_err(|e| Error::ConfigParseError {
            reason: format!("Failed to parse URL: {e}"),
        })?;

        // check if network exists and enable it
        trace!("Locking networks to check if network exists");
        let mut networks = self.inner.networks.lock().await;
        if !networks.contains_key(&url) {
            return Err(Error::NetworkNotFound {
                config_url: config_url.to_string(),
            });
        }

        // enable network
        trace!("Enabling network");
        if let Some(network) = networks.get_mut(&url) {
            network.disabled = false;
        }

        // persist configuration
        self.save_config(&networks).await?;

        info!("Network '{}' enabled successfully", config_url);
        Ok(())
    }

    /// saves the current configuration to file
    async fn save_config(
        &self,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) -> Result<(), Error> {
        trace!("Saving configuration");

        // load current configuration
        let mut config = AgentConfig::load(&self.inner.config_path)?;

        // update networks from inner state
        config.networks = (*networks).clone();

        // save configuration
        config.save(&self.inner.config_path)
    }
}

pub struct ChannelSink(pub flume::Sender<(PubKey, Vec<u8>)>);

impl MessageSink for ChannelSink {
    fn accept(&self, sender: PubKey, message: Vec<u8>) {
        match self.0.try_send((sender, message)) {
            Ok(_) => {}
            Err(e) => warn!("Received APP dropped: {e}"),
        }
    }
}

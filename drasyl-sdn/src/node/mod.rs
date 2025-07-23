mod config;
mod error;
mod housekeeping;
mod inner;

use crate::network::Network;
pub use config::*;
use drasyl::identity::PubKey;
use drasyl::node::{MessageSink, Node, SendHandle};
use drasyl::util;
pub use error::*;
pub use inner::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::{error, info, warn};
use url::Url;

pub struct SdnNode {
    pub(crate) inner: Arc<SdnNodeInner>,
}

impl SdnNode {
    pub async fn start(config: SdnNodeConfig, config_path: String, token_path: String) -> Self {
        info!("Start SDN node.");

        // start node
        let cancellation_token = CancellationToken::new();
        let (node, recv_buf_rx) = SdnNodeInner::bind_node(&config)
            .await
            .expect("Failed to bind node");

        // options
        let channel_cap = util::get_env("CHANNEL_CAP", 512);

        // tun <-> drasyl packet processing
        let (tun_tx, drasyl_rx) = flume::bounded::<(Vec<u8>, Arc<SendHandle>)>(channel_cap);
        let tun_tx = Arc::new(tun_tx);
        let drasyl_rx = Arc::new(drasyl_rx);

        let inner = Arc::new(SdnNodeInner::new(
            config.id,
            config.networks,
            cancellation_token,
            node,
            recv_buf_rx,
            tun_tx.clone(),
            drasyl_rx.clone(),
            config_path,
            token_path,
        ));

        let mut join_set = JoinSet::new();

        // node runner task
        join_set.spawn(SdnNodeInner::node_runner(
            inner.clone(),
            inner.cancellation_token.child_token(),
        ));

        // housekeeping task
        join_set.spawn(SdnNodeInner::housekeeping_runner(
            inner.clone(),
            inner.cancellation_token.child_token(),
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

        info!("SDN node started.");

        Self { inner }
    }

    pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancellation_token.cancelled()
    }

    pub async fn shutdown(&self) {
        info!("Shutdown SDN node.");
        self.inner.shutdown().await;
        info!("SDN node shut down.");
    }

    pub fn drasyl_node(&self) -> Arc<Node> {
        self.inner.node.clone()
    }

    /// adds a new network
    pub async fn add_network(&self, config_url: &str) -> Result<(), Error> {
        let url = Url::parse(config_url).map_err(|e| Error::ConfigParseError {
            reason: format!("Failed to parse URL: {e}"),
        })?;

        // check if network already exists and add it
        let mut networks = self.inner.networks.lock().await;
        if networks.contains_key(&url) {
            return Err(Error::NetworkAlreadyExists {
                config_url: config_url.to_string(),
            });
        }

        // add network
        let network = Network {
            config_url: config_url.to_string(),
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
        let mut networks = self.inner.networks.lock().await;
        if !networks.contains_key(&url) {
            return Err(Error::NetworkNotFound {
                config_url: config_url.to_string(),
            });
        }

        // shutdown network
        self.inner
            .teardown_network(self.inner.clone(), url.clone(), &mut networks)
            .await;
        let _ = networks.remove(&url);

        // persist configuration
        self.save_config(&networks).await?;

        info!("Network '{}' removed successfully", config_url);
        Ok(())
    }

    /// saves the current configuration to file
    async fn save_config(
        &self,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) -> Result<(), Error> {
        // load current configuration
        let mut config = SdnNodeConfig::load(&self.inner.config_path)?;

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

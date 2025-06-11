mod config;
mod error;
mod housekeeping;
mod inner;

pub use config::*;
use drasyl::identity::PubKey;
use drasyl::node::{MessageSink, Node, SendHandle};
use drasyl::util;
pub use error::*;
pub use inner::*;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::{error, info, warn};

pub struct SdnNode {
    pub(crate) inner: Arc<SdnNodeInner>,
}

impl SdnNode {
    pub async fn start(config: SdnNodeConfig) -> Self {
        info!("Start SDN node.");

        // start node
        let cancellation_token = CancellationToken::new();
        let (node, recv_buf_rx) = SdnNodeInner::bind_node(&config.id)
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

        Self { inner }
    }

    pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancellation_token.cancelled()
    }

    pub async fn shutdown(&self) {
        info!("Shutdown SDN node.");
        self.inner.shutdown().await
    }

    pub fn drasyl_node(&self) -> Arc<Node> {
        self.inner.node.clone()
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

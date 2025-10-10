use crate::agent::AgentInner;
use crate::agent::PlatformDependent;
use crate::agent::netif::AgentNetifInterface;
use crate::network::Network;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;
use tracing::{error, trace};
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

pub struct AgentNetif {
    pub(crate) tun_device: Arc<TunDevice>,
    pub(crate) cancellation_token: Mutex<Option<CancellationToken>>,
}

impl AgentNetif {
    pub(crate) fn new(platform_dependent: Arc<PlatformDependent>) -> Self {
        Self {
            tun_device: platform_dependent.tun_device.clone(),
            cancellation_token: Default::default(),
        }
    }
}

impl AgentNetifInterface for AgentNetif {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // ensure tun device is there
        let mut cancellation_token = self.cancellation_token.lock().await;
        if cancellation_token.is_none() {
            trace!("We need to create TUN device runner");
            let token = inner.cancellation_token.child_token();
            *cancellation_token = Some(token.clone());

            trace!("Start TUN device runner");
            let inner_clone = inner.clone();
            let tun_clone = self.tun_device.clone();
            tokio::spawn(async move {
                let result =
                    AgentNetif::tun_runner(inner_clone.clone(), tun_clone.clone(), token).await;

                if let Err(e) = result {
                    error!("TUN runner failed: {}", e);
                    inner_clone.cancellation_token.cancel();
                } else {
                    trace!("TUN runner finished");
                }
            });
        }

        trace!(
            "We're running on a mobile platform where the network listener handles TUN address updates. Therefore, we just assume everything is fine and hope for the best! 🤞"
        );
        if let Some(network) = networks.get_mut(config_url) {
            network.current_state.ip = network.desired_state.ip.clone();
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun_device.send(buf).await
    }
}

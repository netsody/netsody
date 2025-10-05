use crate::agent::AgentInner;
use crate::agent::PlatformDependent;
use crate::agent::netif::AgentNetifInterface;
use crate::network::Network;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tokio_util::sync::CancellationToken;
use tracing::{error, trace};
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

pub struct AgentNetif {
    pub(crate) tun_device: ArcSwap<(Option<Arc<TunDevice>>, Option<CancellationToken>)>,
}

impl AgentNetif {
    pub(crate) fn new(platform_dependent: Arc<PlatformDependent>) -> Self {
        Self {
            tun_device: ArcSwap::new(Arc::new((platform_dependent.tun_device.clone(), None))),
        }
    }

    /// Update the TUN device, stopping any existing runner and starting a new one if needed
    pub(crate) fn update_tun_device(&self, inner: Arc<AgentInner>, new_device: Arc<TunDevice>) {
        trace!("Updating TUN device");

        // Get current state
        let device_pair = self.tun_device.load();
        let (_, current_token) = device_pair.as_ref();

        // TODO: drop previous tun device?

        // Cancel existing runner if running
        if let Some(cancellation_token) = current_token {
            trace!("Cancelling existing TUN runner for device replacement");
            cancellation_token.cancel();
        }

        // Always start a new runner
        let token = inner.cancellation_token.child_token();
        let new_device_clone = new_device.clone();
        let token_clone = token.clone();

        trace!("Starting new TUN device runner");
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            let result =
                AgentNetif::tun_runner(inner_clone.clone(), new_device_clone.clone(), token_clone)
                    .await;

            if let Err(e) = result {
                error!("TUN runner failed: {}", e);
                inner_clone.cancellation_token.cancel();
            } else {
                trace!("TUN runner finished");
            }
        });
        let new_token = Some(token);

        // Update the device
        self.tun_device
            .store(Arc::new((Some(new_device), new_token)));
        trace!("TUN device replaced successfully");
    }
}

impl AgentNetifInterface for AgentNetif {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // ensure TUN runner is running
        let device_pair = self.tun_device.load();
        let (tun_device, current_token) = device_pair.as_ref();

        if current_token.is_none() {
            // Start TUN device runner
            let token = inner.cancellation_token.child_token();
            let tun_device_clone = tun_device.clone();
            self.tun_device
                .store(Arc::new((tun_device_clone.clone(), Some(token.clone()))));

            trace!("Start TUN device runner");
            let inner_clone = inner.clone();
            tokio::spawn(async move {
                let result = AgentNetif::tun_runner(
                    inner_clone.clone(),
                    tun_device_clone.clone().unwrap(),
                    token,
                )
                .await;

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
        let device_pair = self.tun_device.load();
        let (tun_device, _) = device_pair.as_ref();
        let Some(tun_device) = tun_device else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN device is None",
            ));
        };
        tun_device.send(buf).await
    }
}

use crate::agent::netif::AgentNetifInterface;
use crate::agent::{AgentInner, PlatformDependent};
use crate::network::{AppliedStatus, Network};
use arc_swap::ArcSwapOption;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tokio_util::sync::CancellationToken;
use tracing::{error, trace, warn};
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

pub struct AgentNetif {
    pub(crate) tun_device: ArcSwapOption<(Arc<TunDevice>, CancellationToken)>,
}

impl AgentNetif {
    pub(crate) fn new(_platform_dependent: Arc<PlatformDependent>) -> Self {
        Self {
            tun_device: Default::default(),
        }
    }

    pub(crate) fn create_tun_device(
        mtu: u16,
    ) -> Result<Arc<tun_rs::AsyncDevice>, crate::agent::Error> {
        trace!("Create TUN device");
        let mut dev_builder = tun_rs::DeviceBuilder::new().mtu(mtu);
        if cfg!(any(target_os = "windows", target_os = "linux")) {
            dev_builder = dev_builder.name("netsody");
        } else if cfg!(target_os = "macos") {
            dev_builder = dev_builder.name("utun112");
        }
        #[cfg(target_os = "linux")]
        let tun_device = Arc::new(dev_builder.multi_queue(true).build_async()?);
        #[cfg(not(target_os = "linux"))]
        let tun_device = Arc::new(dev_builder.build_async()?);
        trace!("TUN device created: {:?}", tun_device.name());

        Ok(tun_device)
    }
}

impl AgentNetifInterface for AgentNetif {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // Check if any network needs TUN device
        let any_network_needs_iface = networks.values().any(|network| !network.disabled);

        if any_network_needs_iface {
            // ensure tun device is there
            let tun_device = match self.tun_device.load().as_ref() {
                Some(device_pair) => device_pair.0.clone(),
                None => {
                    trace!("We need to create a TUN device");
                    let new_tun_device = AgentNetif::create_tun_device(inner.mtu);
                    trace!("TUN device created");
                    match new_tun_device {
                        Ok(new_tun_device) => {
                            let token = inner.cancellation_token.child_token();
                            self.tun_device
                                .store(Some(Arc::new((new_tun_device.clone(), token.clone()))));

                            trace!("Start TUN device runner");
                            let inner_clone = inner.clone();
                            let tun_device_for_runner = new_tun_device.clone();
                            tokio::spawn(async move {
                                let result = AgentNetif::tun_runner(
                                    inner_clone.clone(),
                                    tun_device_for_runner,
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
                            new_tun_device
                        }
                        Err(e) => {
                            error!("Failed to create TUN device: {}", e);
                            for (_, network) in networks.iter_mut() {
                                network.current_state.ip = AppliedStatus::error(format!(
                                    "Failed to create TUN device: {}",
                                    e
                                ));
                            }
                            return;
                        }
                    }
                }
            };

            if let Some(network) = networks.get_mut(config_url) {
                // check if TUN device has wanted address
                if let Some(current_ip) = network.current_state.ip.applied
                    && let Ok(addresses) = tun_device.addresses()
                    && !addresses
                        .iter()
                        .any(|address| address == &IpAddr::V4(current_ip.addr()))
                {
                    warn!(
                        "TUN device address {} has been removed externally.",
                        current_ip
                    );
                    network.current_state.ip = AppliedStatus::error(format!(
                        "TUN device address {} has been removed externally.",
                        current_ip
                    ));
                }

                if network.current_state.ip != network.desired_state.ip {
                    trace!(
                        "TUN device address mismatch: current={} desired={}",
                        &network.current_state.ip, network.desired_state.ip
                    );

                    if let Some(current_ip) = network.current_state.ip.applied {
                        trace!("Remove TUN device address {}", &network.current_state.ip);
                        if let Err(e) = tun_device.remove_address(IpAddr::V4(current_ip.addr())) {
                            warn!("Failed to remove address: {}", e);
                            network.current_state.ip = AppliedStatus::with_error(
                                current_ip,
                                format!("Failed to remove address: {}", e),
                            );
                            return;
                        } else {
                            network.current_state.ip = AppliedStatus::unapplied();
                        }
                    }

                    if let Some(desired_ip) = network.desired_state.ip.applied {
                        trace!("Add TUN device address {}", desired_ip);
                        if let Err(e) =
                            tun_device.add_address_v4(desired_ip.addr(), desired_ip.prefix_len())
                        {
                            warn!("Failed to add address: {}", e);
                            network.current_state.ip =
                                AppliedStatus::error(format!("Failed to add address: {}", e));
                        } else {
                            network.current_state.ip = network.desired_state.ip.clone();
                        }
                    }
                } else {
                    trace!(
                        "TUN device is in desired state {}",
                        network.current_state.ip
                    );
                }
            }
        } else {
            // ensure tun device is not there
            if let Some(device_pair) = self.tun_device.load().as_ref().cloned() {
                trace!("We need to remove the TUN device");
                let (_, cancellation_token) = device_pair.as_ref();
                trace!("Cancel TUN device runner");
                cancellation_token.cancel();
                self.tun_device.store(None);
            }

            for (_, network) in networks.iter_mut() {
                network.current_state.ip = AppliedStatus::unapplied();
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(device_pair) = self.tun_device.load().as_ref().cloned() {
            let (tun_device, _) = device_pair.as_ref();
            tun_device.send(buf).await
        } else {
            Err(io::Error::other("TUN device not found"))
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod embedded;
#[cfg(target_os = "linux")]
mod hosts_file;

use crate::network::{LocalNodeState, Network};
use cfg_if::cfg_if;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use tokio::sync::MutexGuard;
use tracing::trace;
use tun_rs::AsyncDevice;
use url::Url;

pub(crate) struct AgentDns {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    embedded_catalog: arc_swap::ArcSwap<hickory_server::authority::Catalog>,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    server_ip: AtomicU32,
}

impl AgentDns {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            embedded_catalog: arc_swap::ArcSwap::from_pointee(
                hickory_server::authority::Catalog::new(),
            ),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            server_ip: AtomicU32::default(),
        }
    }

    pub(crate) fn is_server_ip(&self, ip: Ipv4Addr) -> bool {
        self.server_ip.load(SeqCst) == ip.to_bits()
    }

    pub(crate) async fn shutdown(&self) {
        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                trace!("Shutting down DNS using embedded DNS");
                self.shutdown_embedded().await;
            } else if #[cfg(target_os = "linux")] {
                trace!("Shutting down DNS using hosts file");
                self.shutdown_hosts_file();
            } else {
                trace!("No supported platform detected for shutting down DNS, skipping");
            }
        }
    }

    pub(crate) async fn update_network_hostnames(
        &self,
        current: Option<LocalNodeState>,
        desired: LocalNodeState,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        match current.as_ref().map(|state| state.hostnames.clone()) {
            Some(current_hostnames) if current_hostnames == desired.hostnames => {}
            _ => {
                cfg_if! {
                    if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                        trace!("Update network hostnames using embedded DNS");
                        self.update_network_hostnames_embedded(networks).await;
                    } else if #[cfg(target_os = "linux")] {
                        trace!("Update network hostnames using hosts file");
                        self.update_network_hostnames_hosts_file(networks).await;
                    } else {
                        trace!(
                            "No supported platform detected for updating network hostnames, skipping"
                        );
                    }
                }
            }
        }
    }

    pub(crate) async fn update_all_hostnames(
        &self,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                trace!("Update all hostnames using embedded DNS");
                self.update_all_hostnames_embedded(networks).await;
            } else if #[cfg(target_os = "linux")] {
                trace!("Update all hostnames using hosts file");
                self.update_all_hostnames_host_file(networks).await;

                self.embedded_catalog
                    .store(Arc::new(build_catalog(networks)));
            } else {
                trace!("No supported platform detected for updating all hostnames, skipping");
            }
        }
    }

    pub(crate) async fn on_packet(
        &self,
        message_bytes: &[u8],
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        dev: Arc<AsyncDevice>,
    ) -> bool {
        trace!(
            src=?src,
            src_port=?src_port,
            dst=?dst,
            dst_port=?dst_port,
            len=?message_bytes.len(),
            "Received DNS packet from {}:{} ({} bytes)",
            src,
            src_port,
            message_bytes.len()
        );

        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                trace!("Processing DNS packet using embedded DNS");
                self.on_packet_embedded(message_bytes, src, src_port, dst, dst_port, dev)
                    .await
            } else {
                trace!("No supported platform detected for processing DNS packet, skipping");
                false
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod embedded;
#[cfg(target_os = "linux")]
mod hosts_file;

use crate::network::{LocalNodeState, Network};
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
    #[cfg(target_os = "macos")]
    embedded_catalog: arc_swap::ArcSwap<hickory_server::authority::Catalog>,
    #[cfg(target_os = "macos")]
    server_ip: AtomicU32,
}

impl AgentDns {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            embedded_catalog: arc_swap::ArcSwap::from_pointee(
                hickory_server::authority::Catalog::new(),
            ),
            #[cfg(target_os = "macos")]
            server_ip: AtomicU32::default(),
        }
    }

    pub(crate) fn is_server_ip(&self, ip: Ipv4Addr) -> bool {
        self.server_ip.load(SeqCst) == ip.to_bits()
    }

    pub(crate) async fn shutdown(&self) {
        #[cfg(target_os = "linux")]
        {
            trace!("Shutting down DNS using hosts file");
            self.shutdown_hosts_file();
        }
        #[cfg(target_os = "macos")]
        {
            trace!("Shutting down DNS using embedded DNS");
            self.shutdown_embedded().await;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            trace!("No supported platform detected for shutting down DNS, skipping");
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
                #[cfg(target_os = "linux")]
                {
                    trace!("Update network hostnames using hosts file");
                    self.update_network_hostnames_hosts_file(networks).await;
                }
                #[cfg(target_os = "macos")]
                {
                    trace!("Update network hostnames using hosts file");
                    self.update_network_hostnames_embedded(networks).await;
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    trace!(
                        "No supported platform detected for updating network hostnames, skipping"
                    );
                }
            }
        }
    }

    pub(crate) async fn update_all_hostnames(
        &self,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        #[cfg(target_os = "linux")]
        {
            trace!("Update all hostnames using hosts file");
            self.update_all_hostnames_host_file(networks).await;

            self.embedded_catalog
                .store(Arc::new(build_catalog(networks)));
        }
        #[cfg(target_os = "macos")]
        {
            trace!("Update all hostnames using embedded DNS");
            self.update_all_hostnames_embedded(networks).await;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            trace!("No supported platform detected for updating all hostnames, skipping");
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

        #[cfg(target_os = "macos")]
        {
            trace!("Processing DNS packet using embedded DNS");
            self.on_packet_embedded(message_bytes, src, src_port, dst, dst_port, dev)
                .await
        }
        #[cfg(not(target_os = "macos"))]
        {
            trace!("No supported platform detected for processing DNS packet, skipping");
            false
        }
    }
}

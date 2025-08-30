#[cfg(any(target_os = "macos", target_os = "linux"))]
mod hosts_file;

use crate::network::{LocalNodeState, Network};
use cfg_if::cfg_if;
use std::collections::HashMap;
use tokio::sync::MutexGuard;
use tracing::trace;
use url::Url;

pub(crate) struct AgentDns {}

impl AgentDns {}

impl AgentDns {}

impl AgentDns {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn shutdown(&self) {
        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "linux"))] {
                trace!("Shutting down DNS using hosts file");
                self.shutdown_hosts_file();
            }
            else {
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
        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "linux"))] {
                trace!("Update network hostnames using hosts file");
                self.update_network_hostnames_hosts_file(current, desired, networks)
                    .await;
            }
            else {
                trace!("No supported platform detected for updating network hostnames, skipping");
            }
        }
    }

    pub(crate) async fn update_all_hostnames(
        &self,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            trace!("Update all hostnames using hosts file");
            self.update_all_hostnames_host_file(networks).await;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            trace!("No supported platform detected for updating all hostnames, skipping");
        }
    }
}

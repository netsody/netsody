use crate::agent::AgentInner;
use crate::agent::Error;
use crate::agent::PlatformDependent;
use crate::agent::dns::AgentDnsInterface;
use crate::network::{AppliedStatus, Network};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use url::Url;
use {std::fs, std::io::Write};

pub struct AgentDns {}

impl AgentDns {
    pub(crate) fn new(_platform_dependent: Arc<PlatformDependent>) -> Self {
        Self {}
    }

    async fn update_hosts_file(
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) -> Result<(), Error> {
        // read existing /etc/hosts
        let hosts_content = fs::read_to_string("/etc/hosts")?;
        trace!("read /etc/hosts");

        // filter out existing Netsody entries
        let lines: Vec<&str> = hosts_content
            .lines()
            .filter(|line| !line.contains("# managed by Netsody"))
            .collect();

        // create temporary file next to /etc/hosts
        let temp_path = "/etc/.hosts.netsody";
        let mut temp_file = fs::File::create(temp_path)?;
        trace!("created temporary file at {}", temp_path);

        // write existing entries
        for line in lines {
            writeln!(temp_file, "{line}")?;
        }

        for (_, network) in networks.iter() {
            if let Some(hostnames) = network.desired_state.hostnames.applied.clone() {
                for (ip, hostname) in hostnames.0.iter() {
                    writeln!(
                        temp_file,
                        "{ip:<15} {hostname} {hostname}.netsody.me   # managed by Netsody"
                    )?;
                }
            }
        }
        trace!("added new Netsody entries");

        // write file directly
        fs::rename(temp_path, "/etc/hosts")?;
        trace!("updated /etc/hosts");

        Ok(())
    }

    async fn update_all_networks(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        trace!("Hosts File DNS: Update all hostnames");
        if let Err(e) = Self::update_hosts_file(networks).await {
            warn!("failed to update /etc/hosts: {}", e);
            for (_, network) in networks.iter_mut() {
                network.current_state.hostnames =
                    AppliedStatus::error(format!("failed to update /etc/hosts: {}", e));
            }
        } else {
            for (_, network) in networks.iter_mut() {
                network.current_state.hostnames = network.desired_state.hostnames.clone();
            }
        }
    }
}

impl AgentDnsInterface for AgentDns {
    async fn apply_desired_state(
        &self,
        _inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // we do not support updating a single network. We have to update all networks.
        if let Some(network) = networks.get_mut(config_url) {
            trace!("Update network in DNS");
            if network.current_state.hostnames != network.desired_state.hostnames {
                trace!(
                    "DNS mismatch: current={:?} desired={:?}",
                    &network.current_state.hostnames, network.desired_state.hostnames
                );
                self.update_all_networks(networks).await;
            }
        }
    }
}

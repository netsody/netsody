use crate::agent::Error;
use crate::agent::dns::AgentDnsInterface;
use crate::network::Network;
use std::collections::HashMap;
use tokio::sync::MutexGuard;
use tracing::{error, trace};
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

        // filter out existing drasyl entries
        let lines: Vec<&str> = hosts_content
            .lines()
            .filter(|line| !line.contains("# managed by drasyl"))
            .collect();

        // create temporary file next to /etc/hosts
        let temp_path = "/etc/.hosts.drasyl";
        let mut temp_file = fs::File::create(temp_path)?;
        trace!("created temporary file at {}", temp_path);

        // write existing entries
        for line in lines {
            writeln!(temp_file, "{line}")?;
        }

        for (_, network) in networks.iter() {
            if let Some(hostnames) = network.state.as_ref().map(|state| state.hostnames.clone()) {
                for (ip, hostname) in hostnames {
                    writeln!(
                        temp_file,
                        "{ip:<15} {hostname} {hostname}.drasyl.network   # managed by drasyl"
                    )?;
                }
            }
        }
        trace!("added new drasyl entries");

        // write file directly
        fs::rename(temp_path, "/etc/hosts")?;
        trace!("updated /etc/hosts");

        Ok(())
    }

    fn cleanup_hosts_file() -> Result<(), Error> {
        // read existing /etc/hosts
        let hosts_content = fs::read_to_string("/etc/hosts")?;
        trace!("read /etc/hosts");

        // filter out drasyl entries
        let lines: Vec<&str> = hosts_content
            .lines()
            .filter(|line| !line.contains("# managed by drasyl"))
            .collect();

        // create temporary file next to /etc/hosts
        let temp_path = "/etc/.hosts.drasyl";
        let mut temp_file = fs::File::create(temp_path)?;
        trace!("created temporary file at {}", temp_path);

        // write remaining entries
        for line in lines {
            writeln!(temp_file, "{line}")?;
        }

        // write file directly
        fs::rename(temp_path, "/etc/hosts")?;
        trace!("cleaned up /etc/hosts");

        Ok(())
    }
}

impl AgentDnsInterface for AgentDns {
    async fn shutdown(&self) {
        trace!("Hosts File DNS: Shutting down DNS");
        if let Err(e) = Self::cleanup_hosts_file() {
            error!("Failed to cleanup /etc/hosts: {}", e);
        }
    }

    async fn update_network_hostnames(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        // we do not support updating hostnames for a single network
        self.update_all_hostnames(networks).await;
    }

    async fn update_all_hostnames(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        trace!("Hosts File DNS: Update all hostnames");
        if let Err(e) = Self::update_hosts_file(networks).await {
            error!("failed to update /etc/hosts: {}", e);
        }
    }
}

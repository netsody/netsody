mod systemd_resolved;

use crate::agent::dns::AgentDnsInterface;
use crate::agent::dns::linux::systemd_resolved::{
    systemd_resolved_available, systemd_resolved_dns_ip, systemd_resolved_dns_stub_listener,
    systemd_resolved_flush_caches, systemd_resolved_revert, systemd_resolved_set_dns_ip,
};
use crate::agent::{AgentInner, PlatformDependent};
use crate::network::{AppliedStatus, Network};
use arc_swap::ArcSwap;
use hickory_resolver::config::NameServerConfigGroup;
use hickory_server::authority::Catalog;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use url::Url;

/// DNS management for Linux systems.
///
/// Manages DNS configuration via systemd-resolved or embedded DNS server,
/// depending on the system configuration.
pub struct AgentDns {
    /// Detected DNS resolver type (systemd-resolved, etc.)
    dns_resolver: Option<DnsResolver>,
    /// Embedded DNS catalog for resolving netsody.me hostnames
    pub(crate) embedded_catalog: ArcSwap<Catalog>,
    /// Currently configured DNS server IP address (as u32 for atomic operations)
    pub(crate) server_ip: AtomicU32,
    /// Upstream DNS servers for forwarding
    upstream_servers: NameServerConfigGroup,
}

impl AgentDns {
    /// Create a new DNS manager instance for Linux.
    ///
    /// This method detects the system's DNS resolver (systemd-resolved)
    /// and initializes the embedded DNS server.
    ///
    /// # Arguments
    /// * `platform_dependent` - Platform-specific dependencies
    ///
    /// # Returns
    /// Initialized AgentDns instance
    #[allow(unused_variables)]
    pub(crate) async fn new(platform_dependent: Arc<PlatformDependent>) -> Self {
        // Check what DNS resolver is used
        trace!("Creating AgentDns for Linux. Check what DNS resolver is used.");

        // systemd-resolved?
        let dns_resolver = match systemd_resolved_available().await {
            Ok(true) => {
                trace!("systemd-resolved is available.");

                match systemd_resolved_dns_stub_listener().await {
                    Ok(true) => {
                        trace!("systemd-resolved stub listener is enabled.");
                        Some(DnsResolver::SystemdResolved)
                    }
                    Ok(false) => {
                        trace!(
                            "systemd-resolved stub listener is disabled. This is not supported by netsody-agent."
                        );
                        None
                    }
                    Err(e) => {
                        warn!("Unable to determine systemd-resolved stub listener: {}.", e);
                        None
                    }
                }
            }
            _ => {
                warn!("Unable to determine used DNS resolver.");
                None
            }
        };

        Self {
            dns_resolver,
            embedded_catalog: ArcSwap::from_pointee(Catalog::new()),
            server_ip: AtomicU32::default(),
            upstream_servers: NameServerConfigGroup::new(),
        }
    }
}

impl AgentDnsInterface for AgentDns {
    /// Apply desired DNS state for all configured networks.
    ///
    /// This method:
    /// 1. Queries current DNS configuration via systemd-resolved
    /// 2. Calculates desired DNS IP from enabled networks
    /// 3. Updates DNS server configuration if needed
    /// 4. Updates hostname mappings in embedded DNS catalog
    /// 5. Flushes DNS caches when changes are made
    async fn apply_desired_state(
        &self,
        _inner: Arc<AgentInner>,
        _config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // Get current DNS configuration
        let mut current_dns_ip = match self.dns_resolver {
            Some(DnsResolver::SystemdResolved) => match systemd_resolved_dns_ip().await {
                Ok(dns_ip) => {
                    trace!("Current DNS IP: {:?}", dns_ip);
                    dns_ip
                }
                Err(e) => {
                    for (_, network) in networks.iter_mut() {
                        if network.current_state.hostnames.applied.is_some() {
                            warn!("Unable to determine current DNS IP: {}", e);
                            network.current_state.hostnames = AppliedStatus::error(format!(
                                "Unable to determine current DNS IP: {}",
                                e
                            ));
                        }
                    }
                    return;
                }
            },
            _ => {
                // log nothing, we already did this in the constructor
                for (_, network) in networks.iter_mut() {
                    if network.desired_state.hostnames.applied.is_some() {
                        network.current_state.hostnames =
                            AppliedStatus::error(format!("Unable to determine used DNS resolver"));
                    }
                }
                return;
            }
        };

        // Calculate desired DNS IP from enabled networks
        let network_dns_ips: Vec<Ipv4Addr> = networks
            .values()
            .filter(|network| !network.disabled)
            .filter_map(|network| network.current_state.ip.applied)
            .map(|network_ip| {
                let broadcast = network_ip.broadcast();
                // DNS server IP is the broadcast address minus 1
                Ipv4Addr::from(u32::from(broadcast).saturating_sub(1))
            })
            .collect();
        let desired_dns_ip = network_dns_ips.first();

        // Remove current DNS server if it doesn't match desired state
        if let Some(current_ip) = current_dns_ip
            && Some(&current_ip) != desired_dns_ip
        {
            trace!(
                "Removing DNS server because current IP is not in desired state: current_ip={:?}, desired_ip={:?}",
                current_ip, desired_dns_ip
            );

            match self.dns_resolver {
                Some(DnsResolver::SystemdResolved) => {
                    if let Err(e) = systemd_resolved_revert().await {
                        warn!("Unable to revert DNS server IP: {}.", e);
                        for (_, network) in networks.iter_mut() {
                            if network.current_state.hostnames.applied.is_some() {
                                network.current_state.hostnames = AppliedStatus::error(format!(
                                    "Unable to revert DNS server IP: {}",
                                    e
                                ));
                            }
                        }
                        return;
                    }
                }
                _ => unreachable!(),
            }

            trace!("Successfully removed DNS server.");
            current_dns_ip = None;
            self.server_ip.store(0, SeqCst);
        }

        // Add DNS server if desired state requires it
        if let Some(desired_ip) = desired_dns_ip
            && current_dns_ip != Some(*desired_ip)
        {
            trace!("We need to set DNS server to {:?}.", desired_ip);
            match self.dns_resolver {
                Some(DnsResolver::SystemdResolved) => {
                    if let Err(e) = systemd_resolved_set_dns_ip(desired_ip).await {
                        warn!("Unable to set DNS server IP: {}.", e);
                        for (_, network) in networks.iter_mut() {
                            if network.current_state.hostnames.applied.is_some() {
                                network.current_state.hostnames = AppliedStatus::error(format!(
                                    "Unable to set DNS server IP: {}",
                                    e
                                ));
                            }
                        }
                        return;
                    }
                }
                _ => unreachable!(),
            }

            trace!("Successfully set DNS server to {:?}.", desired_ip);
            self.server_ip.store(desired_ip.to_bits(), SeqCst);
        }

        // Check if hostname mappings need to be updated
        let mut update_hostnames = false;
        for (_, network) in networks.iter_mut() {
            if network.current_state.hostnames != network.desired_state.hostnames {
                trace!(
                    "DNS hostnames mismatch: current={:?} desired={:?}",
                    &network.current_state.hostnames, network.desired_state.hostnames
                );
                update_hostnames = true;
                break;
            }
        }
        if !update_hostnames {
            trace!("All DNS hostnames up to date");
        } else {
            trace!("Update hostnames in DNS");
            // Update DNS catalog with new hostname mappings
            self.embedded_catalog.store(Arc::new(
                self.build_catalog(networks, &self.upstream_servers),
            ));

            for (_, network) in networks.iter_mut() {
                network.current_state.hostnames = network.desired_state.hostnames.clone();
            }

            // Flush DNS caches after updating entries
            match self.dns_resolver {
                Some(DnsResolver::SystemdResolved) => {
                    if let Err(e) = systemd_resolved_flush_caches().await {
                        warn!("Unable to flush DNS caches: {}.", e);
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

/// Supported DNS resolver types on Linux
enum DnsResolver {
    /// systemd-resolved (default on most modern Linux distributions)
    SystemdResolved,
}
